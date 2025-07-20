import { PrivyClient } from "@privy-io/server-auth";
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { randomUUID } from 'crypto';
import { v4 as uuid } from 'uuid';
import { registerTools } from "./mcp_tools";

const app = new Hono<{ Bindings: Env/*, MCP_OBJECT: MCPrivy */ }>();

  
// Define our MCP agent with version and register tools
export class MCPrivy extends McpAgent {
	server = new McpServer({ name: "Privium", version: "0.1.1" });
	initialState = {sesh: null};
	transport: StreamableHTTPServerTransport | undefined;

	async init() {

		// Register tools from external file (mcp_tools.ts)
		registerTools(this.server);
		
		// Attach custom transport for specific sessions
		const transport = new StreamableHTTPServerTransport({
			sessionIdGenerator: () => randomUUID(),
			onsessioninitialized: (sessionId) => {
				// Integrate with McpAgent state for persistence
				this.setState({sesh: sessionId});
				// Assign the transport to the agent (since agent is per-session)
				this.transport = transport;
				// Log the session ID for debugging
				console.log(`Session initialized with ID: ${sessionId}`);
			},			
		});

		transport.onclose = () => {
			console.log(`Session closed for ID: ${transport.sessionId}`);
			this.setState({sesh: null});
			this.transport = undefined;
		};

		// Connect the agent's McpServer to the transport
		await this.server.connect(transport);
	}
}

interface Env {
	PRIVY_APP_ID: string;
	PRIVY_APP_SECRET: string;
	AUTH_PRIVATE_KEY: string; // Use this PEM key for signing (SDK handles it)
	QUORUM_ID: string;
	MCP_OBJECT: MCPrivy;
	Privium_KV: KVNamespace;
	VITE_FRONTEND_URL: string;
	userId?: string; // Extended dynamically for per-request user context
}


// Helper to initialize Privy client with walletApi config for automatic signing
function initPrivyClient(env: Env): PrivyClient {
	return new PrivyClient(env.PRIVY_APP_ID, env.PRIVY_APP_SECRET, {
	  walletApi: {
		authorizationPrivateKey: env.AUTH_PRIVATE_KEY,
	  },
	});
}

// Allow CORS all domains, expose the Mcp-Session-Id header
app.use(cors({
	origin: '*', // Allow all origins
	exposeHeaders: ["Mcp-Session-Id"]
}));

app.get('/.well-known/oauth-protected-resource', (c) => {
  const frontendUrl = c.env.VITE_FRONTEND_URL; // Your frontend URL
  return c.json({
    resource: `${c.req.url.split('/.well-known')[0]}/mcp`, // Canonical MCP resource URI
    authorization_servers: [`${frontendUrl}`], // Issuer URI (your frontend acts as AS)
  });
});

app.post('/reg', async (c) => {
  const body = await c.req.json();
  // Validate required fields per RFC 7591 (e.g., redirect_uris, client_name)
  if (!body.redirect_uris || !Array.isArray(body.redirect_uris)) {
    return c.json({ error: 'invalid_client_metadata' }, 400);
  }
  const clientId = uuid();
  const clientSecret = uuid(); // For confidential clients
  const kv = c.env.Privium_KV;
  await kv.put(`client:${clientId}`, JSON.stringify({
    ...body,
    client_id: clientId,
    client_secret: clientSecret,
    client_id_issued_at: Math.floor(Date.now() / 1000),
  }));
  return c.json({
    client_id: clientId,
    client_secret: clientSecret,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    // Echo back other metadata
    ...body,
  });
});

app.post('/generate-code', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  if (!token) {
    return c.text('Unauthorized', 401);
  }
  const privyClient = initPrivyClient(c.env);
  let verifiedClaims;
  try {
    verifiedClaims = await privyClient.verifyAuthToken(token);
  } catch (error) {
    return c.text('Invalid token', 401);
  }
  const body = await c.req.json<{ client_id: string; redirect_uri: string; scope?: string; state?: string; code_challenge?: string; code_challenge_method?: string; resource?: string }>();
  // Optional: Validate client_id (e.g., fetch from KV if dynamic)
  const code = randomUUID();
  const kv = c.env.Privium_KV;
  await kv.put(
    `auth_code:${code}`,
    JSON.stringify({
      privy_token: token,
      user_id: verifiedClaims.userId,
      redirect_uri: body.redirect_uri,
      client_id: body.client_id,
      scope: body.scope,
      code_challenge: body.code_challenge,
      code_challenge_method: body.code_challenge_method,
      resource: body.resource,
      token_exp: verifiedClaims.expiration,
      exp: Date.now() / 1000 + 300, // Code expires in 5 minutes
    }),
    { expirationTtl: 300 }
  );
  return c.json({ code });
});

app.post('/token', async (c) => {
  const body = await c.req.parseBody() as Record<string, string>;
  const grant_type = body.grant_type;
  if (grant_type !== 'authorization_code') {
    return c.text('Unsupported grant type', 400);
  }
  const code = body.code;
  const redirect_uri = body.redirect_uri;
  const client_id = body.client_id;
  const code_verifier = body.code_verifier;
  if (!code || !redirect_uri || !client_id) {
    return c.text('Missing required parameters', 400);
  }
  const kv = c.env.Privium_KV;
  const storedStr = await kv.get(`auth_code:${code}`);
  if (!storedStr) {
    return c.text('Invalid code', 400);
  }
  const stored = JSON.parse(storedStr);
  if (stored.redirect_uri !== redirect_uri || stored.client_id !== client_id) {
    return c.text('Invalid request', 400);
  }
  if (stored.exp < Date.now() / 1000) {
    return c.text('Code expired', 400);
  }
  // PKCE verification
  if (stored.code_challenge && stored.code_challenge_method === 'S256') {
    if (!code_verifier) {
      return c.text('Missing code_verifier', 400);
    }
    const encoder = new TextEncoder();
    const data = encoder.encode(code_verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(digest));
    const hashStr = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    const base64Url = btoa(hashStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    if (base64Url !== stored.code_challenge) {
      return c.text('Invalid code_verifier', 400);
    }
  }
  await kv.delete(`auth_code:${code}`);
  const expires_in = stored.token_exp - Math.floor(Date.now() / 1000);
  return c.json({
    access_token: stored.privy_token,
    token_type: 'Bearer',
    expires_in,
    scope: stored.scope,
  });
});

app.post('/mcp', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const resourceMetadataUrl = `${c.req.url.split('/mcp')[0]}/.well-known/oauth-protected-resource`;
  if (!token) {
    const headers = new Headers();
    headers.set(
      'WWW-Authenticate',
      `Bearer error="unauthorized", error_description="Authorization required", resource_metadata="${resourceMetadataUrl}"`
    );
    return new Response('Unauthorized', { status: 401, headers });
  }
  const privyClient = initPrivyClient(c.env);
  try {
    const verifiedClaims = await privyClient.verifyAuthToken(token);
    // Optional: c.env.userId = verifiedClaims.userId; // If needed for per-user logic in MCP
  } catch (error) {
    const headers = new Headers();
    headers.set(
      'WWW-Authenticate',
      `Bearer resource_metadata="${resourceMetadataUrl}", error="invalid_token"`
    );
    return new Response('Invalid token', { status: 401, headers });
  }
  return MCPrivy.serve('/mcp').fetch(c.req.raw, c.env, c.executionCtx);
});

export default app;