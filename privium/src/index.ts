import { PrivyClient } from "@privy-io/server-auth";
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerTools } from "./mcp_tools";
import { Hono } from 'hono';
import { cors } from 'hono/cors';

// Define our MCP agent with version and register tools
export class MCPrivy extends McpAgent {
  server = new McpServer({ name: "Privium", version: "0.4.1" });
  initialState = { sesh: null };

  async init() {
    // Register tools from external file (mcp_tools.ts)
    registerTools(this.server);

    // Session management is handled by McpAgent.serve() internally
    // Persist session ID to state if needed for tracking
    // Note: StreamableHTTPServerTransport generates session IDs automatically
    console.log('Agent initialized; session will be managed by StreamableHTTPServerTransport');
    // Optionally access ctx for session info after serve() is called
    // this.setState({ sesh: this.ctx?.sessionId || null }); // Uncomment if session tracking is needed
  }
}

interface Env {
  PRIVY_APP_ID: string;
  PRIVY_APP_SECRET: string;
  AUTH_PRIVATE_KEY: string; // Use this PEM key for signing (SDK handles it)
  QUORUM_ID: string;
  MCP_OBJECT: DurableObjectNamespace<MCPrivy>;
  Privium_KV: KVNamespace;
  OAUTH_KV: KVNamespace;
  ASSETS: Fetcher;
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

// Create Hono app
const app = new Hono<{ Bindings: Env }>();

// Add CORS middleware
app.use('/*', cors({
  origin: '*', // Adjust for production to specific origins
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'mcp-session-id'],
  exposeHeaders: ['mcp-session-id'],
}));

// OAuth Discovery Endpoints
app.get('/.well-known/oauth-authorization-server', (c) => {
	const url = new URL(c.req.url);
	return c.json({
		issuer: url.origin,
		authorization_endpoint: `${url.origin}/authorize`,
		token_endpoint: `${url.origin}/token`,
		registration_endpoint: `${url.origin}/reg`,
		scopes_supported: ['mcp'],
		response_types_supported: ['code'],
		response_modes_supported: ['query'],
		grant_types_supported: ['authorization_code', 'refresh_token'],
		token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
		revocation_endpoint: `${url.origin}/revoke`,
		code_challenge_methods_supported: ['plain', 'S256'],
	});
});

app.get('/.well-known/oauth-protected-resource', (c) => {
	const url = new URL(c.req.url);
	return c.json({
		resource: `${url.origin}/mcp`,
		authorization_servers: [url.origin],
		scopes_supported: ['mcp'],
		bearer_methods_supported: ['header'],
		resource_documentation: `${url.origin}/mcp`,
	});
});

// Authorization Endpoint (serve frontend)
app.get('/authorize', async (c) => {
	try {
		const url = new URL(c.req.url);
		const indexRequest = new Request(url.origin + '/index.html');
		const asset = await c.env.ASSETS.fetch(indexRequest);
		
		if (asset.ok) {
			console.log('🔵 FRONTEND: Asset fetched successfully');
			let html = await asset.text();
			// Inject environment variables into the frontend
			html = html.replace(
				'</head>',
				`<script>
					window.PRIVY_APP_ID = "${c.env.PRIVY_APP_ID}";
				</script></head>`
			);
			console.log('🔵 FRONTEND: HTML injected with Privy App ID');
			return c.html(html);
		} else {
			console.error('🔴 FRONTEND ERROR: Asset fetch failed, status:', asset.status);
			return c.text('Frontend not found', 404);
		}
	} catch (error) {
		console.error('🔴 FRONTEND ERROR: Failed to serve frontend:', error);
		return c.text('Frontend error', 500);
	}
});

// Authorization Completion (Privy → OAuth Code)
app.post('/complete-authorize', async (c) => {
	try {
		const body = await c.req.json();
		console.log('🔵 OAUTH: Request body received:', { 
			hasAccessToken: !!body.accessToken,
			client_id: body.client_id,
			redirect_uri: body.redirect_uri,
			code_challenge: body.code_challenge ? 'present' : 'missing'
		});
		
		const token = body.accessToken;
		if (!token) {
			console.error('🔴 OAUTH ERROR: Missing access token');
			return c.text('Missing access token', 401);
		}

		console.log('🔵 OAUTH: Verifying Privy token...');
		const privyClient = initPrivyClient(c.env);
		
		let verifiedClaims;
		try {
			verifiedClaims = await privyClient.verifyAuthToken(token);
			console.log('🔵 OAUTH: Token verified for user:', verifiedClaims.userId);
			console.log(verifiedClaims);
		} catch (error) {
			console.error('🔴 OAUTH ERROR: Token verification failed:', error);
			return c.json({ 
				error: 'Invalid token', 
				details: error instanceof Error ? error.message : String(error) 
			}, 401);
		}

		// Generate authorization code
		const authCode = crypto.randomUUID();
		console.log('🔵 OAUTH: Generated auth code:', authCode);
		
		// Store the authorization details in KV for later token exchange
		const authData = {
			userId: verifiedClaims.userId,
			clientId: body.client_id,
			redirectUri: body.redirect_uri,
			scope: body.scope || 'mcp',
			codeChallenge: body.code_challenge,
			codeChallengeMethod: body.code_challenge_method,
			createdAt: Date.now(),
		};
		
		console.log('🔵 OAUTH: Storing auth data in KV...');
		await c.env.OAUTH_KV.put(`auth_code:${authCode}`, JSON.stringify(authData), { expirationTtl: 600 });
		console.log('🔵 OAUTH: Auth data stored successfully');

		// Build redirect URL back to Cursor
		console.log('🔵 OAUTH: Building redirect URL...');
		const redirectUrl = new URL(body.redirect_uri);
		redirectUrl.searchParams.set('code', authCode);
		if (body.state) {
			redirectUrl.searchParams.set('state', body.state);
		}
		
		const redirectTo = redirectUrl.toString();
		console.log('🔵 OAUTH: Redirect URL built:', redirectTo);

		return c.json({ redirectTo });
	} catch (error) {
		console.error('🔴 OAUTH ERROR: /complete-authorize failed:', error);
		return c.json({ 
			error: 'Internal server error', 
			details: error instanceof Error ? error.message : String(error) 
		}, 500);
	}
});

// Token Exchange (OAuth Code → Bearer Token)
app.post('/token', async (c) => {
	try {
		const authHeader = c.req.header('Authorization');
		let clientId: string | null = null;
		let clientSecret: string | null = null;

		if (authHeader && authHeader.startsWith('Basic ')) {
			const encoded = authHeader.substring(6);
			const decoded = atob(encoded);
			const [basicClientId, basicClientSecret] = decoded.split(':');
			clientId = basicClientId;
			clientSecret = basicClientSecret;
			console.log('🔵 TOKEN: Basic Auth client_id:', clientId);
		}

		const body = await c.req.text();
		const params = new URLSearchParams(body);
		
		const grantType = params.get('grant_type');
		const code = params.get('code');
		const codeVerifier = params.get('code_verifier');
		const redirectUri = params.get('redirect_uri');

		// If client_id was not in Basic Auth, try to get it from the body
		if (!clientId) {
			clientId = params.get('client_id');
		}
		// If client_secret was not in Basic Auth, try to get it from the body
		if (!clientSecret) {
			clientSecret = params.get('client_secret');
		}

		console.log('🔵 TOKEN: Exchange request:', { grantType, code, clientId, hasCodeVerifier: !!codeVerifier, hasClientSecret: !!clientSecret });

		if (grantType !== 'authorization_code') {
			console.error('🔴 TOKEN ERROR: Unsupported grant type:', grantType);
			return c.json({ error: 'unsupported_grant_type' }, 400);
		}

		if (!code || !clientId || !codeVerifier) {
			console.error('🔴 TOKEN ERROR: Missing required parameters (code, clientId, codeVerifier)');
			return c.json({ error: 'invalid_request' }, 400);
		}

		// Retrieve auth data from KV
		console.log('🔵 TOKEN: Retrieving auth data from KV...');
		const authDataStr = await c.env.OAUTH_KV.get(`auth_code:${code}`);
		if (!authDataStr) {
			console.error('🔴 TOKEN ERROR: Invalid or expired authorization code');
			return c.json({ error: 'invalid_grant' }, 400);
		}

		const authData = JSON.parse(authDataStr);
		console.log('🔵 TOKEN: Auth data retrieved for user:', authData.userId);

		// Validate PKCE
		if (authData.codeChallenge && authData.codeChallengeMethod === 'S256') {
			console.log('🔵 TOKEN: Validating PKCE...');
			const encoder = new TextEncoder();
			const data = encoder.encode(codeVerifier);
			const digest = await crypto.subtle.digest('SHA-256', data);
			const base64Digest = btoa(String.fromCharCode(...new Uint8Array(digest)))
				.replace(/\+/g, '-')
				.replace(/\//g, '_')
				.replace(/=/g, '');
			
			if (base64Digest !== authData.codeChallenge) {
				console.error('🔴 TOKEN ERROR: PKCE validation failed');
				return c.json({ error: 'invalid_grant' }, 400);
			}
			console.log('🔵 TOKEN: PKCE validation successful');
		}

		// Validate client and redirect URI
		if (authData.clientId !== clientId || authData.redirectUri !== redirectUri) {
			console.error('🔴 TOKEN ERROR: Client ID or redirect URI mismatch');
			return c.json({ error: 'invalid_grant' }, 400);
		}

		// Generate access token
		const accessToken = crypto.randomUUID();
		console.log('🔵 TOKEN: Generated access token for user:', authData.userId);
		
		// Store token data in KV
		const tokenData = {
			userId: authData.userId,
			clientId: authData.clientId,
			scope: authData.scope,
			createdAt: Date.now(),
		};
		
		await c.env.OAUTH_KV.put(`access_token:${accessToken}`, JSON.stringify(tokenData), { expirationTtl: 3600 });
		console.log('🔵 TOKEN: Access token stored in KV');

		// Clean up authorization code
		await c.env.OAUTH_KV.delete(`auth_code:${code}`);

		return c.json({
			access_token: accessToken,
			token_type: 'Bearer',
			expires_in: 3600,
			scope: authData.scope,
		});
	} catch (error) {
		console.error('🔴 TOKEN ERROR: Token exchange failed:', error);
		return c.json({ 
			error: 'server_error', 
			details: error instanceof Error ? error.message : String(error) 
		}, 500);
	}
});

// Client Registration (OAuth Dynamic Registration)
app.post('/reg', async (c) => {
	try {
		const body = await c.req.json();
		
		// Validate required fields per RFC 7591
		if (!body.redirect_uris || !Array.isArray(body.redirect_uris)) {
			console.error('🔴 REG ERROR: Missing or invalid redirect_uris');
			return c.json({ error: 'invalid_client_metadata' }, 400);
		}

		const clientId = crypto.randomUUID();
		const clientSecret = crypto.randomUUID();
		
		console.log('🔵 REG: Generated client:', { clientId, hasSecret: !!clientSecret });

		// Store client metadata in KV
		const clientData = {
			...body,
			client_id: clientId,
			client_secret: clientSecret,
			client_id_issued_at: Math.floor(Date.now() / 1000),
		};

		await c.env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(clientData));
		console.log('🔵 REG: Client registered successfully');

		return c.json({
			client_id: clientId,
			client_secret: clientSecret,
			client_id_issued_at: Math.floor(Date.now() / 1000),
			...body,
		});
	} catch (error) {
		console.error('🔴 REG ERROR: Client registration failed:', error);
		return c.json({ 
			error: 'server_error', 
			details: error instanceof Error ? error.message : String(error) 
		}, 500);
	}
});

// Token Revocation / Logout
app.post('/revoke', async (c) => {
	try {
		const body = await c.req.text();
		const params = new URLSearchParams(body);
		
		const token = params.get('token');
		const tokenTypeHint = params.get('token_type_hint');
		
		if (!token) {
			console.error('🔴 REVOKE ERROR: Missing token parameter');
			return c.json({ error: 'invalid_request' }, 400);
		}

		console.log('🔵 REVOKE: Revoking token:', { tokenHint: tokenTypeHint });

		// Try to revoke as access token
		const accessTokenKey = `access_token:${token}`;
		const accessTokenData = await c.env.OAUTH_KV.get(accessTokenKey);
		if (accessTokenData) {
			await c.env.OAUTH_KV.delete(accessTokenKey);
			console.log('🔵 REVOKE: Access token revoked successfully');
		}

		// Try to revoke as auth code (just in case)
		const authCodeKey = `auth_code:${token}`;
		const authCodeData = await c.env.OAUTH_KV.get(authCodeKey);
		if (authCodeData) {
			await c.env.OAUTH_KV.delete(authCodeKey);
			console.log('🔵 REVOKE: Auth code revoked successfully');
		}

		// Per RFC 7009, return 200 OK even if token wasn't found
		console.log('🔵 REVOKE: Token revocation completed');
		return c.text('', 200);
	} catch (error) {
		console.error('🔴 REVOKE ERROR: Token revocation failed:', error);
		return c.json({ 
			error: 'server_error', 
			details: error instanceof Error ? error.message : String(error) 
		}, 500);
	}
});

// Bearer token authentication middleware
const requireAuth = async (c: any, next: any) => {

	// Validate OAuth Bearer token
	const authHeader = c.req.header('Authorization');
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		console.error('🔴 MCP ERROR: Missing or invalid Authorization header');
		c.header('WWW-Authenticate', 'Bearer realm="mcp"');
		return c.text('Unauthorized', 401);
	}

	const token = authHeader.substring(7); // Remove "Bearer " prefix
	console.log('🔵 MCP: Validating access token...');
	
	// Retrieve token data from KV
	const tokenDataStr = await c.env.OAUTH_KV.get(`access_token:${token}`);
	if (!tokenDataStr) {
		console.error('🔴 MCP ERROR: Invalid or expired access token');
		c.header('WWW-Authenticate', 'Bearer realm="mcp"');
		return c.text('Unauthorized', 401);
	}

	const tokenData = JSON.parse(tokenDataStr);
	console.log('🔵 MCP: Token validated for user:', tokenData.userId);

	// Set user context
	c.env.userId = tokenData.userId;
	
	await next();
};

// GET /mcp - Discovery/Health Check (no auth required)
app.get('/mcp', async (c) => {
	const url = new URL(c.req.url);
	return c.json({
		name: "Privium MCP Server",
		version: "0.3.1",
		status: "running",
		protocol: "Model Context Protocol",
		authentication_required: true,
		authorization_endpoint: `${url.origin}/authorize`,
		resource_metadata: `${url.origin}/.well-known/oauth-protected-resource`,
		documentation: "https://github.com/arbuthnot-eth/privium",
		endpoints: {
			mcp: `${url.origin}/mcp (POST only)`,
			authorize: `${url.origin}/authorize`,
			token: `${url.origin}/token`,
		}
	});
});

// MCP API with Bearer Token validation (POST requests)
app.post('/mcp', requireAuth, async (c) => {
	try {
		return MCPrivy.serve('/mcp').fetch(c.req.raw, c.env, {} as ExecutionContext);
	} catch (error) {
		console.error('🔴 MCP ERROR: Request failed:', error);
		return c.text('Internal Server Error', 500);
	}
});

// MCP API with Bearer Token validation (catch-all for other methods)
app.all('/mcp/*', requireAuth, async (c) => {
	try {
		return MCPrivy.serve('/mcp').fetch(c.req.raw, c.env, {} as ExecutionContext);
	} catch (error) {
		console.error('🔴 MCP ERROR: Request failed:', error);
		return c.text('Internal Server Error', 500);
	}
});

// Serve static assets (fallback for other requests)
app.get('*', async (c) => {
	try {
		return c.env.ASSETS.fetch(c.req.raw);
	} catch (error) {
		return c.text('Not Found', 404);
	}
});

export default app;