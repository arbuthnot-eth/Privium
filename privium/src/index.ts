import { PrivyClient } from "@privy-io/server-auth";
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { oauthMetadata } from '@modelcontextprotocol/sdk/src/shared/oauth.js';
import { randomUUID } from 'crypto';
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

// Privy auth
app.use('*', async (c, next) => {
	const privyClient = initPrivyClient(c.env);
	const token = c.req.header('Authorization')?.split(' ')[1];
	if (!token) return c.text('Unauthorized', 401);
	try {
	  const verifiedClaims = await privyClient.verifyAuthToken(token);
	} catch (error) {
	  return c.text('Invalid token', 401);
	}
	await next();
});


app.post('/mcp', (c) => {
		return MCPrivy.serve("/mcp").fetch(c.req.raw, c.env, c.executionCtx);
});


// app.get('/mcp', (c) => {
// 	return MCPrivy.serve("/mcp").fetch(c.req.raw, c.env, c.executionCtx);
// });

export default app;