import { PrivyClient } from "@privy-io/server-auth";
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerTools } from "./mcp_tools";

// Check for OAuth flag
const useOAuth = process.argv.includes('--oauth');
const app = new Hono<{ Bindings: Env }>();

interface Env {
	PRIVY_APP_ID: string;
	PRIVY_APP_SECRET: string;
	AUTH_PRIVATE_KEY: string; // Use this PEM key for signing (SDK handles it)
	QUORUM_ID: string;
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

// // Helper to verify token and extend env with userId
// async function verifyToken(token: string | null, env: Env): Promise<Env | null> {
// 	if (!token) {
// 		console.log('No token provided');
// 		return null;
// 	}
// 	try {
// 		const client = initPrivyClient(env);
// 		const verificationResult = await client.verifyAuthToken(token);
// 		console.log('Token verification successful for user:', verificationResult.userId);
// 		return { ...env, userId: verificationResult.userId };
// 	} catch (error) {
// 		console.error('Authentication error:', error);
// 		return null;
// 	}
// }



// Allow CORS all domains, expose the Mcp-Session-Id header
app.use(cors({
	origin: '*', // Allow all origins
	exposeHeaders: ["Mcp-Session-Id"]
  }));
  
// Define our MCP agent with version and register tools
export class MCPrivy extends McpAgent {
	server = new McpServer({
		name: "Privium",
		version: "0.0.12",
	});
	async init() {
		// Register tools from external file (mcp_tools.ts)
		registerTools(this.server);
	}
}


if (!useOAuth) {
	app.post('/mcp', (c) => {
		console.log("Not using OAuth");
		return MCPrivy.serve("/mcp").fetch(c.req.raw, c.env, c.executionCtx);

	});
} else {
	app.post('/mcp', (c) => {
		console.log("Not using OAuth");
		return c.text("Using OAuth", 404);
	});
}

app.all('/mcp/*', (c) => {
	return c.text("Good looks");
});

app.get('/mcp/*', (c) => {
	return c.text("Good looks");
});

export default app;
