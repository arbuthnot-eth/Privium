import { PrivyClient } from "@privy-io/server-auth";
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerTools } from "./mcp_tools";



interface Env {
	PRIVY_APP_ID: string;
	PRIVY_APP_SECRET: string;
	AUTH_PRIVATE_KEY: string; // Use this PEM key for signing (SDK handles it)
	QUORUM_ID: string;
	MCP_OBJECT: DurableObjectNamespace; // Added for MCP Durable Object
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

// CORS headers (allow all origins for dev; restrict in prod, e.g., to your client's origin)
const corsHeaders = {
	'Access-Control-Allow-Origin': '*', // Or 'http://localhost:6274' for specific
	'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, PUT, DELETE',
	'Access-Control-Allow-Headers': '*',
	'Access-Control-Max-Age': '86400', // Cache preflight for 24 hours
};

export default {
	fetch(request: Request, env: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);
		const pathname = url.pathname.replace(/\/$/, ''); // Normalize by removing trailing slash


    // Helper to verify token and extend env with userId
    async function verifyToken(token: string | null): Promise<Env | null> {
		if (!token) {
		  console.log('No token provided');
		  return null;
		}
		try {
			const client = initPrivyClient(env);
			const verificationResult = await client.verifyAuthToken(token);
			console.log('Token verification successful for user:', verificationResult.userId);
			return { ...env, userId: verificationResult.userId };
			} catch (error) {
		  		console.error('Authentication error:', error);
		  		return null;
			}
		}

		if (url.pathname === "/mcp") {
			return MCPrivy.serve("/mcp").fetch(request, env, ctx);
		}



    // Handle root route
    if (pathname === '' || pathname === '/') {
		return new Response(`
		  	<!DOCTYPE html>
		  	<html>
			<head><title>MCPrivy Backend</title></head>
			<body>
			  <h1>MCPrivy Backend Server</h1>
			  <p>WebSocket endpoint: <code>/ws?token=yourtoken</code></p>
			  <p>Health check: <code>/health</code></p>
			  <p>MCP SSE endpoint: <code>/sse?token=yourtoken</code></p>
			  <p>MCP endpoint: <code>/mcp?token=yourtoken</code></p>
			  <p>Current path: <code>${pathname}</code></p>
			</body>
		  </html>
		`, {
		  headers: { ...corsHeaders, 'Content-Type': 'text/html' }
		});
	}



		return new Response("Not found", {
			status: 404, 
			headers: corsHeaders,
		});
	},
};
