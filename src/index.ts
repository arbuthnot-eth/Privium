import { SuperAgent } from "./mcp_tools"
import { Hono } from 'hono'
import { requireAuth, authHandler } from "./authMiddleware"
import { SERVER_NAME, SERVER_VERSION } from "./config"

// Hono App
const app = new Hono<{ Bindings: Env }>()

// Auth Handler
authHandler(app)

// GET /mcp - Discovery/Health Check (no auth required)
app.get('/mcp', async (c) => {
	const url = new URL(c.req.url)
	return c.json({
		name: SERVER_NAME,
		version: SERVER_VERSION,
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
	})
})

// MCP API with Bearer Token validation (POST requests)
app.post('/mcp', requireAuth, async (c) => {
	try {
		return SuperAgent.serve('/mcp').fetch(c.req.raw, c.env, c.executionCtx)
	} catch (error) {
		console.error('🔴 MCP ERROR: Request failed:', error)
		return c.text('Internal Server Error', 500)
	}
})

// MCP API with Bearer Token validation (catch-all for other methods)
app.all('/mcp/*', requireAuth, async (c) => {
	try {
		return SuperAgent.serve('/mcp').fetch(c.req.raw, c.env, c.executionCtx)
	} catch (error) {
		console.error('🔴 MCP ERROR: Request failed:', error)
		return c.text('Internal Server Error', 500)
	}
})

// Serve static assets (fallback for other requests)
app.get('*', async (c) => {
	try {
		return c.env.ASSETS.fetch(c.req.raw)
	} catch (error) {
		return c.text('Not Found', 404)
	}
})

export { SuperAgent }
export default app