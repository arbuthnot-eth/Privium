import { z } from "zod"
import { McpAgent } from "agents/mcp"
import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js"
import { SERVER_NAME, SERVER_VERSION } from "./config"
import { getPrivyWallets, translateENS } from "./walletLocator"
import { refreshUser } from "./authMiddleware"
import { signMessage } from "./Privy/walletUtils"

// Define our MCP agent with version and register tools
export class SuperAgent extends McpAgent<Env, DurableObjectState, {}> {
	server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION, description: SERVER_NAME + ' MCP Server' })

	// Initialize the MCP agent
	async init() {
		console.log('⛅', SERVER_NAME, 'Agent initialized, Version:', SERVER_VERSION)
		console.log('.      for: ' + this.env.privyUser?.id)
	}

	async fetch(request: Request) {
		const userJson = request.headers.get('X-Privy-User')
		if (!userJson) {
			throw new Error('No user provided in request')
		}
		const cachedUser = JSON.parse(userJson)
		const refreshedData = await refreshUser(cachedUser)
		const user = refreshedData.freshUser || refreshedData.cachedUser
		if (!user) {
			throw new Error("No user available")
		}

		// Verify Id consistency
		if (user.id !== cachedUser.id) {
			console.error('🔴 AUTH ERROR: User ID mismatch between cached and refreshed data')
			throw new Error('User ID mismatch - potential security issue')
		}
		
		const privyClient = refreshedData.privyClient
		registerTools(this.server, { user, privyClient })
		registerResources(this.server, user)
		return super.fetch(request)
	}
}

// Register Tools
async function registerTools(server: McpServer, privy: { user: PrivyUser, privyClient: any }) {
	const user = privy.user
	const privyClient = privy.privyClient

	// Get User Wallets Tool
	server.registerTool(
		"Embedded Wallets",
		{
			title: "Get App Wallets",
			description: "Get all embedded wallets connected to the current user",
			inputSchema: {}
		},
		async () => {
			try {
				const wallets = await getPrivyWallets(user)

				return {
					content: [{
						type: "text",
						text: JSON.stringify(wallets)
					}]
				}
			} catch (error) {
				return {
					content: [{
						type: "text",
						text: `❌ Error: ${error instanceof Error ? error.message : String(error)}`
					}]
				}
			}
		}
	)

	// Get User Wallets Tool
	server.registerTool(
		"Sign Message",
		{
			title: "Sign Message",
			description: "Sign a message with a wallet",
			inputSchema: {
				walletId: z.string().describe("The wallet ID to sign the message with"),
				message: z.string().describe("The message to sign")
			}
		},
		async ({ message, walletId }: { message: string, walletId: string }) => {
			try {
				const sig = await signMessage(message, walletId, privyClient)

				return {
					content: [{
						type: "text",
						text: JSON.stringify(sig)
					}]
				}
			} catch (error) {
				return {
					content: [{
						type: "text",
						text: `❌ Error: ${error instanceof Error ? error.message : String(error)}`
					}]
				}
			}
		}
	)

	// Add a tool to get user info easily (no URI needed)
	server.registerTool(
		"Active User",
		{
			title: "Active User",
			description: "Get current authenticated user information",
			inputSchema: {}
		},
		async () => {
			try {
				if (!user) {
					return {
						content: [{
							type: "text",
							text: "❌ User context not available - make sure you're authenticated"
						}]
					}
				}


				const walletCount = user.linkedAccounts?.filter((acc: any) => acc.type === 'wallet').length || 0

				return {
					content: [{
						type: "text",
						text: `✅ **User Profile**\n\n📧 **Email:** ${user.email?.address || 'Not set'}\n🆔 **ID:** ${user.id}\n💼 **Wallets:** ${walletCount}\n\n**Available Resources:**\n- \`user://me\` - Full user data\n- \`user://profile\` - Structured profile`
					}]
				}
			} catch (error) {
				return {
					content: [{
						type: "text",
						text: `❌ Error: ${error instanceof Error ? error.message : String(error)}`
					}]
				}
			}
		}
	)

	// Crossmint tools and funcionality
	// await registerCrossmintTools(server, user)

	// Get Authentication Status Tool
	server.registerTool(
		"auth_status",
		{
			title: "Authentication Status",
			description: "Check the current authentication status and session information",
			inputSchema: {}
		},
		async () => {
			try {
				if (!user) {
					return {
						content: [{
							type: "text",
							text: "❌ Not authenticated"
						}]
					}
				}

				return {
					content: [{
						type: "text",
						text: `🔐 **Authentication Status**\n\n✅ **Authenticated**: Yes\n🆔 **User ID**: ${user.id}\n📧 **Email**: ${user.email?.address || 'Not set'}\n📱 **Linked Accounts**: ${user.linkedAccounts?.length || 0}\n\nUse \`user://me\` resource for full profile details.`
					}]
				}
			} catch (error) {
				return {
					content: [{
						type: "text",
						text: `❌ Error: ${error instanceof Error ? error.message : String(error)}`
					}]
				}
			}
		}
	)

	// List Linked Accounts Tool
	server.registerTool(
		"list_linked_accounts",
		{
			title: "List Linked Accounts",
			description: "List all accounts linked to the current user",
			inputSchema: {}
		},
		async () => {
			try {
				if (!user) {
					return {
						content: [{
							type: "text",
							text: "❌ User not authenticated"
						}]
					}
				}

				const accounts = user.linkedAccounts || []

				if (accounts.length === 0) {
					return {
						content: [{
							type: "text",
							text: "📭 No accounts linked to this user"
						}]
					}
				}

				const accountSummary = accounts.map((account: any, index: number) => {
					const type = account.type
					let details = ''

					switch (type) {
						case 'wallet':
							details = `Address: ${account.address}\nClient: ${account.walletClientType || 'Unknown'}`
							break
						case 'email':
							details = `Email: ${account.address}\nVerified: ${account.verified ? 'Yes' : 'No'}`
							break
						case 'phone':
							details = `Phone: ${account.phoneCountryCode} ${account.phoneNumber}\nVerified: ${account.verified ? 'Yes' : 'No'}`
							break
						default:
							details = `Details: ${JSON.stringify(account, null, 2)}`
					}

					return `${index + 1}. **${type.toUpperCase()}**\n   ${details.replace(/\n/g, '\n   ')}`
				}).join('\n\n')

				return {
					content: [{
						type: "text",
						text: `🔗 **Linked Accounts** (${accounts.length})\n\n${accountSummary}`
					}]
				}
			} catch (error) {
				return {
					content: [{
						type: "text",
						text: `❌ Error: ${error instanceof Error ? error.message : String(error)}`
					}]
				}
			}
		}
	)

	// List Resources Tool
	server.registerTool(
		"list_resources",
		{
			title: "List Resources",
			description: "Shows available resources and how to access them",
			inputSchema: {}
		},
		async () => {
			const resourceList = [
				{
					name: "user://me",
					description: "Complete user profile with all Privy data",
					example: "Just type: user://me"
				},
				{
					name: "user://[anything]/profile",
					description: "Structured user profile (clean format)",
					example: "Try: user://current/profile"
				},
				{
					name: "wallets://me",
					description: "User's connected wallets",
					example: "Just type: wallets://me"
				}
			]

			const help = `🔗 **Available Resources**\n\n${resourceList.map(r =>
				`**${r.name}**\n${r.description}\n💡 ${r.example}\n`
			).join('\n')}\n📝 **How to use:** Go to Resources tab → Type URI → Click "Fetch Resource"`

			return {
				content: [{
					type: "text",
					text: help
				}]
			}
		}
	)

	// Simple addition tool
	server.registerTool(
		"add",
		{
			title: "Addition Tool",
			description: "A simple tool to add two numbers",
			inputSchema: {
				a: z.number().describe("First number"),
				b: z.number().describe("Second number")
			},
		},
		async ({ a, b }: { a: number, b: number }) => ({
			content: [{ type: "text", text: String(a + b) }],
		})
	)

	// ENS to Address Translation Tool
	server.registerTool(
		'translate',
		{
			title: 'Translate ENS to Address',
			description: 'Translate an ENS name to an address',
			inputSchema: {
				ens: z.string().describe('ENS name to translate'),
				chain: z.string().describe('Chain to translate to'),
			},
		},
		async ({ ens, chain }: { ens: string, chain: string | 'ethereum' }) => {
			const addr = await translateENS(ens, chain)
			return { content: [{ type: "text", text: `Address: ${addr}` }] }
		}
	)

	// Calculator tool with multiple operations
	server.registerTool(
		"calculate",
		{
			title: "Calculator Tool",
			description: "A tool to perform basic arithmetic operations",
			inputSchema: {
				operation: z.enum(["add", "subtract", "multiply", "divide"]).describe("Operation to perform"),
				a: z.number().describe("First number"),
				b: z.number().describe("Second number"),
			},
		},
		async ({ operation, a, b }: { operation: string, a: number, b: number }) => {
			let result: number | undefined
			switch (operation) {
				case "add":
					result = a + b
					break
				case "subtract":
					result = a - b
					break
				case "multiply":
					result = a * b
					break
				case "divide":
					if (b === 0)
						return {
							content: [
								{
									type: "text",
									text: "Error: Cannot divide by zero",
								},
							],
						}
					result = a / b
					break
			}
			return { content: [{ type: "text", text: String(result) }] }
		}
	)
}

// Register Resources
async function registerResources(server: McpServer, user: PrivyUser) {

	// Add a dynamic greeting resource
	server.registerResource(
		"greeting",
		new ResourceTemplate("greeting://{name}", { list: undefined }),
		{
			title: "Greeting Resource",      // Display name for UI
			description: "Dynamic greeting generator"
		},
		async (uri: URL, extra: any) => { // Explicitly type uri and extra
			// Assuming 'name' is passed in the 'extra' object by the ResourceTemplate
			const name = extra.name || 'Guest' // Access name directly from extra
			return {
				contents: [{
					uri: uri.href,
					text: `Hello, ${name}!`
				}]
			}
		}
	)

	// Add a simpler "me" resource for easy access
	server.registerResource(
		"Current User",
		new ResourceTemplate("user://me", { list: undefined }),
		{
			title: "Current User",
			description: "Fetches the current authenticated user's information"
		},
		async (uri: URL, extra: any) => {
			try {
				if (!user) {
					throw new Error("User context not available")
				}

				return {
					contents: [{
						uri: uri.href,
						mimeType: "application/json",
						text: JSON.stringify(user, null, 2)
					}]
				}
			} catch (error) {
				return {
					contents: [{
						uri: uri.href,
						mimeType: "application/json",
						text: JSON.stringify({ error: "Failed to fetch current user" })
					}]
				}
			}
		}
	)

	// Add user resource
	server.registerResource(
		"whoami",
		new ResourceTemplate("user://me", { list: undefined }),
		{
			title: "User Information",
			description: "Fetches the current user's Privy profile information"
		},
		async (uri: URL, extra: any) => {
			try {
				if (!user) {
					throw new Error("User context not available")
				}

				return {
					contents: [{
						uri: "user://" + user.id,
						mimeType: "application/json",
						text: JSON.stringify(user, null, 2)
					}]
				}
			} catch (error) {
				return {
					contents: [{
						uri: uri.href,
						mimeType: "application/json",
						text: JSON.stringify({ error: "Failed to fetch user information" })
					}]
				}
			}
		}
	)

	// Add wallets resource
	server.registerResource(
		"wallets",
		new ResourceTemplate("wallets://me", { list: undefined }),
		{
			title: "User Wallets",
			description: "Fetches the current user's linked wallets from Privy"
		},
		async (uri: URL, extra: any) => {
			try {
				if (!user) {
					throw new Error("User context not available")
				}
				// Use the already-stored Privy user data
				const wallets = user.linkedAccounts.filter(
					(account: any) => account.type === 'wallet'
				)
				return {
					contents: [{
						uri: uri.href,
						mimeType: "application/json",
						text: JSON.stringify(wallets)
					}]
				}
			} catch (error) {
				return {
					contents: [{
						uri: uri.href,
						mimeType: "application/json",
						text: JSON.stringify({ error: "Failed to fetch wallets" })
					}]
				}
			}
		}
	)


}
