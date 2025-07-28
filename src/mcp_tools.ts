import { z } from "zod"
import { McpAgent } from "agents/mcp"
import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js"
import { SERVER_NAME, SERVER_VERSION } from "./config"
import { createCrossmintWallet, getPrivyWallets } from "./walletLocator"

// Define our MCP agent with version and register tools
export class SuperAgent extends McpAgent<Env, DurableObjectState, {}> {
	server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION, description: SERVER_NAME + ' MCP Server'})
	
	// Initialize the MCP agent
	async init() {
	  // Register tools and resources from external file (mcp_tools.ts)
	  registerTools(this.server, this.env.privyUser)
	  registerResources(this.server, this.env.privyUser)
	  console.log('⛅',SERVER_NAME, 'Agent initialized, Version:', SERVER_VERSION)
	  console.log('.      for: ' + this.env.privyUser?.id)
	}
}

// Register Tools
async function registerTools(server: McpServer, user: any) {

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

	// Greeting Tool
	server.registerTool(
		'greet',
		{
			title: 'Greeting Tool',
			description: 'A simple greeting tool',
			inputSchema: {
				name: z.string().describe('Name to greet'),
			},
		},
		async({ name }: { name: string }) => {
			return { content: [{ type: "text", text: `Hello, ${name}!` }] }
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

				return {
					content: [{
						type: "text", 
						text: `✅ **User Profile**\n\n📧 **Email:** ${user.email?.address || 'Not set'}\n🆔 **ID:** ${user.id}\n📅 **Created:** ${new Date(user.createdAt).toLocaleDateString()}\n👤 **Type:** ${user.isGuest ? 'Guest' : 'Full User'}\n💼 **Wallets:** ${user.linkedAccounts?.filter((acc: any) => acc.type === 'wallet').length || 0}\n\n**Available Resources:**\n- \`user://me\` - Full user data\n- \`user://profile\` - Structured profile`
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

	// Get User Wallets Tool
	server.registerTool(
		"Get Privy Wallets",
		{
			title: "Get App Wallets",
			description: "Get all embedded wallets connected to the current user",
			inputSchema: {}
		},
		async () => {
			try {
				const wallets = await getPrivyWallets(user)

				const walletsInfo = wallets.map((wallet: any, index: number) => {
					return `${index + 1}. ${wallet.address}\n   📋 Type: ${wallet.walletClientType || 'Unknown'}\n   🌐 Chain: ${wallet.chainType || 'EVM'}`
				}).join('\n\n')

				return {
					content: [{
						type: "text",
						text: `💼 Embedded Wallets (${wallets.length}):\n\n${walletsInfo}`
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

	// Create Crossmint Wallet Tool
	server.registerTool(
		"getSmartWallets",
		{
			title: "Create Crossmint Wallet",
			description: "Create a new Crossmint wallet for the current user",
			inputSchema: {}
		},
		async () => {
			const wallets = {
				ethereum: await createCrossmintWallet(user, "ethereum"), 
				solana: await createCrossmintWallet(user, "solana")
				// sui: await createCrossmintWallet(user, "sui")
			};
			return {
				content: [{
					type: "text",
					mimeType: "application/json",
					text: JSON.stringify(wallets)
				}]
			}
		}
	)


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

				const now = Date.now()
				const createdAt = new Date(user.createdAt).getTime()
				const sessionAge = Math.floor((now - createdAt) / (1000 * 60 * 60 * 24)) // Days

				return {
					content: [{
						type: "text",
						text: `🔐 **Authentication Status**\n\n✅ **Authenticated**: Yes\n🆔 **User ID**: ${user.id}\n📧 **Email**: ${user.email?.address || 'Not set'}\n📅 **Account Created**: ${new Date(user.createdAt).toLocaleDateString()}\n⏱️ **Session Age**: ${sessionAge} days\n📱 **Linked Accounts**: ${user.linkedAccounts?.length || 0}\n\nUse \`user://me\` resource for full profile details.`
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
}

// Register Resources
async function registerResources(server: McpServer, user: any) {

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
				// Use the already-stored Privy user data
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
