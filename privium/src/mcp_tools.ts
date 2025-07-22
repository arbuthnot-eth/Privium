import { z } from "zod";
import { ResourceTemplate} from "@modelcontextprotocol/sdk/server/mcp.js";
import { PrivyClient } from "@privy-io/server-auth";

export function initPrivyClient(env: any): PrivyClient {
  return new PrivyClient(env.PRIVY_APP_ID, env.PRIVY_APP_SECRET, {
    walletApi: {
      authorizationPrivateKey: env.AUTH_PRIVATE_KEY,
    },
  });
}

export function registerTools(agent: any, privyClient: PrivyClient) {
	const server = agent.server;
	const toolList: { name: string; title: string; description: string }[] = [];
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
	);
	toolList.push({ name: "add", title: "Addition Tool", description: "A simple tool to add two numbers" });

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
			return { content: [{ type: "text", text: `Hello, ${name}!` }] };
		}
	);
	toolList.push({ name: "greet", title: "Greeting Tool", description: "A simple greeting tool" });
	
	
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
			let result: number | undefined;
			switch (operation) {
				case "add":
					result = a + b;
					break;
				case "subtract":
					result = a - b;
					break;
				case "multiply":
					result = a * b;
					break;
				case "divide":
					if (b === 0)
						return {
							content: [
								{
									type: "text",
									text: "Error: Cannot divide by zero",
								},
							],
						};
					result = a / b;
					break;
			}
			return { content: [{ type: "text", text: String(result) }] };
		}
	);
	toolList.push({ name: "calculate", title: "Calculator Tool", description: "A tool to perform basic arithmetic operations" });


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
			const name = extra.name || 'Guest'; // Access name directly from extra
		    return {
			    contents: [{
				    uri: uri.href,
				    text: `Hello, ${name}!`
				}]
			};
		}
	);
	toolList.push({ name: "greeting", title: "Greeting Resource", description: "Dynamic greeting generator" });

	// Add user resource
	server.registerResource(
		"whoami",
		new ResourceTemplate("user://me", { list: undefined }),
		{
			title: "User Information",
			description: "Fetches the current user's Privy profile information"
		},
		async () => {
			const user = await privyClient.getUserById(agent.env.userId);
			return {
				contents: [{
					uri: "user://" + agent.env.userId,
					mimeType: "application/json",
					text: JSON.stringify(user, null, 2)
				}]
			}
		}
	);

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
				const user = await privyClient.getUserById(agent.id.name());
				const wallets = user.linkedAccounts.filter(
					(account) => account.type === 'wallet'
				);
				return {
					contents: [{
						uri: uri.href,
						mimeType: "application/json",
						text: JSON.stringify(wallets)
					}]
				};
			} catch (error) {
				return {
					contents: [{
						uri: uri.href,
						mimeType: "application/json",
						text: JSON.stringify({ error: "Failed to fetch wallets" })
					}]
				};
			}
		}
	);


	server.registerTool(
		"list_tools",
		{
			title: "List Tools",
			description: "Gets the title and description of all available tools",
			inputSchema: {},
		},
		async () => {
			return { content: [{ type: "text", text: JSON.stringify(toolList, null, 2) }] };
		}
	);

		  // TODO: Add your own tools here, e.g., a "signMessage" tool that integrates with Privy/wallet logic
		  // this.server.tool("signMessage", { message: z.string() }, async ({ message }) => {
		  //   if (!this.env.userId) throw new Error("Unauthorized");
		  //   ...
		  // });

}