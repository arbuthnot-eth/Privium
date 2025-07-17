import { z } from "zod";
import { McpServer, ResourceTemplate} from "@modelcontextprotocol/sdk/server/mcp.js";

export function registerTools(server: McpServer) {
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
		async ({ a, b }) => ({
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
		async({name}) => {
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
		async ({ operation, a, b }) => {
			let result: number;
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