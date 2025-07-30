import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { createCrossmintWallet, getCrossmintBalances } from "../walletLocator"

// Register all Crossmint-related tools
export async function registerCrossmintTools(server: McpServer, user: any) {
	// Create Crossmint Wallet Tool
	server.registerTool(
		"Smart Wallets",
		{
			title: "Create Crossmint Wallet",
			description: "Create a new Crossmint wallet for the current user",
			inputSchema: {}
		},
		async () => {
			const ethWallet = await createCrossmintWallet(user, "ethereum")
			const solWallet = await createCrossmintWallet(user, "solana")
			// const suiWallet =  await createCrossmintWallet(user, "sui")

			const wallets = {
				ethereum: {
					wallet: ethWallet,
					balances: await getCrossmintBalances(ethWallet),
				},
				solana: {
					wallet: solWallet,
					balances: await getCrossmintBalances(solWallet),
				},
				// sui: {
				// 	wallet: suiWallet,
				// 	balances: await getCrossmintBalances(suiWallet),
				// },
			}
			return {
				content: [{
					type: "text",
					mimeType: "application/json",
					text: JSON.stringify(wallets)
				}]
			}
		}
	)
}