import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { createCrossmintWallet, getCrossmintBalances } from "../walletLocator"
// import { initCrossmint } from "./authMiddleware"
// import { Wallet, type Chain } from "@crossmint/wallets-sdk"

// export async function createCrossmintWallet(privyUser: PrivyUser, chain: string) {
//     try {
//         const crossmintWallets = initCrossmint()

//         const privyWallet = await getPrivyWallets(privyUser)


//         const wallet = await crossmintWallets.createWallet({
//             chain: chain as Chain,
//             signer: {
//                 type: "external-wallet",
//                 address: privyWallet.address
//             },
//             owner: "userId:" + privyUser?.id,
//         })
//         return wallet as Wallet<Chain>
//     } catch (error) {
//         console.error('Error creating Crossmint wallet:', error)
//         throw error
//     }
// }

// export async function getCrossmintBalances(wallet: Wallet<Chain>) {
//     const balances = await wallet.balances()
//     return balances
// }
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