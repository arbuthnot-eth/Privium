import { initCrossmint } from "./authMiddleware"
import { Wallet, type Chain } from "@crossmint/wallets-sdk"

export async function createCrossmintWallet(privyUser: any, chain: string) {
    try {
        const crossmintWallets = initCrossmint()
        const wallet = await crossmintWallets.createWallet({
            owner: "userId:" + privyUser.id,
            chain: chain as Chain,
            signer: {
                type: "external-wallet",
                address: (await getWallet(privyUser, chain))?.address
            }
        })
        return wallet
    } catch (error) {
        return {
            content: [{
                type: "text",
                text: `❌ Error: ${error instanceof Error ? error.message : String(error)}`
            }]
        }
    }
}

async function getWallet(privyUser: any, chain: string) {
    const wallet = await privyUser.linkedAccounts.find((acc: any) => acc.type === 'wallet' && acc.chainType === chain && acc.walletClientType === 'privy')
    return wallet
}