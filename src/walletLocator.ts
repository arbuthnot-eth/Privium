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
                address: (await getPrivyWallets(privyUser, chain)).address
            }
        })
        return wallet as Wallet<Chain>
    } catch (error) {
        return {
            content: [{
                type: "text",
                text: `❌ Error: ${error instanceof Error ? error.message : String(error)}`
            }]
        }
    }
}

export async function getPrivyWallets(privyUser: any, chain?: string): Promise<any | any[]> {
    if (chain) {
        const wallet = privyUser.linkedAccounts?.find((acc: any) => acc.type === 'wallet' && acc.chainType === chain && acc.walletClientType === 'privy');
        return wallet as Wallet<Chain>;
    }
    const wallets = privyUser.linkedAccounts?.filter((acc: any) => acc.type === 'wallet' && acc.walletClientType === 'privy');
    return wallets as any[];
}