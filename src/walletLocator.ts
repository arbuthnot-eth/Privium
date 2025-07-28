import { initCrossmint } from "./authMiddleware"
import { Wallet, type Chain } from "@crossmint/wallets-sdk"

export async function createCrossmintWallet(privyUser: Env["privyUser"], chain: string) {
    try {
        const crossmintWallets = initCrossmint()

        const privyWallet = await getPrivyWallets(privyUser, chain)


        const wallet = await crossmintWallets.createWallet({
            chain: chain as Chain,
            signer: {
                type: "external-wallet",
                address: privyWallet.address
            },
            owner: "userId:" + privyUser?.id,
        })
        return wallet as Wallet<Chain>
    } catch (error) {
        console.error('Error creating Crossmint wallet:', error)
        throw error
    }
}

export async function getCrossmintBalances(wallet: Wallet<Chain>) {
    const balances = await wallet.balances()
    return balances
}

export async function getPrivyWallets(privyUser: Env["privyUser"], chain?: string): Promise<any | any[]> {
    if (chain) {
        const wallet = privyUser?.linkedAccounts?.find((acc: any) => acc.type === 'wallet' && acc.chainType === chain && acc.walletClientType === 'privy');
        return wallet
    }
    const wallets = privyUser?.linkedAccounts?.filter((acc: any) => acc.type === 'wallet' && acc.walletClientType === 'privy');
    return wallets
}