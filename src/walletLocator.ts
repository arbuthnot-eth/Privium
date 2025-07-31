import { initCrossmint } from "./authMiddleware"
import { Wallet, type Chain } from "@crossmint/wallets-sdk"

export async function createCrossmintWallet(privyUser: PrivyUser, chain: string) {
    try {
        const crossmintWallets = initCrossmint()

        const privyWallet = await getPrivyWallets(privyUser)


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

export async function getPrivyWallets(privyUser: PrivyUser): Promise<any | any[]> {
    return privyUser?.linkedAccounts?.filter((acc: any) => acc.type === 'wallet' && acc.walletClientType === 'privy')
}