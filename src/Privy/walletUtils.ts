
export async function createWalletsIfNeeded(user: PrivyUser, privyClient: any) {
    let suiWallet = null
    try {
      // Check if user already has a Sui wallet
      suiWallet = user.linkedAccounts.find(
        (account: any) => account.type === 'wallet' && account.chainType === 'sui' && account.walletClientType === 'privy'
      )

      if (!suiWallet) {
        // Create wallets for the user
        try {
          suiWallet = await privyClient.walletApi.createWallet({
            chainType: 'sui',
            owner: { userId: user.id },
          })
          console.log('🟢 Wallet: Created Sui wallet for user:', user.id)
        } catch (error) {
          console.error('🔴 Wallet ERROR: Failed to create wallets:', error)
        }
      }

      return suiWallet
    } catch (error) {
      console.error('❌ Failed to create Sui wallet:', error)
      throw error
    }
}

export async function signMessage(message: string, walletId: string, privyClient: any) {

  const signature = await privyClient.walletApi.ethereum.signMessage({
    walletId,
    message
  })
  return signature
}