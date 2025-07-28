// src/utils/walletUtils.ts
import { useCreateWallet } from '@privy-io/react-auth/extended-chains'
import { useCallback } from 'react'


export const useSuiWalletCreation = () => {
  const { createWallet } = useCreateWallet()

  const createSuiWalletIfNeeded = useCallback(async (user: any) => {
    if (!user) {
      console.log('❌ No user provided for Sui wallet creation')
      return
    }

    let suiWallet = null
    try {
      // Check if user already has a Sui wallet
      suiWallet = user.linkedAccounts.find(
        (account: any) => account.type === 'wallet' && account.chainType === 'sui' && account.walletClientType === 'privy'
      )
        
      if (!suiWallet) { 
        // Create a new Sui wallet using Privy's extended-chains API
          suiWallet = await createWallet({
          chainType: 'sui'
        })
      }
      
      return suiWallet
    } catch (error) {
      console.error('❌ Failed to create Sui wallet:', error)
      throw error
    }
  }, [createWallet])

  return {
    createSuiWalletIfNeeded
  }
}
