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

    try {
      // Check if user already has a Sui wallet
      const hasSuiWallet = user.linkedAccounts?.some(
        (account: any) => account.type === 'wallet' && account.chainType === 'sui'
      ) || (user.wallet?.chainType === 'sui')

      if (hasSuiWallet) {
        console.log('✅ User already has a Sui wallet')
        return
      }

      console.log('🔄 Creating Sui wallet for user:', user.id)
      
      // Create a new Sui wallet using Privy's extended-chains API
      const newWallet = await createWallet({
        chainType: 'sui'
      })

      console.log('✅ Successfully created Sui wallet:', newWallet)
      return newWallet
    } catch (error) {
      console.error('❌ Failed to create Sui wallet:', error)
      throw error
    }
  }, [createWallet])

  return {
    createSuiWalletIfNeeded
  }
}
