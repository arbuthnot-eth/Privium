// src/utils/walletUtils.ts
import { useCreateWallet } from '@privy-io/react-auth/extended-chains'
import { useRef } from 'react'

export const useSuiWalletCreation = () => {
  const { createWallet } = useCreateWallet()
  const creatingWalletRef = useRef(false)

  const createSuiWalletIfNeeded = async (user: any) => {
    // Prevent multiple simultaneous wallet creation attempts
    if (creatingWalletRef.current) {
      console.log('⏳ Sui wallet creation already in progress...')
      return null
    }

    try {
      creatingWalletRef.current = true
      
      console.log('🔧 POST-LOGIN: Starting Sui wallet creation process')
      console.log('🔍 Checking for Sui wallet in linked accounts:', user.linkedAccounts)
      
      // Debug: Show details of each account
      user.linkedAccounts.forEach((account: any, index: number) => {
        console.log(`Account ${index + 1}:`, {
          type: account.type,
          chainType: account.chainType,
          address: account.address ? `${account.address.slice(0, 8)}...` : 'N/A'
        })
      })

      const hasSuiWallet = user.linkedAccounts.find(
        (account: any) =>
          account.type === 'wallet' && account.chainType === 'sui'
      )

      console.log('❓ Does user already have a Sui wallet?', !!hasSuiWallet)

      if (!hasSuiWallet) {
        console.log('🚀 Attempting to create a Sui wallet now...')
        try {
          const newWallet = await createWallet({ chainType: 'sui' })
          console.log('✅ Successfully created and linked Sui wallet:', newWallet)
          return newWallet
        } catch (walletError: any) {
          console.warn('⚠️ Sui wallet creation failed, continuing without Sui wallet:', walletError.message)
          // Don't throw error - allow login to continue without Sui wallet
          // This handles the case where Privy doesn't support Sui embedded wallets
          if (walletError.message?.includes('invalid') || walletError.message?.includes('Address')) {
            console.log('💡 This appears to be related to Sui not being supported in Privy embedded wallets')
          }
          return null
        }
      } else {
        console.log('✅ User already has a Sui wallet - no need to create one')
        return null
      }
    } catch (error) {
      console.error('❌ An error occurred during wallet creation process:', error)
      // Don't throw error - allow login to continue
      console.log('💡 Continuing with login despite wallet creation error')
      return null
    } finally {
      creatingWalletRef.current = false
    }
  }

  return { createSuiWalletIfNeeded }
} 