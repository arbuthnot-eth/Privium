// frontend/src/components/LogoutHandler.tsx
import { usePrivy, useSessionSigners, type WalletWithMetadata } from '@privy-io/react-auth'

// Hook for components that need logout functionality
export const useLogout = () => {
  const { logout: privyLogout, user: privyUser } = usePrivy()
  const { removeSessionSigners } = useSessionSigners()
  
  const logout = async () => {
    try {
      const token = sessionStorage.getItem('bearer_token')

      // Remove session signers for all delegated wallets
      if (privyUser) {
        const delegatedWallet = privyUser.linkedAccounts.filter(
          (account): account is WalletWithMetadata => account.type === 'wallet' && account.delegated
        )
        if (delegatedWallet.length > 0) {
          for (const wallet of delegatedWallet) {
            await removeSessionSigners({address: wallet.address})
      }
    }}

      if (token) {
        await fetch('/revoke', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            token,
            revoke_all: 'true'  // Revoke all tokens for this user
          }),
        })
        sessionStorage.removeItem('bearer_token')
        console.log('🔴 LOGOUT: Revoked all tokens for user')
      } else {
        console.log('🔴 LOGOUT: No bearer token found or generated, skipping revocation')
      }

      // Clear session storage flags
      sessionStorage.removeItem('hasAuthorized')
      
      // Use Privy's logout to completely sign out the user
      await privyLogout()
    } catch (error) {
      console.error('Logout failed:', error)
    }
  }
  
  return { logout }
}