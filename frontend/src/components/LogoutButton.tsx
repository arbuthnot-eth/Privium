// frontend/src/components/LogoutButton.tsx
import { useLogout } from '@privy-io/react-auth'
import { useIdentityToken } from '@privy-io/react-auth'
import { getAccessToken } from '@privy-io/react-auth'
import { generateBearer } from './utils/generateBearer'

export default function LogoutButton() {
  const { logout } = useLogout({
    onSuccess: () => {
      console.log('🔴 LOGOUT: User successfully logged out')
    }
  });
  const { identityToken } = useIdentityToken()

  const handleLogout = async () => {
    try {
      // Always attempt to revoke all tokens
      let token = sessionStorage.getItem('bearer_token')
      
      if (!token) {
        // Generate a temporary bearer token if none exists
        const accessToken = await getAccessToken()
        if (accessToken && identityToken) {
          const tempToken = await generateBearer(accessToken, identityToken, true)
          if (tempToken) {
            token = tempToken
            console.log('🔴 LOGOUT: Generated temporary token for revocation')
          } else {
            console.warn('🔴 LOGOUT: Failed to generate temporary token; skipping revocation')
          }
        } else {
          console.warn('🔴 LOGOUT: Access or identity token not available; skipping revocation')
        }
      }

      if (token) {
        await fetch('/revoke', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ 
            token,
            revoke_all: 'true'  // Revoke all tokens for this user
          }),
        });
        sessionStorage.removeItem('bearer_token')
        console.log('🔴 LOGOUT: Revoked all tokens for user')
      } else {
        console.log('🔴 LOGOUT: No bearer token found or generated; skipping revocation')
      }
      
      // Clear session storage flags
      sessionStorage.removeItem('hasAuthorized')
      
      // Proceed with Privy logout (clears client-side session)
      logout();

      setTimeout(() => {
        window.location.reload()
      }, 50)
    } catch (error) {
      console.error('Logout failed:', error)
    }
  }

  return <button onClick={handleLogout}>Disconnect</button>
}