import { useLogout } from '@privy-io/react-auth'

export default function LogoutButton() {
  const { logout } = useLogout({
    onSuccess: () => {
      console.log('🔴 LOGOUT: User successfully logged out')
    }
  });

  const handleLogout = async () => {
    try {
      // Optional: Revoke all server-side tokens if a bearer token is stored
      const token = sessionStorage.getItem('bearer_token')
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
        console.log('🔴 LOGOUT: No bearer token found; skipping revocation')
      }
      
      // Proceed with Privy logout (clears client-side session)
      logout();
    } catch (error) {
      console.error('Logout failed:', error)
    }
  }

  return <button onClick={handleLogout}>Disconnect</button>
}