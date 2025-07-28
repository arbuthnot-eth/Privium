import { useLogout } from '@privy-io/react-auth'

export default function LogoutButton() {
  const { logout } = useLogout({
    onSuccess: () => {
      console.log('🔴 LOGOUT: User successfully logged out')
    }
  });

  const handleLogout = async () => {
    try {
      // Optional: Revoke server-side token if stored
      const token = localStorage.getItem('bearer_token')
      if (token) {
        await fetch('/revoke', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ token }),
        });
        localStorage.removeItem('bearer_token')
      }
      logout();
    } catch (error) {
      console.error('Logout failed:', error)
    }
  }

  return <button onClick={handleLogout}>Log out</button>
}