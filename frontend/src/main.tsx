import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { PrivyProvider } from '@privy-io/react-auth'
import './index.css'
import App from './App'

// Use the Privy App ID injected by the backend, fallback to Vite env var for development
const privyAppId = (window as any).PRIVY_APP_ID || import.meta.env.VITE_PRIVY_APP_ID

if (!privyAppId) {
  console.error('❌ PRIVY_APP_ID not found. Make sure it\'s injected by the backend or set VITE_PRIVY_APP_ID for development.')
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <PrivyProvider
      appId={privyAppId}
      config={{
        appearance: {
          theme: 'dark',
          accentColor: '#676FFF',
        },
        loginMethods: ['email', 'wallet', 'google', 'github'],
        embeddedWallets: {
          ethereum: {
            createOnLogin: 'all-users',
          },
          solana: {
            createOnLogin: 'all-users',
          }
        },
      }}
    >
      <App />
    </PrivyProvider>
  </StrictMode>,
)