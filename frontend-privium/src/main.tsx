import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { PrivyProvider } from '@privy-io/react-auth'
import './index.css'
import App from './App.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <PrivyProvider
      appId={import.meta.env.VITE_PRIVY_APP_ID}
      config={{
        customAuth: {
          getCustomAccessToken: async () => {
            // This function will be called by Privy to get the custom access token
            // We will store the token in localStorage after the OAuth flow
            return localStorage.getItem('privy_access_token') || undefined;
          },
          isLoading: false, // Added required isLoading property
        },
        appearance: {
          theme: 'light',
          accentColor: '#676FFF',
        },
      }}
    >
      <App />
    </PrivyProvider>
  </StrictMode>,
)
