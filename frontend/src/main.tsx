import React, { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { PrivyProvider } from '@privy-io/react-auth'
import './index.css'
import App from './App.tsx'

// Get Privy App ID from injected global variable
declare global {
  interface Window {
    PRIVY_APP_ID?: string;
  }
}

// The backend injects PRIVY_APP_ID from Cloudflare env vars when serving /authorize
const privyAppId = window.PRIVY_APP_ID || 'cmbey93ef00v8js0n8vdxwyv4';

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
          createOnLogin: 'users-without-wallets',
        },
      }}
    >
      <App />
    </PrivyProvider>
  </StrictMode>,
)