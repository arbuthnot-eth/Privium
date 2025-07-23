import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import React from 'react';
import { PrivyProvider } from '@privy-io/react-auth'
import './index.css'
import App from './App.tsx'

// Get Privy App ID from injected global variable
declare global {
  interface Window {
    PRIVY_APP_ID: string;
  }
}

const privyAppId = (typeof window !== 'undefined' && window.PRIVY_APP_ID) || import.meta.env.VITE_PRIVY_APP_ID;

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