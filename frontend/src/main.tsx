import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'
import { PrivyProvider } from '@privy-io/react-auth'
import { toSolanaWalletConnectors } from '@privy-io/react-auth/solana'
import { Buffer } from 'buffer'

// Configure the Buffer polyfill for global use
window.Buffer = Buffer

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <PrivyProvider
      appId={import.meta.env.VITE_PRIVY_APP_ID}
      config={{
        appearance: {
          theme: 'dark',
          accentColor: '#EFBF04',
          walletChainType: 'ethereum-and-solana',
          walletList: ['detected_ethereum_wallets', 'detected_solana_wallets'],
        },
        loginMethods: ['email', 'wallet', 'google', 'github'],
        embeddedWallets: {
          ethereum: {
            createOnLogin: 'all-users'
          },
          solana: {
            createOnLogin: 'all-users'
          }
        },
        externalWallets: {
          solana: {
            connectors: toSolanaWalletConnectors(),
          },
        },
      }}
    >
      <App />
    </PrivyProvider>
  </React.StrictMode>
)