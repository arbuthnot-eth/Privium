// frontend/src/components/AuthorizeHandler.tsx
import { usePrivy, getAccessToken, useIdentityToken, useSessionSigners, useWallets } from '@privy-io/react-auth'
import { useSolanaWallets } from '@privy-io/react-auth/solana'
import { useState, useEffect } from 'react'
import LoginScreen from './LoginScreen'
import { useLogout } from './LogoutHandler'

interface AuthorizeHandlerProps {
  authParams: {
    client_id: string | null
    redirect_uri: string | null
    scope: string | null
    state: string | null
    response_type: string | null
    code_challenge: string | null
    code_challenge_method: string | null
    resource: string | null
  }
}

interface CompleteAuthResponse {
  redirectTo: string
}

// All visual styles are moved to `index.css` classes

export default function AuthorizeHandler({ authParams }: AuthorizeHandlerProps) {
  const { ready, authenticated, user } = usePrivy()
  if (!ready) return <div>Loading...</div>

  const { identityToken } = useIdentityToken()
  const { addSessionSigners } = useSessionSigners()
  const { wallets } = useWallets()
  const { wallets: solanaWallets } = useSolanaWallets()
  const { logout } = useLogout()

  const [processing, setProcessing] = useState(false)
  const [accessToken, setAccessToken] = useState<string | null>(null)

  useEffect(() => {
    if (ready && authenticated && !accessToken) {
      getAccessToken().then(token => {
        setAccessToken(token)
      })
    }
  }, [ready, authenticated, accessToken])

  const handleApprove = async () => {
    console.log('🟢 OAUTH: User clicked Grant Authorization')
    console.log('🔵 OAUTH: Starting handleApprove with accessToken:', !!accessToken, 'redirect_uri:', authParams.redirect_uri)
    if (!accessToken || !authParams.redirect_uri || processing) return
    setProcessing(true)

    // Add session signers to generate walletIds
    const allEmbeddedWallets = [
      ...wallets.filter((w) => w.walletClientType === 'privy'),
      ...solanaWallets.filter((w) => w.walletClientType === 'privy') as any
    ]
    if (!!allEmbeddedWallets) {
      for (const wallet of allEmbeddedWallets) {
        if ('getEthereumProvider' in wallet) {
          await wallet.getEthereumProvider()
        } else if ('getSolanaProvider' in wallet) {
          await wallet.getSolanaProvider()
        }
        await addSessionSigners({
          address: wallet.address,
          signers: []
        })
      }
    }

    // Complete authorization
    const backendUrl = '/complete-authorize'

    try {
      const response = await fetch(backendUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          client_id: authParams.client_id,
          redirect_uri: authParams.redirect_uri,
          scope: authParams.scope,
          state: authParams.state,
          response_type: authParams.response_type,
          code_challenge: authParams.code_challenge,
          code_challenge_method: authParams.code_challenge_method,
          resource: authParams.resource,
          accessToken: accessToken,
          idToken: identityToken,
        }),
      })

      if (!response.ok) {
        throw new Error('Failed to complete authorization')
      }

      const data: CompleteAuthResponse = await response.json()
      const redirectUrl = new URL(data.redirectTo)
      redirectUrl.searchParams.set('authorized', 'true')
      console.log('🔵 OAUTH: Received redirect response:', data)
      console.log('🔵 OAUTH: Redirecting to:', data.redirectTo)
      window.location.href = redirectUrl.toString()
      setTimeout(() => {
        window.close()
      }, 2400)
    } catch (err) {
      console.error('🔴 OAUTH ERROR: Authorization error:', err)
      setProcessing(false)
    }
  }

  const handleCancel = () => {
    console.log('🔴 OAUTH: User clicked Deny Access')
    if (authParams.redirect_uri) {
      const redirectUrl = new URL(authParams.redirect_uri)
      redirectUrl.searchParams.set('error', 'access_denied')
      if (authParams.state) redirectUrl.searchParams.set('state', authParams.state)
      console.log('🔴 OAUTH: Redirecting with access_denied error to:', redirectUrl.toString())
      window.location.href = redirectUrl.toString()
    }
    console.log('🔴 OAUTH: Attempting to close window...')
    window.close()
  }

  if (authParams.response_type !== 'code') {
    return <div>Unsupported response type. Only 'code' is supported.</div>
  }

  if (!authenticated) {
    return <LoginScreen />
  }

  if (processing) return (
    <div className="modal-overlay">
      <div className="card processing-card">
        <h3>Processing...</h3>
        <p className="mt-2">Completing authorization</p>
      </div>
    </div>
  )

  return (
    <div className="modal-overlay">
      <div className="modal">
        <div className="modal-header">
          <h2 className="modal-title">Authorize Access</h2>
          <p className="modal-subtitle">An MCP Client wants to access your {SERVER_NAME} MCP Server</p>
        </div>

        <div className="info-box">
          <div className="info-section">
            <div className="overline">PERMISSIONS</div>
            <div>• Access to {SERVER_NAME} MCP Server tools and resources</div>
          </div>

          <div className="info-section">
            <div className="overline">ACCOUNT</div>
            <div className="row-between">
              <span>
                {user?.email?.address || user?.phone?.number || user?.wallet?.address?.slice(0, 5) + '...' + user?.wallet?.address?.slice(-5) || 'Connected'}
              </span>
              <button className="btn btn-ghost" onClick={logout}>Switch Account</button>
            </div>
          </div>
        </div>

        <div className="btn-group" style={{ display: 'flex' }}>
          <button className="btn btn-secondary" style={{ flex: 1 }} onClick={handleCancel}>Cancel</button>
          <button className="btn btn-primary" style={{ flex: 2 }} onClick={handleApprove}>Grant Authorization</button>
        </div>

        <p className="caption">This allows the MCP Client to connect to your {SERVER_NAME} MCP Server using OAuth 2.1 with PKCE</p>
      </div>
    </div>
  )
}