import { usePrivy, useLogout, useLogin, getAccessToken, useIdentityToken } from '@privy-io/react-auth'
import { useState, useCallback, useEffect } from 'react'

function LogoutButton() {
  const { logout } = useLogout({
    onSuccess: () => {
      console.log('🔴 LOGOUT: User successfully logged out')
    }
  })
  return <button onClick={logout}>Log out</button>
}

function LoginScreen() {
  const { login } = useLogin({
    onComplete: () => {
      console.log('🟢 LOGIN: User successfully logged in (LoginScreen)')
    }
  })
  return (
    <div style={{ textAlign: 'center', padding: '2rem' }}>
      <h1>{APP_NAME} MCP Server</h1>
      <p>Please sign in to continue</p>
      <button onClick={login} style={{ padding: '12px 24px', fontSize: '16px', cursor: 'pointer' }}>
        Sign In
      </button>
    </div>
  )
}

function CopyToClipboardButton({ textToCopy, buttonText = 'Copy', highlightTargetId }: { textToCopy: string; buttonText?: string; highlightTargetId?: string }) {
  const [isCopied, setIsCopied] = useState(false)
  const [isHovered, setIsHovered] = useState(false)
  
  const handleCopyClick = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(textToCopy)
      setIsCopied(true)
      setTimeout(() => setIsCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy text: ', err)
    }
  }, [textToCopy])
  
  const handleMouseEnter = () => {
    setIsHovered(true)
    if (highlightTargetId) {
      const target = document.getElementById(highlightTargetId)
      if (target) {
        target.style.backgroundColor = 'rgba(255, 255, 255, 0.3)'
        target.style.color = '#ffffff'
        target.style.padding = '2px 4px'
        target.style.borderRadius = '3px'
        target.style.boxShadow = '0 0 5px rgba(255, 255, 255, 0.5)'
      }
    }
  }
  const handleMouseLeave = () => {
    setIsHovered(false)
    if (highlightTargetId) {
      const target = document.getElementById(highlightTargetId)
      if (target) {
        target.style.backgroundColor = ''
        target.style.color = ''
        target.style.padding = ''
        target.style.borderRadius = ''
        target.style.boxShadow = ''
      }
    }
  }
  
  return (
    <button
      onClick={handleCopyClick}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      style={{
        padding: '5px 10px',
        fontSize: '14px',
        cursor: 'pointer',
        backgroundColor: isHovered ? '#0056b3' : '#007bff',
        color: 'white',
        border: 'none',
        borderRadius: '4px'
      }}
    >
      {isCopied ? 'Copied!' : buttonText}
    </button>
  )
}

function BearerTokenGenerator() {
  const { authenticated, getAccessToken: getPrivyAccessToken, user } = usePrivy()
  const { identityToken } = useIdentityToken()
  const [isGenerating, setIsGenerating] = useState(false)
  const [bearerTokenInfo, setBearerTokenInfo] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)
  const [clientId, setClientId] = useState<string | null>(null)
  const [clientSecret, setClientSecret] = useState<string | null>(null)

  // Generate PKCE parameters
  const generatePKCE = () => {
    const codeVerifier = Array.from(crypto.getRandomValues(new Uint8Array(32)))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
    
    const encoder = new TextEncoder()
    const data = encoder.encode(codeVerifier)
    return crypto.subtle.digest('SHA-256', data).then(hash => {
      const hashArray = Array.from(new Uint8Array(hash))
      const base64Digest = btoa(String.fromCharCode(...hashArray))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '')
      return { codeVerifier, codeChallenge: base64Digest }
    })
  }

  // Register client with the server
  const registerClient = async () => {
    const response = await fetch('/reg', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        redirect_uris: [`${window.location.origin}/authorize`]
      }),
    })
    
    if (!response.ok) {
      const errorText = await response.text()
      throw new Error(`Failed to register client: ${response.status} - ${errorText}`)
    }
    
    const data: RegisterClientResponse = await response.json()
    return { clientId: data.client_id, clientSecret: data.client_secret }
  }

  // Exchange authorization code for tokens
  const exchangeToken = async (authorizationCode: string, codeVerifier: string, clientIdParam: string) => {
    console.log('exchangeToken called with:', { authorizationCode, codeVerifier, clientIdParam })
    if (!clientIdParam) {
      throw new Error('Client ID is required for token exchange')
    }
    if (!authorizationCode) {
      throw new Error('Authorization code is required for token exchange')
    }
    if (!codeVerifier) {
      throw new Error('Code verifier is required for token exchange')
    }
    
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code: authorizationCode,
      redirect_uri: `${window.location.origin}/authorize`,
      client_id: clientIdParam,
      code_verifier: codeVerifier,
    })

    console.log('Sending token exchange request with params:', Object.fromEntries(params))
    const response = await fetch('/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    })
    console.log('Token exchange response status:', response.status)

    if (!response.ok) {
      const errorText = await response.text()
      console.error('Token exchange failed with response:', errorText)
      throw new Error(`Failed to exchange token: ${response.status} - ${errorText}`)
    }

    const responseData: ExchangeTokenResponse = await response.json()
    console.log('Token exchange successful, received data:', responseData)
    return responseData
  }

  const generateBearerToken = async () => {
    if (!authenticated) {
      setError('You must be logged in to generate a bearer token')
      return
    }

    if (!identityToken) {
      setError('Identity token not available')
      return
    }

    setIsGenerating(true)
    setError(null)
    setBearerTokenInfo(null)
    setClientId(null)
    setClientSecret(null)

    try {
      // Step 1: Register client
      console.log('Step 1: Registering client...')
      const { clientId: newClientId, clientSecret: newClientSecret } = await registerClient()
      if (!newClientId) {
        throw new Error('Failed to register client - no client ID returned')
      }
      setClientId(newClientId)
      setClientSecret(newClientSecret)
      console.log('Client registered:', newClientId)

      // Step 2: Generate PKCE parameters
      console.log('Step 2: Generating PKCE parameters...')
      const { codeVerifier, codeChallenge } = await generatePKCE()
      if (!codeVerifier || !codeChallenge) {
        throw new Error('Failed to generate PKCE parameters')
      }
      console.log('PKCE generated')

      // Step 3: Get Privy tokens
      console.log('Step 3: Getting Privy tokens...')
      const accessToken = await getPrivyAccessToken()
      if (!accessToken) {
        throw new Error('Failed to get access token from Privy')
      }
      console.log('Privy tokens obtained')

      // Step 4: Complete authorization with Privy tokens
      console.log('Step 4: Completing authorization...')
      const completeAuthResponse = await fetch('/complete-authorize', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          client_id: newClientId,
          redirect_uri: `${window.location.origin}/authorize`,
          scope: 'mcp',
          response_type: 'code',
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          resource: `${window.location.origin}/mcp`,
          accessToken: accessToken,
          idToken: identityToken,
        }),
      })

      if (!completeAuthResponse.ok) {
        const errorText = await completeAuthResponse.text()
        throw new Error(`Failed to complete authorization: ${completeAuthResponse.status} - ${errorText}`)
      }

      const authData: CompleteAuthResponse = await completeAuthResponse.json()
      console.log('Authorization completed, redirecting to:', authData.redirectTo)

      // Extract authorization code from redirect URL
      const redirectUrl = new URL(authData.redirectTo)
      const authorizationCode = redirectUrl.searchParams.get('code')
      
      if (!authorizationCode) {
        throw new Error('Authorization code not found in redirect URL')
      }

      console.log('Authorization code obtained:', authorizationCode)
      console.log('Client ID for token exchange:', newClientId)
      console.log('Code verifier for token exchange:', codeVerifier)

      // Step 5: Exchange authorization code for bearer token
      console.log('Step 5: Exchanging authorization code for bearer token...')
      const tokenData = await exchangeToken(authorizationCode, codeVerifier, newClientId)
      console.log('Token exchange completed')

      // Step 6: Format the response as requested
      const baseUrl = window.location.origin
      const tokenInfo = {
        [APP_NAME]: {
          type: "streamable-http",
          url: `${baseUrl}/mcp`,
          headers: {
            authorization: `Bearer ${tokenData.access_token}`
          }
        }
      }
      
      setBearerTokenInfo(tokenInfo)
      console.log('Bearer token generation completed successfully')
    } catch (err) {
      console.error('Error generating bearer token:', err)
      setError(err instanceof Error ? err.message : 'Failed to generate bearer token')
    } finally {
      setIsGenerating(false)
    }
  }

  return (
    <div style={{
      backgroundColor: '#2a2a2a',
      border: '1px solid #404040',
      borderRadius: '8px',
      padding: '20px',
      marginTop: '20px',
      textAlign: 'center',
      color: '#ffffff'
    }}>
      <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', marginBottom: '20px' }}>
        <button
          onClick={generateBearerToken}
          disabled={isGenerating || !authenticated}
          style={{
            padding: '10px 20px',
            fontSize: '16px',
            cursor: isGenerating || !authenticated ? 'not-allowed' : 'pointer',
            backgroundColor: isGenerating || !authenticated ? '#ccc' : '#007bff',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            opacity: isGenerating || !authenticated ? 0.6 : 1
          }}
        >
          {isGenerating ? 'Generating...' : 'Generate Bearer Token'}
        </button>
        <LogoutButton />
      </div>

      {error && (
        <div style={{
          color: '#ff6b6b',
          marginTop: '10px',
          padding: '10px',
          backgroundColor: '#3a1a1a',
          borderRadius: '4px',
          border: '1px solid #ff6b6b'
        }}>
          Error: {error}
        </div>
      )}

      {bearerTokenInfo && (
        <div style={{
          marginTop: '20px',
          padding: '15px',
          backgroundColor: '#1a2a1a',
          borderRadius: '4px',
          textAlign: 'left',
          border: '1px solid #4caf50'
        }}>
          <h4 style={{ color: '#4caf50', margin: '0 0 10px 0' }}>Bearer Token Information:</h4>
          <div style={{
            backgroundColor: '#0a1a0a',
            padding: '10px',
            borderRadius: '4px',
            overflowX: 'auto',
            fontSize: '14px',
            color: '#aaffaa',
            margin: '10px 0',
            fontFamily: 'monospace',
            whiteSpace: 'pre-wrap'
          }}>
            {bearerTokenInfo && (
              <>
                <div>{'{'}</div>
                <div>&nbsp;&nbsp;"{APP_NAME}": {'{'}</div>
                <div>&nbsp;&nbsp;&nbsp;&nbsp;"type": "streamable-http",</div>
                <div>&nbsp;&nbsp;&nbsp;&nbsp;"url": "{bearerTokenInfo[APP_NAME].url}",</div>
                <div>&nbsp;&nbsp;&nbsp;&nbsp;"headers": {'{'}</div>
                <div>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"authorization": "Bearer <span id="bearer-token-value">{bearerTokenInfo[APP_NAME].headers.authorization.replace('Bearer ', '')}</span>"</div>
                <div>&nbsp;&nbsp;&nbsp;&nbsp;{'}'}</div>
                <div>&nbsp;&nbsp;{'}'}</div>
                <div>{'}'}</div>
              </>
            )}
          </div>
          <div style={{ display: 'flex', gap: '10px', marginTop: '10px' }}>
            <CopyToClipboardButton textToCopy={JSON.stringify(bearerTokenInfo, null, 2)} buttonText="Copy JSON" />
            <CopyToClipboardButton
              textToCopy={bearerTokenInfo[APP_NAME].headers.authorization.replace('Bearer ', '')}
              buttonText="Copy Token"
              highlightTargetId="bearer-token-value"
            />
          </div>
        </div>
      )}
    </div>
  )
}

function AuthorizeHandler({ authParams }: { authParams: { client_id: string | null; redirect_uri: string | null; scope: string | null; state: string | null; response_type: string | null; code_challenge: string | null; code_challenge_method: string | null; resource: string | null } }) {
  const { ready, authenticated, user } = usePrivy()
  const { identityToken } = useIdentityToken()
  const { login } = useLogin({
    onComplete: () => {
      console.log('🟢 OAUTH LOGIN: User successfully logged in for authorization')
    },
  })
  const { logout } = useLogout({
    onSuccess: () => {
      console.log('🔴 OAUTH LOGOUT: User logged out to switch accounts')
    }
  })
  const [processing, setProcessing] = useState(false)
  const [accessToken, setAccessToken] = useState<string | null>(null)

  useEffect(() => {
    console.log('🔵 OAUTH AUTH STATE: ready:', ready, 'authenticated:', authenticated)
    if (ready && authenticated) {
      console.log('🔵 OAUTH AUTH STATE: Getting access token...')
      getAccessToken().then(token => {
        console.log('🔵 OAUTH AUTH STATE: Received access token:', !!token)
        setAccessToken(token)
      })
    }
  }, [ready, authenticated])

  const handleApprove = () => {
    console.log('🟢 OAUTH: User clicked Grant Authorization')
    console.log('🔵 OAUTH: Starting handleApprove with accessToken:', !!accessToken, 'redirect_uri:', authParams.redirect_uri)
    if (!accessToken || !authParams.redirect_uri || processing) return
    setProcessing(true)
    const backendUrl = '/complete-authorize'
    console.log('🔵 OAUTH: Calling complete-authorize endpoint')
    fetch(backendUrl, {
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
      .then((res) => {
        if (!res.ok) throw new Error('Failed to complete authorization')
        return res.json() as Promise<CompleteAuthResponse>
      })
      .then((data) => {
        console.log('🔵 OAUTH: Received redirect response:', data)
        console.log('🔵 OAUTH: Redirecting to:', data.redirectTo)
        window.location.href = data.redirectTo
        setTimeout(() => {
          window.close()
        }, 2400)
      })
      .catch((err) => {
        console.error('🔴 OAUTH ERROR: Authorization error:', err)
        setProcessing(false)
      })
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

  if (!ready) return <div>Loading...</div>

  if (authParams.response_type !== 'code') {
    return <div>Unsupported response type. Only 'code' is supported.</div>
  }

  if (!authenticated) {
    return (
      <div style={{ textAlign: 'center', padding: '2rem' }}>
        <h1>Authorize Access</h1>
        <p>Please sign in to grant access to the application.</p>
        <button onClick={login} style={{ padding: '12px 24px', fontSize: '16px', cursor: 'pointer' }}>
          Sign In
        </button>
      </div>
    )
  }

  if (processing) return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'color-mix(in srgb, var(--bg-color) 80%, transparent)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000
    }}>
      <div style={{
        backgroundColor: 'var(--card-bg)',
        border: '1px solid var(--border-color)',
        borderRadius: '12px',
        padding: '24px',
        textAlign: 'center',
        color: 'var(--text-color)',
        maxWidth: '300px'
      }}>
        <h3 style={{ margin: '0 0 12px 0', fontSize: '18px' }}>Processing...</h3>
        <p style={{ margin: 0, fontSize: '14px', opacity: 0.8 }}>
          Completing authorization
        </p>
      </div>
    </div>
  )

  const authDialogStyle = `
    :root {
      --bg-color: light-dark(#ffffff, #1a1a1a)
      --card-bg: light-dark(#ffffff, #2a2a2a)
      --text-color: light-dark(#1a1a1a, #ffffff)
      --text-secondary: light-dark(#666666, #999999)
      --border-color: light-dark(#e1e5e9, #404040)
      --button-primary: light-dark(#007bff, #0d6efd)
      --button-primary-hover: light-dark(#0056b3, #0b5ed7)
      --button-secondary: light-dark(#6c757d, #6c757d)
      --button-secondary-hover: light-dark(#545b62, #5a6268)
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --bg-color: #1a1a1a
        --card-bg: #2a2a2a
        --text-color: #ffffff
        --text-secondary: #999999
        --border-color: #404040
        --button-primary: #0d6efd
        --button-primary-hover: #0b5ed7
      }
    }
  `

  return (
    <>
      <style>{authDialogStyle}</style>
      <div style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'color-mix(in srgb, var(--bg-color) 80%, transparent)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000
      }}>
        <div style={{
          backgroundColor: 'var(--card-bg)',
          border: '1px solid var(--border-color)',
          borderRadius: '12px',
          padding: '24px',
          width: '400px',
          maxWidth: '90vw',
          color: 'var(--text-color)',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3)'
        }}>
          <div style={{ textAlign: 'center', marginBottom: '20px' }}>
            <h2 style={{ margin: '0 0 8px 0', fontSize: '20px', fontWeight: '600' }}>
              Authorize Access
            </h2>
            <p style={{ margin: 0, fontSize: '14px', color: 'var(--text-secondary)' }}>
              An MCP Client wants to access your {APP_NAME} MCP Server
            </p>
          </div>

          <div style={{
            backgroundColor: 'color-mix(in srgb, var(--border-color) 30%, transparent)',
            borderRadius: '8px',
            padding: '16px',
            marginBottom: '20px'
          }}>
            <div style={{ marginBottom: '12px' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                PERMISSIONS
              </div>
              <div style={{ fontSize: '14px' }}>
                • Access to {APP_NAME} MCP Server tools and resources
              </div>
            </div>
            
            <div style={{ marginBottom: '12px' }}>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                ACCOUNT
              </div>
              <div style={{ fontSize: '14px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span>
                  {user?.email?.address || user?.phone?.number || user?.wallet?.address?.slice(0, 8) + '...' || 'Connected'}
                </span>
                <button
                  onClick={logout}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--text-secondary)',
                    cursor: 'pointer',
                    fontSize: '12px',
                    textDecoration: 'underline',
                    padding: 0
                  }}
                >
                  Switch Account
                </button>
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '12px' }}>
            <button 
              onClick={handleCancel} 
              style={{ 
                flex: 1,
                padding: '12px',
                fontSize: '14px',
                cursor: 'pointer',
                backgroundColor: 'var(--button-secondary)',
                color: 'white',
                border: 'none',
                borderRadius: '8px',
                transition: 'background-color 0.2s'
              }}
              onMouseOver={(e) => e.currentTarget.style.backgroundColor = 'var(--button-secondary-hover)'}
              onMouseOut={(e) => e.currentTarget.style.backgroundColor = 'var(--button-secondary)'}
            >
              Cancel
            </button>
            <button 
              onClick={handleApprove} 
              style={{ 
                flex: 2,
                padding: '12px',
                fontSize: '14px',
                cursor: 'pointer',
                backgroundColor: 'var(--button-primary)',
                color: 'white',
                border: 'none',
                borderRadius: '8px',
                transition: 'background-color 0.2s',
                fontWeight: '500'
              }}
              onMouseOver={(e) => e.currentTarget.style.backgroundColor = 'var(--button-primary-hover)'}
              onMouseOut={(e) => e.currentTarget.style.backgroundColor = 'var(--button-primary)'}
            >
              Grant Authorization
            </button>
          </div>

          <p style={{ 
            fontSize: '11px', 
            color: 'var(--text-secondary)', 
            textAlign: 'center',
            margin: '16px 0 0 0',
            lineHeight: '1.4'
          }}>
            This allows the MCP Client to connect to your {APP_NAME} MCP Server using OAuth 2.1 with PKCE
          </p>
        </div>
      </div>
    </>
  )
}

export default function App() {
  const { ready, authenticated, user } = usePrivy()
  const [isAuthorizeMode, setIsAuthorizeMode] = useState(false)
  const [authParams, setAuthParams] = useState<{ client_id: string | null; redirect_uri: string | null; scope: string | null; state: string | null; response_type: string | null; code_challenge: string | null; code_challenge_method: string | null; resource: string | null } | null>(null)

  useEffect(() => {
    if (window.location.pathname === '/authorize') {
      setIsAuthorizeMode(true)
      const params = new URLSearchParams(window.location.search)
      setAuthParams({
        client_id: params.get('client_id'),
        redirect_uri: params.get('redirect_uri'),
        scope: params.get('scope'),
        state: params.get('state'),
        response_type: params.get('response_type'),
        code_challenge: params.get('code_challenge'),
        code_challenge_method: params.get('code_challenge_method'),
        resource: params.get('resource') || window.location.origin + '/mcp',
      })
    }
  }, [])
  
  if (!ready) {
      return <>Loading</>
  }
  
  if (isAuthorizeMode && authParams) {
    return <AuthorizeHandler authParams={authParams} />
  }
  
  if (ready && !authenticated) {
      return <LoginScreen />
  }
  
  if (ready && authenticated) {
      return (
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          <h1>{APP_NAME} MCP Server</h1>
          <p>User {user?.id} is logged in.</p>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginTop: '1rem' }}>
          </div>
          <div style={{ marginTop: '1rem' }}>
            <BearerTokenGenerator />
          </div>
        </div>
      )
  }
  return null
}