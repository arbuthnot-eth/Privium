import { usePrivy } from '@privy-io/react-auth'
import { useState, useEffect } from 'react'
import LoginScreen from './components/LoginScreen'
import BearerTokenGenerator from './components/BearerTokenGenerator'
import AuthorizeHandler from './components/AuthorizeHandler'

/**
 * Main application component that handles authentication routing
 * and displays the appropriate UI based on the user's state.
 */
export default function App() {
  const { ready, authenticated, user } = usePrivy()

  const [isAuthorizeMode, setIsAuthorizeMode] = useState(false)
  const [authParams, setAuthParams] = useState<{
    client_id: string | null
    redirect_uri: string | null
    scope: string | null
    state: string | null
    response_type: string | null
    code_challenge: string | null
    code_challenge_method: string | null
    resource: string | null
  } | null>(null)

  const [hasAuthorized, setHasAuthorized] = useState(false)

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const authorizedParam = params.get('authorized')

    // Detect successful authorization redirect and set flag
    if (authorizedParam === 'true' && !hasAuthorized) {
      setHasAuthorized(true)
      // Clean up URL by removing query param (prevents re-trigger on refresh)
      const cleanUrl = window.location.origin + window.location.pathname
      window.history.replaceState({}, '', cleanUrl)
      return
    }

    if (window.location.pathname === '/authorize') {
      setIsAuthorizeMode(true)
      const parsedAuthParams = {
        client_id: params.get('client_id'),
        redirect_uri: params.get('redirect_uri'),
        scope: params.get('scope'),
        state: params.get('state'),
        response_type: params.get('response_type'),
        code_challenge: params.get('code_challenge'),
        code_challenge_method: params.get('code_challenge_method'),
        resource: params.get('resource') || window.location.origin + '/mcp',
      }
      setAuthParams(parsedAuthParams)
      return
    }

    const authorized = sessionStorage.getItem('hasAuthorized')
    if (authorized) {
      setHasAuthorized(true)
    }
  }, []) // Empty dependency array to run only on mount


  useEffect(() => {
    if (authenticated && !hasAuthorized && !isAuthorizeMode) {
      const generateInternalParams = async () => {
        try {
          const regResponse = await fetch('/reg', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ redirect_uris: [window.location.origin] }),
          })
          const data = await regResponse.json() as RegisterClientResponse
          const client_id = data.client_id
          
          // Optional: Generate PKCE (for full compliance)
          const codeVerifier = Array.from(crypto.getRandomValues(new Uint8Array(32)))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('')
          const encoder = new TextEncoder()
          const hashed = await crypto.subtle.digest('SHA-256', encoder.encode(codeVerifier))
          const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(hashed)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '')

          const internalParams = new URLSearchParams({
            client_id: client_id || 'internal-client',
            redirect_uri: window.location.origin,
            scope: 'mcp',
            response_type: 'code',
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
            resource: window.location.origin + '/mcp',
          })

          window.location.href = `/authorize?${internalParams.toString()}`
        } catch (error) {
          console.error('Failed to register internal client:', error)
          // Fallback to basic params if registration fails
          const fallbackParams = new URLSearchParams({
            client_id: 'internal-client',
            redirect_uri: window.location.origin,
            scope: 'mcp',
            response_type: 'code',
            code_challenge: 'placeholder-challenge',
            code_challenge_method: 'S256',
            resource: window.location.origin + '/mcp',
          })
          window.location.href = `/authorize?${fallbackParams.toString()}`
        }
      }

      generateInternalParams()
    }
  }, [authenticated, hasAuthorized, isAuthorizeMode])

  if (!ready) {
    return (
      <div className="container-center">
        <div className="page app-container stack text-center">
          <h1 className="page-title">{SERVER_NAME} MCP Server</h1>
          <p className="page-subtitle">Loading authentication...</p>
        </div>
      </div>
    )
  }

  if (isAuthorizeMode && authParams) {
    return <AuthorizeHandler authParams={authParams} />
  }

  if (!authenticated) {
    return <LoginScreen />
  }

  if (authenticated && !hasAuthorized && !isAuthorizeMode) {
    return (
      <div className="container-center">
        <div className="page app-container stack text-center">
          <h1 className="page-title">{SERVER_NAME} MCP Server</h1>
          <p className="page-subtitle">Redirecting to authorization...</p>
        </div>
      </div>
    )
  }
  
  return (
    <div className="container-center">
      <div className="page app-container stack-lg">
        <div className="text-center">
          <h1 className="page-title">{SERVER_NAME} MCP Server</h1>
          <p className="page-subtitle">User {user?.id} is connected.</p>
        </div>

        <div className="section">
          <BearerTokenGenerator />
        </div>
      </div>
    </div>
  )
}