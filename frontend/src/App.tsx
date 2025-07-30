import { usePrivy } from '@privy-io/react-auth'
import { useState, useEffect } from 'react'
import LoginScreen from './components/LoginScreen'
import BearerTokenGenerator from './components/BearerTokenGenerator'
import AuthorizeHandler from './components/AuthorizeHandler'
import { useSuiWalletCreation } from './utils/walletUtils'

/**
 * Main application component that handles authentication routing
 * and displays the appropriate UI based on the user's state.
 */
export default function App() {
  // Get authentication state from Privy
  const { ready, authenticated, user } = usePrivy();
  const { createSuiWalletIfNeeded } = useSuiWalletCreation();
  
  // State for OAuth authorization mode
  const [isAuthorizeMode, setIsAuthorizeMode] = useState(false);
  
  // State for OAuth authorization parameters
  const [authParams, setAuthParams] = useState<{
    client_id: string | null;
    redirect_uri: string | null;
    scope: string | null;
    state: string | null;
    response_type: string | null;
    code_challenge: string | null;
    code_challenge_method: string | null;
    resource: string | null;
  } | null>(null);

  /**
   * Check if the user is on the authorize route and parse OAuth parameters
   * This happens when an MCP client redirects to the app for authorization
   */
  useEffect(() => {
    if (window.location.pathname === '/authorize') {
      setIsAuthorizeMode(true);
      const params = new URLSearchParams(window.location.search);
      const parsedAuthParams = {
        client_id: params.get('client_id'),
        redirect_uri: params.get('redirect_uri'),
        scope: params.get('scope'),
        state: params.get('state'),
        response_type: params.get('response_type'),
        code_challenge: params.get('code_challenge'),
        code_challenge_method: params.get('code_challenge_method'),
        resource: params.get('resource') || window.location.origin + '/mcp',
      };
      setAuthParams(parsedAuthParams);
    }
  }, []);

  /**
   * Create Sui wallet when user becomes authenticated
   */
  useEffect(() => {
    if (ready && authenticated && user) {
      const createWallet = async () => {
        try {
          //await createSuiWalletIfNeeded(user);
          console.log('🟢 APP: Sui wallet creation completed');
        } catch (error) {
          console.error('❌ APP: Failed to create Sui wallet:', error);
        }
      };
      
      createWallet();
    }
  }, [ready, authenticated, user, createSuiWalletIfNeeded]);
  
  // Show loading state while Privy is initializing
  if (!ready) {
    return <div>Loading authentication...</div>;
  }
  
  // If user is on the authorize route with valid parameters, show the authorization screen
  if (isAuthorizeMode && authParams) {
    return <AuthorizeHandler authParams={authParams} />
  }
  
  // If user is not authenticated, show the login screen
  if (!authenticated) {
    return <LoginScreen />
  }
  
  // Main application UI for authenticated users
  return (
    <div style={{ textAlign: 'center', padding: '2rem' }}>
      <h1>{SERVER_NAME} MCP Server</h1>
      <p>User {user?.id} is connected.</p>
      
      {/* Container for any additional user controls */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginTop: '1rem' }}>
      </div>
      
      {/* Bearer token generator for MCP client connections */}
      <div style={{ marginTop: '1rem' }}>
        <BearerTokenGenerator />
      </div>
    </div>
  );
}