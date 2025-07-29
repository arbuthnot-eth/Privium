import { usePrivy } from '@privy-io/react-auth'
import { useState, useEffect } from 'react'
import LoginScreen from './components/LoginScreen'
import BearerTokenGenerator from './components/BearerTokenGenerator'
import AuthorizeHandler from './components/AuthorizeHandler'

export default function App() {
  const { ready, authenticated, user } = usePrivy();
  const [isAuthorizeMode, setIsAuthorizeMode] = useState(false);
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
  
  if (!ready) {
    return <div>Loading</div>;
  }
  
  if (isAuthorizeMode && authParams) {
    return <AuthorizeHandler authParams={authParams} />
  }
  
  if (!authenticated) {
    return <LoginScreen />
  }
  
  return (
    <div style={{ textAlign: 'center', padding: '2rem' }}>
      <h1>{SERVER_NAME} MCP Server</h1>
      <p>User {user?.id} is connected.</p>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginTop: '1rem' }}>
      </div>
      <div style={{ marginTop: '1rem' }}>
        <BearerTokenGenerator />
      </div>
    </div>
  );
}