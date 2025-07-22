import { usePrivy, useLogout, useLogin, getAccessToken, useIdentityToken } from '@privy-io/react-auth';
import { useState, useCallback, useEffect } from 'react';
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import cloudflareLogo from './assets/Cloudflare_Logo.svg'
import './App.css'

function LogoutButton() {
  const { logout } = useLogout({
    onSuccess: () => {
      console.log('🔴 LOGOUT: User successfully logged out');
      // Redirect to landing page or perform other post-logout actions
    }
  });

  return <button onClick={logout}>Log out</button>;
}

function LoginScreen() {
  const { login } = useLogin({
    onComplete: () => {
      console.log('🟢 LOGIN: User successfully logged in (LoginScreen)');
    }
  });

  return (
    <div style={{ textAlign: 'center', padding: '2rem' }}>
      <h1>Welcome to Privium</h1>
      <p>Please sign in to continue</p>
      <button onClick={login} style={{ padding: '12px 24px', fontSize: '16px', cursor: 'pointer' }}>
        Sign In
      </button>
    </div>
  );
}

function CopyToClipboardButton({ textToCopy }: { textToCopy: string }) {
  const [isCopied, setIsCopied] = useState(false);

  const handleCopyClick = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(textToCopy);
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 2000); // Reset "Copied!" message after 2 seconds
    } catch (err) {
      console.error('Failed to copy text: ', err);
    }
  }, [textToCopy]);

  return (
    <button onClick={handleCopyClick} style={{ marginLeft: '10px', padding: '5px 10px', fontSize: '14px', cursor: 'pointer' }}>
      {isCopied ? 'Copied!' : 'Copy'}
    </button>
  );
}

function AppContent({ user, accessToken }: { user: any, accessToken: string }) {
  const { identityToken } = useIdentityToken();
  const [count, setCount] = useState(0);
  const [name, setName] = useState('unknown');

  return (
    <>
      <div key="header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', maxWidth: '800px', margin: '0 auto' }}>
        <div>
          <a key="vite" href='https://vite.dev' target='_blank'>
            <img src={viteLogo} className='logo' alt='Vite logo' />
          </a>
          <a key="react" href='https://react.dev' target='_blank'>
            <img src={reactLogo} className='logo react' alt='React logo' />
          </a>
          <a key="cloudflare" href='https://workers.cloudflare.com/' target='_blank'>
            <img src={cloudflareLogo} className='logo cloudflare' alt='Cloudflare logo' />
          </a>
        </div>
        <LogoutButton />
      </div>
      <h1 key="title">Vite + React + Cloudflare</h1>
      <div key="counter-card" className='card'>
        <button
          onClick={() => setCount((count) => count + 1)}
          aria-label='increment'
        >
          count is {count}
        </button>
        <p>
          Edit <code>src/App.tsx</code> and save to test HMR
        </p>
      </div>
      <p key="docs-text" className='read-the-docs'>
        Click on the Vite and React logos to learn more
      </p>
      <p key="user-info">User {user?.id} is logged in.</p>
      <div key="access-token-display" style={{ display: 'flex', alignItems: 'center', marginTop: '1rem' }}>
        <p style={{ margin: 0 }}>Access Token: {accessToken ? `${accessToken.substring(0, 20)}...` : 'N/A'}</p>
        {accessToken && <CopyToClipboardButton textToCopy={accessToken} />}
      </div>
    </>
  );
}

function AuthorizeHandler({ authParams }: { authParams: { client_id: string | null; redirect_uri: string | null; scope: string | null; state: string | null; response_type: string | null; code_challenge: string | null; code_challenge_method: string | null; resource: string | null } }) {
  const { ready, authenticated, user } = usePrivy();
  const { identityToken } = useIdentityToken();
  const { login } = useLogin({
    onComplete: () => {
      console.log('🟢 OAUTH LOGIN: User successfully logged in for authorization');
    },
  });
  const { logout } = useLogout({
    onSuccess: () => {
      console.log('🔴 OAUTH LOGOUT: User logged out to switch accounts');
    }
  });
  const [processing, setProcessing] = useState(false);
  const [accessToken, setAccessToken] = useState<string | null>(null);

  useEffect(() => {
    console.log('🔵 OAUTH AUTH STATE: ready:', ready, 'authenticated:', authenticated);
    if (ready && authenticated) {
      console.log('🔵 OAUTH AUTH STATE: Getting access token...');
      getAccessToken().then(token => {
        console.log('🔵 OAUTH AUTH STATE: Received access token:', !!token);
        setAccessToken(token);
      });
    }
  }, [ready, authenticated]);

  // Removed auto-trigger - now wait for explicit user consent

  const handleApprove = () => {
    console.log('🟢 OAUTH: User clicked Grant Authorization');
    console.log('🔵 OAUTH: Starting handleApprove with accessToken:', !!accessToken, 'redirect_uri:', authParams.redirect_uri);
    if (!accessToken || !authParams.redirect_uri || processing) return;
    setProcessing(true);
    const backendUrl = '/complete-authorize';
    console.log('🔵 OAUTH: Calling complete-authorize endpoint');
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
        idToken: identityToken, // Include the identity token
      }),
    })
      .then((res) => {
        if (!res.ok) throw new Error('Failed to complete authorization');
        return res.json();
      })
      .then((data) => {
        console.log('🔵 OAUTH: Received redirect response:', data);
        console.log('🔵 OAUTH: Redirecting to:', data.redirectTo);
        window.location.href = data.redirectTo;
        // Close the window after redirect
        setTimeout(() => {
          window.close();
        }, 1500);
      })
      .catch((err) => {
        console.error('🔴 OAUTH ERROR: Authorization error:', err);
        setProcessing(false);
        // Optional: Render an error message in the UI
      });
  };

  const handleCancel = () => {
    console.log('🔴 OAUTH: User clicked Deny Access');
    if (authParams.redirect_uri) {
      const redirectUrl = new URL(authParams.redirect_uri);
      redirectUrl.searchParams.set('error', 'access_denied');
      if (authParams.state) redirectUrl.searchParams.set('state', authParams.state);
      console.log('🔴 OAUTH: Redirecting with access_denied error to:', redirectUrl.toString());
      window.location.href = redirectUrl.toString();
    } else {
      // Optionally close window or show message
      console.log('🔴 OAUTH: No redirect URI, closing window');
      window.close();
    }
  };

  if (!ready) return <div>Loading...</div>;

  if (authParams.response_type !== 'code') {
    return <div>Unsupported response type. Only 'code' is supported.</div>;
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
    );
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
  );

  const authDialogStyle = `
    :root {
      --bg-color: light-dark(#ffffff, #1a1a1a);
      --card-bg: light-dark(#ffffff, #2a2a2a);
      --text-color: light-dark(#1a1a1a, #ffffff);
      --text-secondary: light-dark(#666666, #999999);
      --border-color: light-dark(#e1e5e9, #404040);
      --button-primary: light-dark(#007bff, #0d6efd);
      --button-primary-hover: light-dark(#0056b3, #0b5ed7);
      --button-secondary: light-dark(#6c757d, #6c757d);
      --button-secondary-hover: light-dark(#545b62, #5a6268);
    }

    @media (prefers-color-scheme: dark) {
      :root {
        --bg-color: #1a1a1a;
        --card-bg: #2a2a2a;
        --text-color: #ffffff;
        --text-secondary: #999999;
        --border-color: #404040;
        --button-primary: #0d6efd;
        --button-primary-hover: #0b5ed7;
      }
    }
  `;

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
              Cursor IDE wants to access your MCP tools
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
                • Access to MCP Server tools and resources
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
            This allows Cursor to connect to your Privium MCP Server using OAuth 2.1 with PKCE
          </p>
        </div>
      </div>
    </>
  );
}

export default function App() {
  const { ready, authenticated, user } = usePrivy();
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [isAuthorizeMode, setIsAuthorizeMode] = useState(false);
  const [authParams, setAuthParams] = useState<{ client_id: string | null; redirect_uri: string | null; scope: string | null; state: string | null; response_type: string | null; code_challenge: string | null; code_challenge_method: string | null; resource: string | null } | null>(null);

  useEffect(() => {
    if (ready && authenticated) {
      getAccessToken().then(token => {
        setAccessToken(token);
      });
    }
  }, [ready, authenticated]);
  
  useEffect(() => {
    if (window.location.pathname === '/authorize') {
      setIsAuthorizeMode(true);
      const params = new URLSearchParams(window.location.search);
      setAuthParams({
        client_id: params.get('client_id'),
        redirect_uri: params.get('redirect_uri'),
        scope: params.get('scope'),
        state: params.get('state'),
        response_type: params.get('response_type'),
        code_challenge: params.get('code_challenge'),
        code_challenge_method: params.get('code_challenge_method'),
        resource: params.get('resource') || 'http://localhost:8787/mcp', // Ensure resource is always set
      });
    }
  }, []);
  
  if (!ready) {
      // Do nothing while the PrivyProvider initializes with updated user state
      return <>Loading</>;
  }
  
  if (isAuthorizeMode && authParams) {
    return <AuthorizeHandler authParams={authParams} />;
  }
  
  if (ready && !authenticated) {
      // Show login screen when user is not authenticated
      return <LoginScreen />;
  }
  
  if (ready && authenticated) {
      // Show the main app content when authenticated
      return <AppContent user={user} accessToken={accessToken || ''} />;
  }
  return null; // Should not reach here, but good for exhaustive checks
}