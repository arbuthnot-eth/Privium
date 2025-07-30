// frontend/src/components/AuthorizeHandler.tsx
import { usePrivy, useLogin, useLogout, getAccessToken, useIdentityToken } from '@privy-io/react-auth';
import { useState, useEffect } from 'react'

interface AuthorizeHandlerProps {
  authParams: {
    client_id: string | null;
    redirect_uri: string | null;
    scope: string | null;
    state: string | null;
    response_type: string | null;
    code_challenge: string | null;
    code_challenge_method: string | null;
    resource: string | null;
  };
}

interface CompleteAuthResponse {
  redirectTo: string;
}

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

export default function AuthorizeHandler({ authParams }: AuthorizeHandlerProps) {
  const { ready, authenticated, user } = usePrivy();
  const { identityToken } = useIdentityToken();

  // Login handler
  const { login } = useLogin({
    onComplete: async (loginData) => {
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
    if (ready && authenticated && !accessToken) {
      console.log('🔵 OAUTH AUTH STATE: Getting access token...');
      getAccessToken().then(token => {
        console.log('🔵 OAUTH AUTH STATE: Received access token:', !!token);
        setAccessToken(token);
      });
    }
  }, [ready, authenticated, accessToken]);

  const handleApprove = async () => {
    console.log('🟢 OAUTH: User clicked Grant Authorization');
    console.log('🔵 OAUTH: Starting handleApprove with accessToken:', !!accessToken, 'redirect_uri:', authParams.redirect_uri);
    if (!accessToken || !authParams.redirect_uri || processing) return;
    setProcessing(true);


    // Complete authorization
    const backendUrl = '/complete-authorize';
    console.log('🔵 OAUTH: Calling complete-authorize endpoint');

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
      });

      if (!response.ok) {
        throw new Error('Failed to complete authorization');
      }

      const data: CompleteAuthResponse = await response.json();
      console.log('🔵 OAUTH: Received redirect response:', data);
      console.log('🔵 OAUTH: Redirecting to:', data.redirectTo);
      window.location.href = data.redirectTo;
      setTimeout(() => {
        window.close();
      }, 2400);
    } catch (err) {
      console.error('🔴 OAUTH ERROR: Authorization error:', err);
      setProcessing(false);
    }
  };

  const handleCancel = () => {
    console.log('🔴 OAUTH: User clicked Deny Access');
    if (authParams.redirect_uri) {
      const redirectUrl = new URL(authParams.redirect_uri);
      redirectUrl.searchParams.set('error', 'access_denied');
      if (authParams.state) redirectUrl.searchParams.set('state', authParams.state);
      console.log('🔴 OAUTH: Redirecting with access_denied error to:', redirectUrl.toString());
      window.location.href = redirectUrl.toString();
    }
    console.log('🔴 OAUTH: Attempting to close window...');
    window.close();
  };

  if (!ready) return <div>Loading...</div>;

  if (authParams.response_type !== 'code') {
    return <div>Unsupported response type. Only 'code' is supported.</div>;
  }

  if (!authenticated) {
    return (
      <div style={{ textAlign: 'center', padding: '2rem' }}>
        <h1>Authorize Access</h1>
        <p>Connect to grant access to {SERVER_NAME}</p>
        <button onClick={login} style={{ padding: '12px 24px', fontSize: '16px', cursor: 'pointer' }}>
          Connect
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
              An MCP Client wants to access your {SERVER_NAME} MCP Server
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
                • Access to {SERVER_NAME} MCP Server tools and resources
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
                  Disconnect
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
            This allows the MCP Client to connect to your {SERVER_NAME} MCP Server using OAuth 2.1 with PKCE
          </p>
        </div>
      </div>
    </>
  );
}