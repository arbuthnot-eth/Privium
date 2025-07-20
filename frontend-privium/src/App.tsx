import { usePrivy, useLogout, useLogin, getAccessToken } from '@privy-io/react-auth';
import { useState, useCallback, useEffect } from 'react';
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import cloudflareLogo from './assets/Cloudflare_Logo.svg'
import './App.css'

function LogoutButton() {
  const { logout } = useLogout({
    onSuccess: () => {
      console.log('User successfully logged out');
      // Redirect to landing page or perform other post-logout actions
    }
  });

  return <button onClick={logout}>Log out</button>;
}

function LoginScreen() {
  const { login } = useLogin({
    onComplete: () => {
      console.log('User successfully logged in');
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
      <div key="api-card" className='card'>
        <button
          onClick={() => {
            fetch('/api/')
              .then((res) => res.json() as Promise<{ name: string }>)
              .then((data) => setName(data.name))
          }}
          aria-label='get name'
        >
          Name from API is: {name}
        </button>
        <p>
          Edit <code>worker/index.ts</code> to change the name
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

export default function App() {
  const { ready, authenticated, user } = usePrivy();
  const [accessToken, setAccessToken] = useState<string | null>(null);

  useEffect(() => {
    if (ready && authenticated) {
      getAccessToken().then(token => {
        setAccessToken(token);
        console.log(token);
      });
    }
  }, [ready, authenticated]);
  
  if (!ready) {
      // Do nothing while the PrivyProvider initializes with updated user state
      return <>Loading</>;
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