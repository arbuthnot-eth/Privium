// frontend/src/components/LoginScreen.tsx
import { useLogin } from '@privy-io/react-auth'
import { SERVER_NAME } from '../../../src/config'

export default function LoginScreen() {
  const { login } = useLogin({
    onComplete: async (loginData) => {
      console.log('🟢 LOGIN: User successfully logged in (LoginScreen)');
    }
  });

  return (
    <div style={{ textAlign: 'center', padding: '2rem' }}>
      <h1>{SERVER_NAME} MCP Server</h1>
      <p>Please sign in to continue</p>
      <button onClick={login} style={{ padding: '12px 24px', fontSize: '16px', cursor: 'pointer' }}>
        Sign In
      </button>
    </div>
  );
}