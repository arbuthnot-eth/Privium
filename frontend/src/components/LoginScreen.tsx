// frontend/src/components/LoginScreen.tsx
import { useLogin } from '@privy-io/react-auth'

export default function LoginScreen() {
  const { login } = useLogin({
    onComplete: async (loginData) => {
      // TODO: Handle login completion
    }
  });

  return (
    <div style={{ textAlign: 'center', padding: '2rem' }}>
      <h1>{SERVER_NAME} MCP Server</h1>
      <button onClick={login} style={{ padding: '12px 24px', fontSize: '16px', cursor: 'pointer' }}>
        Connect
      </button>
    </div>
  );
}