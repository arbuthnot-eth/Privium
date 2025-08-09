// frontend/src/components/LoginScreen.tsx
import { useLogin } from '@privy-io/react-auth'

export default function LoginScreen() {
  const { login } = useLogin({
    onComplete: async (loginData) => {
      // TODO: Handle login completion
    }
  });

  return (
    <div className="container-center">
      <div className="page app-container stack text-center">
        <h1 className="page-title">{SERVER_NAME} MCP Server</h1>
        <p className="page-subtitle">Sign in to continue</p>
        <div className="btn-group" style={{ justifyContent: 'center' }}>
          <button className="btn btn-primary btn-lg" onClick={login}>Connect</button>
        </div>
      </div>
    </div>
  );
}