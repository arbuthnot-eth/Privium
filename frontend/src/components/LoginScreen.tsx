// frontend/src/components/LoginScreen.tsx
import { useLogin, usePrivy } from '@privy-io/react-auth'
import { useSuiWalletCreation } from '../utils/walletUtils'

export default function LoginScreen() {
  const { user } = usePrivy();
  const { createSuiWalletIfNeeded } = useSuiWalletCreation();
  
  const { login } = useLogin({
    onComplete: async (loginData) => {
      console.log('🟢 LOGIN: User successfully logged in (LoginScreen)');
      
      // Create Sui wallet after successful login
      try {
        await createSuiWalletIfNeeded(user);
        console.log('🟢 LOGIN: Sui wallet creation completed');
      } catch (error) {
        console.error('❌ LOGIN: Failed to create Sui wallet:', error);
      }
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