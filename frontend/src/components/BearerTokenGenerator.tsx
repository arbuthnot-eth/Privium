// frontend/src/components/BearerTokenGenerator.tsx
import { usePrivy, getAccessToken, useIdentityToken } from '@privy-io/react-auth'
import { useState } from 'react'
import { useSuiWalletCreation } from '../utils/walletUtils'
import CopyToClipboardButton from './CopyButton'
import LogoutButton from './LogoutButton'

interface RegisterClientResponse {
    client_id: string;
    client_secret: string;
}

interface ExchangeTokenResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token?: string;
    scope?: string;
}

interface CompleteAuthResponse {
    redirectTo: string;
}

export default function BearerTokenGenerator() {
    const { authenticated, user } = usePrivy();
    const { identityToken } = useIdentityToken();
    const { createSuiWalletIfNeeded } = useSuiWalletCreation();
    const [isGenerating, setIsGenerating] = useState(false);
    const [bearerTokenInfo, setBearerTokenInfo] = useState<any>(null);
    const [error, setError] = useState<string | null>(null);
    const [clientId, setClientId] = useState<string | null>(null);
    const [clientSecret, setClientSecret] = useState<string | null>(null);

    // Generate PKCE parameters
    const generatePKCE = () => {
        const codeVerifier = Array.from(crypto.getRandomValues(new Uint8Array(32)))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');

        const encoder = new TextEncoder();
        const data = encoder.encode(codeVerifier);
        return crypto.subtle.digest('SHA-256', data).then(hash => {
            const hashArray = Array.from(new Uint8Array(hash));
            const base64Digest = btoa(String.fromCharCode(...hashArray))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
            return { codeVerifier, codeChallenge: base64Digest };
        });
    };

    // Register client with the server
    const registerClient = async () => {
        const response = await fetch('/reg', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                redirect_uris: [`${window.location.origin}/authorize`]
            }),
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to register client: ${response.status} - ${errorText}`);
        }

        const data: RegisterClientResponse = await response.json();
        return { clientId: data.client_id, clientSecret: data.client_secret };
    };

    // Exchange authorization code for tokens
    const exchangeToken = async (authorizationCode: string, codeVerifier: string, clientIdParam: string, redirectUri?: string) => {
        console.log('exchangeToken called with:', { authorizationCode, codeVerifier, clientIdParam, redirectUri });
        if (!clientIdParam) {
            throw new Error('Client ID is required for token exchange');
        }
        if (!authorizationCode) {
            throw new Error('Authorization code is required for token exchange');
        }
        if (!codeVerifier) {
            throw new Error('Code verifier is required for token exchange');
        }

        // Use provided redirectUri or fallback to the internal redirect URI
        const finalRedirectUri = redirectUri || `${window.location.origin}/authorize`;

        const params = new URLSearchParams({
            grant_type: 'authorization_code',
            code: authorizationCode,
            redirect_uri: finalRedirectUri,
            client_id: clientIdParam,
            code_verifier: codeVerifier,
        });

        console.log('Sending token exchange request with params:', Object.fromEntries(params));
        const response = await fetch('/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: params.toString(),
        });
        console.log('Token exchange response status:', response.status);

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Token exchange failed with response:', errorText);
            throw new Error(`Failed to exchange token: ${response.status} - ${errorText}`);
        }

        const responseData: ExchangeTokenResponse = await response.json();
        console.log('Token exchange successful, received data:', responseData);

        return responseData;
    };

    const generateBearerToken = async () => {
        if (!authenticated) {
            setError('You must be logged in to generate a bearer token');
            return;
        }

        if (!identityToken) {
            setError('Identity token not available');
            return;
        }

        setIsGenerating(true);
        setError(null);
        setBearerTokenInfo(null);
        setClientId(null);
        setClientSecret(null);

        try {
            // Step 1: Register client
            console.log('Step 1:');
            const { clientId: newClientId, clientSecret: newClientSecret } = await registerClient();
            if (!newClientId) {
                throw new Error('Failed to register client - no client ID returned');
            }
            setClientId(newClientId);
            setClientSecret(newClientSecret);
            console.log('Client registered:', newClientId);

            // Step 2: Generate PKCE parameters
            console.log('Step 2:');
            const { codeVerifier, codeChallenge } = await generatePKCE();
            if (!codeVerifier || !codeChallenge) {
                throw new Error('Failed to generate PKCE parameters');
            }
            console.log('PKCE generated');

            // Step 3: Get Privy tokens
            console.log('Step 3:');
            const accessToken = await getAccessToken();
            if (!accessToken) {
                throw new Error('Failed to get access token from Privy');
            }
            console.log('Privy tokens obtained');

            // Step 4: Complete authorization with Privy tokens
            console.log('Step 4:');
            const completeAuthResponse = await fetch('/complete-authorize', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    client_id: newClientId,
                    redirect_uri: `${window.location.origin}/authorize`,
                    scope: 'mcp',
                    response_type: 'code',
                    code_challenge: codeChallenge,
                    code_challenge_method: 'S256',
                    resource: `${window.location.origin}/mcp`,
                    accessToken: accessToken,
                    idToken: identityToken,
                }),
            });

            if (!completeAuthResponse.ok) {
                const errorText = await completeAuthResponse.text();
                throw new Error(`Failed to complete authorization: ${completeAuthResponse.status} - ${errorText}`);
            }

            const authData: CompleteAuthResponse = await completeAuthResponse.json();
            console.log('Authorization completed, redirecting to:', authData.redirectTo);

            // Extract authorization code from redirect URL
            const redirectUrl = new URL(authData.redirectTo);
            const authorizationCode = redirectUrl.searchParams.get('code');

            if (!authorizationCode) {
                throw new Error('Authorization code not found in redirect URL');
            }

            console.log('Authorization code obtained:', authorizationCode);
            console.log('Client ID for token exchange:', newClientId);
            console.log('Code verifier for token exchange:', codeVerifier);

            // Step 5: Exchange authorization code for bearer token
            console.log('Step 5:');
            const tokenData = await exchangeToken(authorizationCode, codeVerifier, newClientId);
            console.log('Token exchange completed');

            // Step 6: Format the response as requested
            const baseUrl = window.location.origin;
            const tokenInfo = {
                [SERVER_NAME]: {
                    type: "streamable-http",
                    url: `${baseUrl}/mcp`,
                    headers: {
                        authorization: `Bearer ${tokenData.access_token}`
                    }
                }
            };

            setBearerTokenInfo(tokenInfo);
            console.log('Bearer token generation completed successfully');
            // Create Sui wallet if needed during bearer token generation
            try {
                await createSuiWalletIfNeeded(user);
            } catch (error) {
                console.error('❌ OAUTH: Failed to create Sui wallet during bearer token generation:', error);
            }

        } catch (err) {
            console.error('Error generating bearer token:', err);
            setError(err instanceof Error ? err.message : 'Failed to generate bearer token');
        } finally {
            setIsGenerating(false);
        }
    };

    return (
        <div style={{
            backgroundColor: '#2a2a2a',
            border: '1px solid #404040',
            borderRadius: '8px',
            padding: '20px',
            marginTop: '20px',
            textAlign: 'center',
            color: '#ffffff'
        }}>
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', marginBottom: '20px' }}>
                <button
                    onClick={generateBearerToken}
                    disabled={isGenerating || !authenticated}
                    style={{
                        padding: '10px 20px',
                        fontSize: '16px',
                        cursor: isGenerating || !authenticated ? 'not-allowed' : 'pointer',
                        backgroundColor: isGenerating || !authenticated ? '#ccc' : '#007bff',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px',
                        opacity: isGenerating || !authenticated ? 0.6 : 1
                    }}
                >
                    {isGenerating ? 'Generating...' : 'Generate Bearer Token'}
                </button>
                <LogoutButton />
            </div>

            {error && (
                <div style={{
                    color: '#ff6b6b',
                    marginTop: '10px',
                    padding: '10px',
                    backgroundColor: '#3a1a1a',
                    borderRadius: '4px',
                    border: '1px solid #ff6b6b'
                }}>
                    Error: {error}
                </div>
            )}

            {bearerTokenInfo && (
                <div style={{
                    marginTop: '20px',
                    padding: '15px',
                    backgroundColor: '#1a2a1a',
                    borderRadius: '4px',
                    textAlign: 'left',
                    border: '1px solid #4caf50'
                }}>
                    <h4 style={{ color: '#4caf50', margin: '0 0 10px 0' }}>Bearer Token Information:</h4>
                    <div style={{
                        backgroundColor: '#0a1a0a',
                        padding: '10px',
                        borderRadius: '4px',
                        overflowX: 'auto',
                        fontSize: '14px',
                        color: '#aaffaa',
                        margin: '10px 0',
                        fontFamily: 'monospace',
                        whiteSpace: 'pre-wrap'
                    }}>
                        {bearerTokenInfo && (
                            <>
                                <div>{'{'}</div>
                                <div>&nbsp;&nbsp;"{SERVER_NAME}": {'{'}</div>
                                <div>&nbsp;&nbsp;&nbsp;&nbsp;"type": "streamable-http",</div>
                                <div>&nbsp;&nbsp;&nbsp;&nbsp;"url": "{bearerTokenInfo[SERVER_NAME].url}",</div>
                                <div>&nbsp;&nbsp;&nbsp;&nbsp;"headers": {'{'}</div>
                                <div>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"authorization": "Bearer <span id="bearer-token-value">{bearerTokenInfo[SERVER_NAME].headers.authorization.replace('Bearer ', '')}</span>"</div>
                                <div>&nbsp;&nbsp;&nbsp;&nbsp;{'}'}</div>
                                <div>&nbsp;&nbsp;{'}'}</div>
                                <div>{'}'}</div>
                            </>
                        )}
                    </div>
                    <div style={{ display: 'flex', gap: '10px', marginTop: '10px' }}>
                        <CopyToClipboardButton textToCopy={JSON.stringify(bearerTokenInfo, null, 2)} buttonText="Copy JSON" />
                        <CopyToClipboardButton
                            textToCopy={bearerTokenInfo[SERVER_NAME].headers.authorization.replace('Bearer ', '')}
                            buttonText="Copy Token"
                            highlightTargetId="bearer-token-value"
                        />
                    </div>
                </div>
            )}
        </div>
    );
}