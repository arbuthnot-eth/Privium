// frontend/src/components/BearerTokenGenerator.tsx
import { usePrivy, getAccessToken, useIdentityToken } from '@privy-io/react-auth'
import { useState } from 'react'
import CopyToClipboardButton from './CopyButton'
import { useLogout } from './LogoutHandler'
import { generateBearer } from './utils/generateBearer'


export default function BearerTokenGenerator() {
    const { authenticated } = usePrivy()
    const { identityToken } = useIdentityToken()
    const { logout } = useLogout()
    const [isGenerating, setIsGenerating] = useState(false)
    const [bearerTokenInfo, setBearerTokenInfo] = useState<any>(null)
    const [error, setError] = useState<string | null>(null)

    const generateBearerToken = async () => {
        if (!authenticated) {
            setError('You must be logged in to generate a bearer token')
            return
        }

        if (!identityToken) {
            setError('Identity token not available')
            return
        }

        setIsGenerating(true)
        setError(null)
        setBearerTokenInfo(null)

        try {
            const accessToken = await getAccessToken()
            if (!accessToken) {
                throw new Error('Failed to get access token from Privy')
            }

            const token = await generateBearer(accessToken, identityToken)
            if (!token) {
                throw new Error('Failed to generate bearer token')
            }

            // Format the response as requested
            const baseUrl = window.location.origin
            const tokenInfo = {
                [SERVER_NAME]: {
                    type: "streamable-http",
                    url: `${baseUrl}/mcp`,
                    headers: {
                        authorization: `Bearer ${token}`
                    }
                }
            }

            // Store in sessionStorage for revocation on logout
            sessionStorage.setItem('bearer_token', token)

            setBearerTokenInfo(tokenInfo)
            console.log('Bearer token generation completed successfully')

        } catch (err) {
            console.error('Error generating bearer token:', err)
            setError(err instanceof Error ? err.message : 'Failed to generate bearer token')
        } finally {
            setIsGenerating(false)
        }
    }

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
                <button onClick={logout}>Disconnect</button>
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
    )
}