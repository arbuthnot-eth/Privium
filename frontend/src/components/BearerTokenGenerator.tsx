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
        <div className="card text-center">
            <div className="btn-group" style={{ justifyContent: 'center', marginBottom: '16px' }}>
                <button
                    className="btn btn-primary btn-lg"
                    onClick={generateBearerToken}
                    disabled={isGenerating || !authenticated}
                >
                    {isGenerating ? 'Generating...' : 'Generate Bearer Token'}
                </button>
                <button className="btn btn-outline" onClick={logout}>Disconnect</button>
            </div>

            {error && (
                <div className="alert alert-error mt-2">
                    Error: {error}
                </div>
            )}

            {bearerTokenInfo && (
                <div className="token-panel" id="token-panel">
                    <h4 className="token-title">Bearer Token Information:</h4>
                    {(() => {
                        const json = JSON.stringify(bearerTokenInfo, null, 2)
                        const rawToken = bearerTokenInfo[SERVER_NAME].headers.authorization.replace('Bearer ', '')
                        const marker = `Bearer ${rawToken}`
                        const idx = json.indexOf(marker)
                        if (idx === -1) {
                            return (
                                <pre className="code-block mt-2">{json}</pre>
                            )
                        }
                        return (
                            <pre className="code-block mt-2">
                                {json.slice(0, idx)}
                                {'Bearer '}
                                <span id="bearer-token-value" className="code-inline">{rawToken}</span>
                                {json.slice(idx + marker.length)}
                            </pre>
                        )
                    })()}
                    <div className="btn-group mt-2">
                        <CopyToClipboardButton textToCopy={JSON.stringify(bearerTokenInfo, null, 2)} buttonText="Copy JSON" />
                        <CopyToClipboardButton
                            textToCopy={bearerTokenInfo[SERVER_NAME].headers.authorization.replace('Bearer ', '')}
                            buttonText="Copy Token"
                            className="btn btn-primary copy-token"
                            onHoverChange={(hovered) => {
                                const panel = document.getElementById('token-panel')
                                if (panel) {
                                    if (hovered) {
                                        panel.classList.add('copy-hover')
                                    } else {
                                        panel.classList.remove('copy-hover')
                                    }
                                }
                            }}
                        />
                    </div>
                </div>
            )}
        </div>
    )
}