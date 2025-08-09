export async function generateBearer(accessToken: string, idToken: string, isTemp: boolean = false): Promise<string | null> {
  try {
    // Step 1: Register client
    const { clientId: newClientId } = await registerClient()
    if (!newClientId) {
      throw new Error('Failed to register client - no client ID returned')
    }
    if (!isTemp) console.log('Client registered:', newClientId)

    // Step 2: Generate PKCE parameters
    const { codeVerifier, codeChallenge } = await generatePKCE()
    if (!codeVerifier || !codeChallenge) {
      throw new Error('Failed to generate PKCE parameters')
    }
    if (!isTemp) console.log('PKCE generated')

    // Step 3: Complete authorization with Privy tokens
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
        idToken: idToken,
      }),
    })

    if (!completeAuthResponse.ok) {
      const errorText = await completeAuthResponse.text()
      throw new Error(`Failed to complete authorization: ${completeAuthResponse.status} - ${errorText}`)
    }

    const authData: CompleteAuthResponse = await completeAuthResponse.json()
    if (!isTemp) console.log('Authorization completed, redirecting to:', authData.redirectTo)

    // Extract authorization code from redirect URL
    const redirectUrl = new URL(authData.redirectTo)
    const authorizationCode = redirectUrl.searchParams.get('code')

    if (!authorizationCode) {
      throw new Error('Authorization code not found in redirect URL')
    }

    if (!isTemp) {
      console.log('Authorization code obtained:', authorizationCode)
      console.log('Client ID for token exchange:', newClientId)
      console.log('Code verifier for token exchange:', codeVerifier)
    }

    // Step 4: Exchange authorization code for bearer token
    const tokenData = await exchangeToken(authorizationCode, codeVerifier, newClientId)
    if (!isTemp) console.log('Token exchange completed')

    return tokenData.access_token
  } catch (err) {
    console.error('Error generating bearer token:', err)
    return null
  }
}

async function registerClient(): Promise<{ clientId: string }> {
  const response = await fetch('/reg', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      redirect_uris: [`${window.location.origin}/authorize`]
    }),
  })

  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`Failed to register client: ${response.status} - ${errorText}`)
  }

  const data: RegisterClientResponse = await response.json()
  return { clientId: data.client_id }
}

async function generatePKCE(): Promise<{ codeVerifier: string; codeChallenge: string }> {
  const codeVerifier = Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')

  const encoder = new TextEncoder()
  const data = encoder.encode(codeVerifier)
  const digest = await crypto.subtle.digest('SHA-256', data)
  const base64Digest = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')

  return { codeVerifier, codeChallenge: base64Digest }
}

async function exchangeToken(authorizationCode: string, codeVerifier: string, clientIdParam: string): Promise<ExchangeTokenResponse> {
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code: authorizationCode,
    redirect_uri: `${window.location.origin}/authorize`,
    client_id: clientIdParam,
    code_verifier: codeVerifier,
  })

  const response = await fetch('/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  })

  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`Failed to exchange token: ${response.status} - ${errorText}`)
  }

  const responseData: ExchangeTokenResponse = await response.json()
  return responseData
}