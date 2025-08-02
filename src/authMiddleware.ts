import { Hono, Context } from 'hono'
import { cors } from 'hono/cors'
import { PrivyClient } from "@privy-io/server-auth"
import { CrossmintWallets, createCrossmint } from "@crossmint/wallets-sdk"
import { createWalletsIfNeeded } from './Privy/walletUtils'

// Initialize Privy Client
export function initPrivyClient(): PrivyClient {
	return new PrivyClient(process.env.PRIVY_APP_ID, process.env.PRIVY_APP_SECRET, {
		walletApi: {
			authorizationPrivateKey: process.env.AUTH_PRIVATE_KEY,
		},
	})
}

// Initialize Crossmint Wallets
export function initCrossmint(): CrossmintWallets {
	const crossmint = createCrossmint({
		apiKey: process.env.CROSSMINT_API_KEY as string,
	})
	return CrossmintWallets.from(crossmint)
}

// Helper function to get fresh user data with latest wallets
export async function refreshUser(cachedUser: PrivyUser) {
	// Initialize Privy client
	const privyClient = initPrivyClient()
	try {
		// Get fresh user data from Privy using userId string
		const freshUser = await privyClient.getUserById(cachedUser.id)
		// Refresh the user data
		return { freshUser, privyClient }
	} catch (error) {
		console.error('❌ Error fetching fresh user data:', error)
		// Fallback to cached user data if fresh fetch fails
		return { cachedUser, privyClient }
	}
}

// Secure KV Put with expiration TTL
async function secureKvPut(env: Env, key: string, value: string, ttl: number) {
	await env.OAUTH_KV.put(key, value, { expirationTtl: ttl });
}

// Auth middleware
export const requireAuth = async (c: Context<{ Bindings: Env }>, next: any) => {
	// Validate OAuth Bearer token
	const authHeader = c.req.header('Authorization')
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		console.error('🔴 MCP ERROR: Missing or invalid Authorization header')
		const url = new URL(c.req.url)
		const resourceMetadataUrl = `${url.origin}/.well-known/oauth-protected-resource`
		c.header('WWW-Authenticate', `Bearer realm="mcp", resource_metadata="${resourceMetadataUrl}"`)
		return c.json({ error: 'invalid_token', error_description: 'Missing or invalid Authorization header.' }, 401)
	}

	const token = authHeader.substring(7) // Remove "Bearer " prefix

	// Hash token for lookup
	const hashedToken = await hashSecret(token)

	// Retrieve token data from KV
	const tokenDataStr = await c.env.OAUTH_KV.get(`access_token:${hashedToken}`)
	if (!tokenDataStr) {
		console.error('🔴 MCP ERROR: Invalid or expired access token')
		c.header('WWW-Authenticate', 'Bearer realm="mcp"')
		return c.text('Unauthorized', 401)
	}

	// Decrypt token data
	const encryptedTokenData = JSON.parse(tokenDataStr)
	const unwrappedTokenKey = await crypto.subtle.unwrapKey(
		'raw',
		base64ToArrayBuffer(encryptedTokenData.wrappedKey),
		await deriveKeyFromToken(token, c.env),
		{ name: 'AES-KW' },
		{ name: 'AES-GCM' },
		false,
		['decrypt']
	)
	const unwrappedHmacKey = await crypto.subtle.unwrapKey(
		'raw',
		base64ToArrayBuffer(encryptedTokenData.hmacKey),
		await deriveKeyFromToken(token, c.env),
		{ name: 'AES-KW' },
		{ name: 'HMAC', hash: 'SHA-256' },
		true,
		['verify']
	)
	const tokenData = await decryptProps(encryptedTokenData.encryptedData, encryptedTokenData.iv, unwrappedTokenKey, encryptedTokenData.hmac, unwrappedHmacKey)

	// Check user-level revocation
	const revocationTimestamp = await c.env.OAUTH_KV.get(`revoked_user:${tokenData.privyUser.id}`)
	if (revocationTimestamp && parseInt(revocationTimestamp) > tokenData.createdAt) {
		console.error('🔴 MCP ERROR: User AccessToken has been revoked')
		return c.json({ error: 'invalid_token', error_description: 'User AccessToken has been revoked' }, 401)
	}

	console.log('🛡️  MCP: Validated decrypted token for user:', tokenData.privyUser.id)

	// Set user context
	c.env.privyUser = tokenData.privyUser

	await next()
}

// Auth Handler
export const authHandler = (app: Hono<{ Bindings: Env }>, strictMode: boolean) => {
	// Add CORS middleware
	app.use('/*', cors({
		origin: '*',
		allowMethods: ['GET', 'POST', 'OPTIONS'],
		allowHeaders: ['Content-Type', 'Authorization', 'mcp-session-id', 'mcp-protocol-version'],
		exposeHeaders: ['mcp-session-id'],
	}))

	// OAuth Discovery Endpoints
	app.get('/.well-known/oauth-authorization-server', (c) => {
		const url = new URL(c.req.url)
		c.header('Cache-Control', 'public, max-age=86400')
		return c.json({
			issuer: url.origin,
			authorization_endpoint: `${url.origin}/authorize`,
			token_endpoint: `${url.origin}/token`,
			registration_endpoint: `${url.origin}/reg`,
			scopes_supported: ['mcp'],
			response_types_supported: ['code'],
			response_modes_supported: ['query'],
			grant_types_supported: ['authorization_code', 'refresh_token'],
			token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
			revocation_endpoint: `${url.origin}/revoke`,
			code_challenge_methods_supported: ['plain', 'S256'],
		})
	})

	// OAuth Protected Resource Endpoints
	app.get('/.well-known/oauth-protected-resource*', (c) => {
		const url = new URL(c.req.url)
		c.header('Cache-Control', 'public, max-age=3600')
		return c.json({
			resource: `${url.origin}/mcp`,
			authorization_servers: [url.origin],
			scopes_supported: ['mcp'],
			bearer_methods_supported: ['header'],
			resource_documentation: "https://github.com/arbuthnot-eth/privium",
		})
	})

	// Authorization Endpoint (serve frontend)
	app.get('/authorize', async (c) => {
		try {
			const url = new URL(c.req.url)
			const indexRequest = new Request(url.origin + '/dist/index.html')
			const asset = await c.env.ASSETS.fetch(indexRequest)

			if (asset.ok) {
				let html = await asset.text()
				// Inject environment variables into the frontend
				html = html.replace(
					'</head>',
					`<script>
					  window.PRIVY_APP_ID = "${c.env.PRIVY_APP_ID}"
				  </script></head>`
				)
				console.log('✅ FRONTEND: Fetched asset and injected Privy App ID')
				return c.html(html)
			} else {
				console.error('🔴 FRONTEND ERROR: Asset fetch failed, status:', asset.status)
				return c.text('Frontend not found', 404)
			}
		} catch (error) {
			console.error('🔴 FRONTEND ERROR: Failed to serve frontend:', error)
			return c.text('Frontend error', 500)
		}
	})

	// Authorization Completion (Privy → OAuth Code)
	app.post('/complete-authorize', async (c) => {
		try {
			const body = await c.req.json()

			// Get access and identity tokens
			const token = body.accessToken
			const idToken = body.idToken
			if (!token) {
				console.error('🔴 OAUTH ERROR: Missing access token')
				return c.text('Missing access token', 401)
			}
			if (!idToken) {
				console.error('🔴 OAUTH ERROR: Missing identity token')
				return c.text('Missing identity token', 401)
			}

			// Verify and parse the identity token to get full user data
			let verifiedClaims
			let privyUser
			const privyClient = initPrivyClient()
			try {
				verifiedClaims = await privyClient.verifyAuthToken(token)
				privyUser = await privyClient.getUser({ idToken })
				console.log('🛡️  OAUTH: Privy Identity and Access tokens verified')
				await createWalletsIfNeeded(privyUser, privyClient)
			} catch (error) {
				console.error('🔴 OAUTH ERROR: Token verification failed:', error)
				return c.json({
					error: 'Invalid token',
					details: error instanceof Error ? error.message : String(error)
				}, 401)
			}

			const { authorizationKey } = await privyClient.walletApi.generateUserSigner({ userJwt: token })
			privyClient.walletApi.updateAuthorizationKey(authorizationKey)

			// Generate authorization code
			const authCode = crypto.randomUUID()

			// Store the authorization details in KV for later token exchange
			// Include client validation metadata for better caching support
			const authData = {
				userId: privyUser.id, // Use the Privy user ID for consistency
				privyUser: privyUser, // Store the full Privy user object
				clientId: body.client_id,
				redirectUri: body.redirect_uri,
				scope: body.scope || 'mcp',
				codeChallenge: body.code_challenge,
				codeChallengeMethod: body.code_challenge_method,
				// Add client validation metadata
				clientValidation: {
					primaryClientId: body.client_id,
					redirectUri: body.redirect_uri,
					allowClientIdFlexibility: true, // Allow client ID mismatches if other validation passes
					timestamp: Date.now()
				},
				createdAt: Date.now(),
			}

			// Encrypt auth data
			const { encryptedData, iv, key, hmac, hmacKey } = await encryptProps(authData)
			const wrappedKey = await wrapKeyWithToken(authCode, key, c.env)
			const wrappedHmacKey = await wrapKeyWithToken(authCode, hmacKey, c.env)
			const encryptedAuthData = { encryptedData, iv, wrappedKey, hmac, hmacKey: wrappedHmacKey }
			await secureKvPut(c.env, `auth_code:${authCode}`, JSON.stringify(encryptedAuthData), 600)
			console.log('✅ OAUTH: Stored encrypted auth data in KV with client validation metadata')

			// Build redirect URL
			const redirectUrl = new URL(body.redirect_uri)
			redirectUrl.searchParams.set('code', authCode)
			if (body.state) { redirectUrl.searchParams.set('state', body.state) }
			const redirectTo = redirectUrl.toString()
			console.log('🔵 OAUTH: Redirect URL built:', redirectTo)

			// Return redirect URL
			return c.json({ redirectTo })
		} catch (error) {
			console.error('🔴 OAUTH ERROR: /complete-authorize failed:', error)
			return c.json({
				error: 'Internal server error',
				details: error instanceof Error ? error.message : String(error)
			}, 500)
		}
	})

	// Token Exchange (OAuth Code → Bearer Token + Refresh Token)
	app.post('/token', async (c) => {
		try {
			const authHeader = c.req.header('Authorization')
			let clientId: string | null = null
			let clientSecret: string | null = null

			if (authHeader && authHeader.startsWith('Basic ')) {
				const encoded = authHeader.substring(6)
				const decoded = atob(encoded)
				const [basicClientId, basicClientSecret] = decoded.split(':')
				clientId = basicClientId
				clientSecret = basicClientSecret
				console.log('🔵 TOKEN: Basic Auth client_id:', clientId)
			}

			// Get request body
			const body = await c.req.text()
			const params = new URLSearchParams(body)
			// Get grant type, code, code verifier, redirect URI, and refresh token
			const grantType = params.get('grant_type')
			const code = params.get('code')
			const codeVerifier = params.get('code_verifier')
			const redirectUri = params.get('redirect_uri')
			const refreshToken = params.get('refresh_token')

			// If client_id was not in Basic Auth, try to get it from the body
			if (!clientId) {
				clientId = params.get('client_id')
			}

			// If client_secret was not in Basic Auth, try to get it from the body
			if (!clientSecret) {
				clientSecret = params.get('client_secret')
			}
			// Handle refresh_token grant type
			if (grantType === 'refresh_token') {
				if (!refreshToken) {
					console.error('🔴 TOKEN ERROR: Missing refresh_token')
					return c.json({ error: 'invalid_request' }, 400)
				}

				// Retrieve refresh token data from KV
				const refreshDataStr = await c.env.OAUTH_KV.get(`refresh_token:${await hashSecret(refreshToken)}`)
				if (!refreshDataStr) {
					console.error('🔴 TOKEN ERROR: Invalid or expired refresh token')
					return c.json({ error: 'invalid_grant' }, 400)
				}

				// Decrypt refresh token data
				const encryptedRefreshData = JSON.parse(refreshDataStr)
				const unwrappedRefreshKey = await crypto.subtle.unwrapKey(
					'raw',
					base64ToArrayBuffer(encryptedRefreshData.wrappedKey),
					await deriveKeyFromToken(refreshToken, c.env),
					{ name: 'AES-KW' },
					{ name: 'AES-GCM' },
					false,
					['decrypt']
				)

				const unwrappedHmacKey = await crypto.subtle.unwrapKey(
					'raw',
					base64ToArrayBuffer(encryptedRefreshData.hmacKey),
					await deriveKeyFromToken(refreshToken, c.env),
					{ name: 'AES-KW' },
					{ name: 'HMAC', hash: 'SHA-256' },
					true,
					['verify']
				)
				// Decrypt refresh token data
				const refreshData = await decryptProps(encryptedRefreshData.encryptedData, encryptedRefreshData.iv, unwrappedRefreshKey, encryptedRefreshData.hmac, unwrappedHmacKey)
				console.log('🔵 TOKEN: Decrypted refresh data retrieved for user:', refreshData.userId)

				// Generate new access token
				const newAccessToken = crypto.randomUUID()
				console.log('🔵 TOKEN: Generated new access token')

				// Generate new refresh token (rotation)
				const newRefreshToken = crypto.randomUUID()
				console.log('🔵 TOKEN: Generated new refresh token')

				// Store new encrypted access token
				const tokenData = {
					userId: refreshData.userId,
					privyUser: refreshData.privyUser,
					clientId: refreshData.clientId,
					scope: refreshData.scope,
					createdAt: Date.now(),
				}

				// Encrypt access token data
				const { encryptedData: newEncAccessData, iv: newAccessIv, key: newAccessKey, hmac: newAccessHmac, hmacKey: newAccessHmacKey } = await encryptProps(tokenData)
				const newWrappedAccessKey = await wrapKeyWithToken(newAccessToken, newAccessKey, c.env)
				const newWrappedHmacKey = await wrapKeyWithToken(newAccessToken, newAccessHmacKey, c.env)
				const newEncryptedTokenData = { encryptedData: newEncAccessData, iv: newAccessIv, wrappedKey: newWrappedAccessKey, hmac: newAccessHmac, hmacKey: newWrappedHmacKey }
				await secureKvPut(c.env, `access_token:${await hashSecret(newAccessToken)}`, JSON.stringify(newEncryptedTokenData), 18000)
				console.log('🔵 TOKEN: Encrypted access token (new) stored')

				// Store new encrypted refresh token
				const newRefreshData = {
					userId: refreshData.userId,
					privyUser: refreshData.privyUser,
					clientId: refreshData.clientId,
					scope: refreshData.scope,
					previousRefreshToken: await hashSecret(refreshToken),
					createdAt: Date.now(),
				}

				// Encrypt refresh token data
				const { encryptedData: newEncRefreshData, iv: newRefreshIv, key: newRefreshKey, hmac: newRefreshHmac, hmacKey: newRefreshHmacKey } = await encryptProps(newRefreshData)
				const newWrappedRefreshKey = await wrapKeyWithToken(newRefreshToken, newRefreshKey, c.env)
				const newWrappedRefreshHmacKey = await wrapKeyWithToken(newRefreshToken, newRefreshHmacKey, c.env)
				const newEncryptedRefreshData = { encryptedData: newEncRefreshData, iv: newRefreshIv, wrappedKey: newWrappedRefreshKey, hmac: newRefreshHmac, hmacKey: newWrappedRefreshHmacKey }
				await secureKvPut(c.env, `refresh_token:${await hashSecret(newRefreshToken)}`, JSON.stringify(newEncryptedRefreshData), 2592000)
				console.log('🔵 TOKEN: Encrypted refresh token (new) stored')

				// Invalidate old refresh token after successful rotation
				await c.env.OAUTH_KV.delete(`refresh_token:${await hashSecret(refreshToken)}`)
				console.log('🔵 TOKEN: Old refresh token invalidated')

				// Return new access token and refresh token
				return c.json({
					access_token: newAccessToken,
					token_type: 'Bearer',
					expires_in: 36000,
					refresh_token: newRefreshToken,
					scope: refreshData.scope,
				})
			}

			// Handle authorization_code grant type
			if (grantType !== 'authorization_code') {
				console.error('🔴 TOKEN ERROR: Unsupported grant type:', grantType)
				return c.json({ error: 'unsupported_grant_type', error_description: 'The authorization grant type is not supported by the authorization server.' }, 400)
			}

			if (!code || !clientId || !codeVerifier) {
				console.error('🔴 TOKEN ERROR: Missing required parameters (code, clientId, codeVerifier)')
				return c.json({ error: 'invalid_request', error_description: 'Missing required parameters (code, client_id, code_verifier).' }, 400)
			}

			// Retrieve auth data from KV
			const authDataStr = await c.env.OAUTH_KV.get(`auth_code:${code}`)
			if (!authDataStr) {
				console.error('🔴 TOKEN ERROR: Invalid or expired authorization code')
				return c.json({ error: 'invalid_grant' }, 400)
			}

			// Decrypt auth data
			const encryptedAuthData = JSON.parse(authDataStr)
			const unwrappedKey = await crypto.subtle.unwrapKey(
				'raw',
				base64ToArrayBuffer(encryptedAuthData.wrappedKey),
				await deriveKeyFromToken(code, c.env),
				{ name: 'AES-KW' },
				{ name: 'AES-GCM' },
				false,
				['decrypt']
			)

			const unwrappedHmacKey = await crypto.subtle.unwrapKey(
				'raw',
				base64ToArrayBuffer(encryptedAuthData.hmacKey),
				await deriveKeyFromToken(code, c.env),
				{ name: 'AES-KW' },
				{ name: 'HMAC', hash: 'SHA-256' },
				true,
				['verify']
			)



			const authData = await decryptProps(encryptedAuthData.encryptedData, encryptedAuthData.iv, unwrappedKey, encryptedAuthData.hmac, unwrappedHmacKey)
			console.log('✅ TOKEN: Decrypted auth data for User:', authData.userId)

			// Validate PKCE
			if (authData.codeChallenge && authData.codeChallengeMethod === 'S256') {
				const encoder = new TextEncoder()
				const data = encoder.encode(codeVerifier)
				const digest = await crypto.subtle.digest('SHA-256', data)
				const base64Digest = btoa(String.fromCharCode(...new Uint8Array(digest)))
					.replace(/\+/g, '-')
					.replace(/\//g, '_')
					.replace(/=/g, '')

				if (base64Digest !== authData.codeChallenge) {
					console.error('🔴 TOKEN ERROR: PKCE validation failed')
					return c.json({ error: 'invalid_grant', error_description: 'PKCE validation failed.' }, 400)
				}
				console.log('🛡️  TOKEN: Validated PKCE')
			}

			// Enhanced client validation with explicit caching support
			const validateClientCredentials = (authData: any, receivedClientId: string | null, receivedRedirectUri: string | null) => {

				// Check if we have client validation metadata (from newer auth flows)
				const clientValidation = authData.clientValidation || {}

				// Scenario 1: Perfect match - ideal case
				if (authData.clientId === receivedClientId && authData.redirectUri === receivedRedirectUri) {
					console.log('✅ TOKEN: Perfect match - client ID and redirect URI both match exactly')
					return { isValid: true, reason: 'exact_match' }
				}

				// Scenario 2: Redirect URI matches but client ID differs - common with OAuth client caching
				if (authData.redirectUri === receivedRedirectUri) {

					// Check if flexibility is enabled:
					// 1. Check strictMode
					// 2. Check stored client validation metadata (default true for better UX)
					const allowFlexibility = !strictMode && (clientValidation.allowClientIdFlexibility !== false)

					if (allowFlexibility) {
						console.log('📝 TOKEN: Client ID flexibility enabled - allowing mismatch with redirect URI match')
						return { isValid: true, reason: 'redirect_uri_match_with_pkce' }
					} else {
						console.log('❌ TOKEN: Client ID flexibility disabled - strict validation required')
						console.log('🔧 TOKEN: Configuration - AuthHandler strictMode is enabled')
						console.log('📋 TOKEN: To enable flexibility for cached clients, set strictMode to "false"')
						return { isValid: false, reason: 'strict_validation_failed' }
					}
				}

				// Scenario 3: Both mismatch - security violation
				console.error('❌ TOKEN: Security violation - both client ID and redirect URI mismatch')
				console.error('  This indicates either:')
				console.error('  1. Attempt to use authorization code with wrong client')
				console.error('  2. Authorization code replay attack')
				console.error('  3. Client configuration error')
				return { isValid: false, reason: 'complete_mismatch' }
			}

			// Perform enhanced client validation
			const validationResult = validateClientCredentials(authData, clientId, redirectUri)

			if (!validationResult.isValid) {
				console.error('🔴 TOKEN ERROR: Client validation failed')
				console.error('  Reason:', validationResult.reason)
				console.error('  Client ID match:', authData.clientId === clientId)
				console.error('  Redirect URI match:', authData.redirectUri === redirectUri)

				let errorDescription = 'Client validation failed.'
				if (validationResult.reason === 'complete_mismatch') {
					errorDescription = 'Both client ID and redirect URI mismatch. This may indicate a security violation.'
				} else if (validationResult.reason === 'strict_validation_failed') {
					errorDescription = 'Client ID mismatch not allowed in strict validation mode.'
				}

				return c.json({
					error: 'invalid_grant',
					error_description: errorDescription
				}, 400)
			}

			// Generate access token
			const accessToken = crypto.randomUUID()

			// Store token data in KV
			const tokenData = {
				userId: authData.privyUser.id,
				privyUser: authData.privyUser,
				clientId: authData.clientId,
				scope: authData.scope,
				createdAt: Date.now(),
			}

			// Encrypt access token data
			const { encryptedData: encAccessData, iv: accessIv, key: accessKey, hmac: accessHmac, hmacKey: accessHmacKey } = await encryptProps(tokenData)
			const wrappedAccessKey = await wrapKeyWithToken(accessToken, accessKey, c.env)
			const wrappedAccessHmacKey = await wrapKeyWithToken(accessToken, accessHmacKey, c.env)
			const encryptedTokenData = { encryptedData: encAccessData, iv: accessIv, wrappedKey: wrappedAccessKey, hmac: accessHmac, hmacKey: wrappedAccessHmacKey }
			await secureKvPut(c.env, `access_token:${await hashSecret(accessToken)}`, JSON.stringify(encryptedTokenData), 36000)

			// Generate refresh token
			const newRefreshToken = crypto.randomUUID()
			const refreshData = {
				userId: authData.userId,
				privyUser: authData.privyUser,
				clientId: authData.clientId,
				scope: authData.scope,
				createdAt: Date.now(),
			}

			// Encrypt refresh token data
			const { encryptedData: encRefreshData, iv: refreshIv, key: refreshKey, hmac: refreshHmac, hmacKey: refreshHmacKey } = await encryptProps(refreshData)
			const wrappedRefreshKey = await wrapKeyWithToken(newRefreshToken, refreshKey, c.env)
			const wrappedRefreshHmacKey = await wrapKeyWithToken(newRefreshToken, refreshHmacKey, c.env)
			const encryptedRefreshData = { encryptedData: encRefreshData, iv: refreshIv, wrappedKey: wrappedRefreshKey, hmac: refreshHmac, hmacKey: wrappedRefreshHmacKey }
			await secureKvPut(c.env, `refresh_token:${await hashSecret(newRefreshToken)}`, JSON.stringify(encryptedRefreshData), 2592000)
			console.log('🛡️  TOKEN: Encrypted Access, Identity, and Refresh tokens stored in KV')

			// Clean up authorization code
			await c.env.OAUTH_KV.delete(`auth_code:${code}`)

			// Return access token and refresh token
			return c.json({
				access_token: accessToken,
				token_type: 'Bearer',
				expires_in: 36000,
				refresh_token: newRefreshToken,
				scope: authData.scope,
			})
		} catch (error) {
			console.error('🔴 TOKEN ERROR: Token exchange failed:', error)
			return c.json({
				error: 'server_error',
				error_description: `An unexpected error occurred: ${error instanceof Error ? error.message : String(error)}`
			}, 500)
		}
	})

	// Client Registration (OAuth Dynamic Registration)
	app.post('/reg', async (c) => {
		try {
			const body = await c.req.json()

			// Validate required fields per RFC 7591
			if (!body.redirect_uris || !Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0) {
				console.error('🔴 REG ERROR: Missing or invalid redirect_uris')
				return c.json({ error: 'invalid_client_metadata' }, 400)
			}

			// Generate client ID and secret
			const clientId = crypto.randomUUID()
			const clientSecret = crypto.randomUUID()
			const hashedSecret = await hashSecret(clientSecret)
			const clientData = {
				...body,
				client_id: clientId,
				client_secret: hashedSecret,
				client_id_issued_at: Math.floor(Date.now() / 1000)
			}

			// Encrypt client data	
			const { encryptedData: encClientData, iv: clientIv, key: clientKey, hmac: clientHmac, hmacKey: clientHmacKey } = await encryptProps(clientData)
			const wrappedClientKey = await wrapKeyWithToken(clientId, clientKey, c.env)
			const wrappedClientHmacKey = await wrapKeyWithToken(clientId, clientHmacKey, c.env)
			const encryptedClientData = { encryptedData: encClientData, iv: clientIv, wrappedKey: wrappedClientKey, hmac: clientHmac, hmacKey: wrappedClientHmacKey }
			await secureKvPut(c.env, `client:${clientId}`, JSON.stringify(encryptedClientData), 86400)
			console.log('✅ REG: Stored encrypted client data in KV')
			return c.json({ ...clientData, client_secret: clientSecret })
		} catch (error) {
			console.error('🔴 REG ERROR: Client registration failed:', error)
			return c.json({ error: 'server_error' }, 500)
		}
	})

	// Token Revocation / Logout
	app.post('/revoke', async (c) => {
		try {
			const body = await c.req.text()
			const params = new URLSearchParams(body)
			const token = params.get('token')
			const revokeAll = params.get('revoke_all') === 'true'

			if (!token) {
				return c.json({ error: 'invalid_request' }, 400)
			}

			await revokeToken(c.env, token, revokeAll)

			return c.json({ message: revokeAll ? 'All user tokens revoked' : 'Token revoked' })
		} catch (error) {
			console.error('🔴 REVOKE ERROR: Token revocation failed:', error)
			return c.json({
				error: 'server_error',
				details: error instanceof Error ? error.message : String(error)
			}, 500)
		}
	})

	// NEW: Handle DELETE /mcp by triggering token revocation (reuses /revoke logic)
	app.delete('/mcp', requireAuth, async (c) => {
		try {
			// Extract Bearer token from header
			const authHeader = c.req.header('Authorization')
			if (!authHeader || !authHeader.startsWith('Bearer ')) {
				return c.json({ error: 'invalid_token' }, 401)
			}
			const token = authHeader.substring(7)

			// Revoke the specific token (not all)
			await revokeToken(c.env, token, false)

			// Return 204 No Content
			return c.json({ message: 'User tokens revoked' })
		} catch (error) {
			console.error('🔴 MCP ERROR: DELETE /mcp failed:', error)
			return c.text('Internal Server Error', 500)
		}
	})
}

// Cryptographic Functions
async function hashSecret(secret: string): Promise<string> {
	const encoder = new TextEncoder()
	const data = encoder.encode(secret)
	const hashBuffer = await crypto.subtle.digest('SHA-256', data)
	const hashArray = Array.from(new Uint8Array(hashBuffer))
	return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

// Encrypt properties
async function encryptProps(data: any): Promise<{ encryptedData: string; iv: string; key: CryptoKey; hmac: string; hmacKey: CryptoKey }> {
	const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']) as CryptoKey
	const iv = crypto.getRandomValues(new Uint8Array(12)) // Generate random IV for security
	const jsonData = JSON.stringify(data)
	const encoder = new TextEncoder()
	const encodedData = encoder.encode(jsonData)
	const encryptedBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encodedData)

	// HMAC for integrity check
	const hmacKey = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, true, ['sign', 'verify'])
	const hmac = await crypto.subtle.sign('HMAC', hmacKey, encryptedBuffer)
	const hmacBase64 = arrayBufferToBase64(hmac)

	return {
		encryptedData: arrayBufferToBase64(encryptedBuffer),
		iv: arrayBufferToBase64(iv),
		key,
		hmac: hmacBase64,
		hmacKey
	}
}

// Decrypt properties
async function decryptProps(encryptedData: string, iv: string, key: CryptoKey, hmac: string, hmacKey: CryptoKey): Promise<any> {
	const encryptedBuffer = base64ToArrayBuffer(encryptedData)
	const ivBuffer = base64ToArrayBuffer(iv)

	// Verify HMAC
	const isValid = await crypto.subtle.verify('HMAC', hmacKey, base64ToArrayBuffer(hmac), encryptedBuffer)
	if (!isValid) {
		throw new Error('HMAC verification failed - data tampered')
	}

	const decryptedBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBuffer }, key, encryptedBuffer)
	const decoder = new TextDecoder()
	const jsonData = decoder.decode(decryptedBuffer)
	return JSON.parse(jsonData)
}

// Convert base64 to array buffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
	const binaryString = atob(base64)
	const bytes = new Uint8Array(binaryString.length)
	for (let i = 0; i < binaryString.length; i++) {
		bytes[i] = binaryString.charCodeAt(i)
	}
	return bytes.buffer
}

// Convert array buffer to base64
function arrayBufferToBase64(buffer: ArrayBuffer): string {
	return btoa(String.fromCharCode(...Array.from(new Uint8Array(buffer))))
}

// Wrap key with token
async function wrapKeyWithToken(tokenStr: string, keyToWrap: CryptoKey, env: Env): Promise<string> {
	const wrappingKey = await deriveKeyFromToken(tokenStr, env)
	const wrappedKeyBuffer = await crypto.subtle.wrapKey('raw', keyToWrap, wrappingKey, { name: 'AES-KW' })
	return arrayBufferToBase64(wrappedKeyBuffer)
}

// Derive key from token
async function deriveKeyFromToken(tokenStr: string, env: Env): Promise<CryptoKey> {
	const encoder = new TextEncoder()
	const salt = encoder.encode(env.KDF_SALT)
	const keyMaterial = await crypto.subtle.importKey(
		'raw',
		encoder.encode(tokenStr),
		{ name: 'PBKDF2' },
		false,
		['deriveKey']
	)
	return await crypto.subtle.deriveKey(
		{
			name: 'PBKDF2',
			salt: salt,
			iterations: 100000,
			hash: 'SHA-256'
		},
		keyMaterial,
		{ name: 'AES-KW', length: 256 },
		false,
		['wrapKey', 'unwrapKey']
	)
}

// Shared revocation function
export async function revokeToken(env: Env, token: string, revokeAll: boolean = false) {
	try {
		const hashedToken = await hashSecret(token)

		// Revoke specific token
		await env.OAUTH_KV.delete(`access_token:${hashedToken}`)
		await env.OAUTH_KV.delete(`refresh_token:${hashedToken}`)
		await env.OAUTH_KV.delete(`auth_code:${hashedToken}`)

		if (revokeAll) {
			// Fetch and decrypt to get userId
			let tokenDataStr = await env.OAUTH_KV.get(`access_token:${hashedToken}`) ||
				await env.OAUTH_KV.get(`refresh_token:${hashedToken}`)
			if (tokenDataStr) {
				const encryptedTokenData = JSON.parse(tokenDataStr);
				const unwrappedKey = await crypto.subtle.unwrapKey('raw', base64ToArrayBuffer(encryptedTokenData.wrappedKey), await deriveKeyFromToken(token, env), { name: 'AES-KW' }, { name: 'AES-GCM' }, false, ['decrypt'])
				const unwrappedHmacKey = await crypto.subtle.unwrapKey('raw', base64ToArrayBuffer(encryptedTokenData.hmacKey), await deriveKeyFromToken(token, env), { name: 'AES-KW' }, { name: 'HMAC', hash: 'SHA-256' }, true, ['verify'])
				const tokenData = await decryptProps(encryptedTokenData.encryptedData, encryptedTokenData.iv, unwrappedKey, encryptedTokenData.hmac, unwrappedHmacKey)
				const userId = tokenData.privyUser.id
				await env.OAUTH_KV.put(`revoked_user:${userId}`, Date.now().toString(), { expirationTtl: 2592000 })
			}
		}

		console.log(`🛡️  MCP: Disconnected and revoked user token${revokeAll ? ' and all user tokens' : ''}`)
	} catch (error) {
		console.error('🔴 Revoke token failed:', error)
		throw error
	}
}
