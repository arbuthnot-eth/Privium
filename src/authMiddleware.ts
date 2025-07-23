import { Hono, Context } from 'hono';
import { cors } from 'hono/cors';
import { initPrivyClient } from './mcp_tools';

// Auth Handler
export const authHandler = (app: Hono<{ Bindings: Env }>) => {
	// Add CORS middleware
	app.use('/*', cors({
	origin: '*',
	allowMethods: ['GET', 'POST', 'OPTIONS'],
	allowHeaders: ['Content-Type', 'Authorization', 'mcp-session-id'],
	exposeHeaders: ['mcp-session-id'],
	}));
  
 	// OAuth Discovery Endpoints
	app.get('/.well-known/oauth-authorization-server', (c) => {
	  const url = new URL(c.req.url);
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
	  });
	});
  
	// OAuth Protected Resource Endpoints
	app.get('/.well-known/oauth-protected-resource', (c) => {
	  const url = new URL(c.req.url);
	  return c.json({
		  resource: `${url.origin}/mcp`,
		  authorization_servers: [url.origin],
		  scopes_supported: ['mcp'],
		  bearer_methods_supported: ['header'],
		  resource_documentation: `${url.origin}/mcp`,
	  });
	});
  
	// Authorization Endpoint (serve frontend)
	app.get('/authorize', async (c) => {
	  try {
		  const url = new URL(c.req.url);
		  const indexRequest = new Request(url.origin + '/dist/index.html');
		  const asset = await c.env.ASSETS.fetch(indexRequest);
		  
		  if (asset.ok) {
			  let html = await asset.text();
			  // Inject environment variables into the frontend
			  html = html.replace(
				  '</head>',
				  `<script>
					  window.PRIVY_APP_ID = "${c.env.PRIVY_APP_ID}";
				  </script></head>`
			  );
			  console.log('🔵 FRONTEND: Successfully fetched asset and injected Privy App ID');
			  return c.html(html);
		  } else {
			  console.error('🔴 FRONTEND ERROR: Asset fetch failed, status:', asset.status);
			  return c.text('Frontend not found', 404);
		  }
	  } catch (error) {
		  console.error('🔴 FRONTEND ERROR: Failed to serve frontend:', error);
		  return c.text('Frontend error', 500);
	  }
	});
  
	// Authorization Completion (Privy → OAuth Code)
	app.post('/complete-authorize', async (c) => {
	  try {
		  const body = await c.req.json();
		  console.log('🔵 OAUTH: Request body received:', { 
			  hasAccessToken: !!body.accessToken,
			  hasIdToken: !!body.idToken,
			  client_id: body.client_id,
			  redirect_uri: body.redirect_uri,
			  code_challenge: body.code_challenge ? 'present' : 'missing'
		  });
		  
		  // Get access and identity tokens
		  const token = body.accessToken;
		  const idToken = body.idToken;
		  if (!token) {
			  console.error('🔴 OAUTH ERROR: Missing access token');
			  return c.text('Missing access token', 401);
		  }
		  if (!idToken) {
			  console.error('🔴 OAUTH ERROR: Missing identity token');
			  return c.text('Missing identity token', 401);
		  }
		  
		  // Verify and parse the identity token to get full user data
		  let verifiedClaims;
		  let privyUser;
		  try {
			  const privyClient = initPrivyClient(c.env);
			  verifiedClaims = await privyClient.verifyAuthToken(token);
			  privyUser = await privyClient.getUser({ idToken });
			  console.log('🔵 OAUTH: Privy Identity and Access tokens verified for user:', verifiedClaims.userId);
			  console.log('🔵 OAUTH: User Data:', privyUser);
  
		  } catch (error) {
			  console.error('🔴 OAUTH ERROR: Token verification failed:', error);
			  return c.json({
				  error: 'Invalid token', 
				  details: error instanceof Error ? error.message : String(error) 
			  }, 401);
		  }
  
		  // Generate authorization code
		  const authCode = crypto.randomUUID();
		  
		  // Store the authorization details in KV for later token exchange
		  const authData = {
			  userId: privyUser.id, // Use the Privy user ID for consistency
			  privyUser: privyUser, // Store the full Privy user object
			  clientId: body.client_id,
			  redirectUri: body.redirect_uri,
			  scope: body.scope || 'mcp',
			  codeChallenge: body.code_challenge,
			  codeChallengeMethod: body.code_challenge_method,
			  createdAt: Date.now(),
		  };
		  
		  // Encrypt auth data
		  const { encryptedData, iv, key } = await encryptProps(authData);
		  const wrappedKey = await wrapKeyWithToken(authCode, key);
		  const encryptedAuthData = { encryptedData, iv, wrappedKey };
		  await c.env.OAUTH_KV.put(`auth_code:${authCode}`, JSON.stringify(encryptedAuthData), { expirationTtl: 600 });
		  console.log('🔵 OAUTH: Successfully stored encrypted auth data in KV');
  
		  // Build redirect URL
		  const redirectUrl = new URL(body.redirect_uri);
		  redirectUrl.searchParams.set('code', authCode);
		  if (body.state) {redirectUrl.searchParams.set('state', body.state);}
		  const redirectTo = redirectUrl.toString();
		  console.log('🔵 OAUTH: Redirect URL built:', redirectTo);
  
		  // Return redirect URL
		  return c.json({ redirectTo });
	  } catch (error) {
		  console.error('🔴 OAUTH ERROR: /complete-authorize failed:', error);
		  return c.json({ 
			  error: 'Internal server error', 
			  details: error instanceof Error ? error.message : String(error) 
		  }, 500);
	  }
	});
  
	// Token Exchange (OAuth Code → Bearer Token + Refresh Token)
	app.post('/token', async (c) => {
	  try {
		  const authHeader = c.req.header('Authorization');
		  let clientId: string | null = null;
		  let clientSecret: string | null = null;
  
		  if (authHeader && authHeader.startsWith('Basic ')) {
			  const encoded = authHeader.substring(6);
			  const decoded = atob(encoded);
			  const [basicClientId, basicClientSecret] = decoded.split(':');
			  clientId = basicClientId;
			  clientSecret = basicClientSecret;
			  console.log('🔵 TOKEN: Basic Auth client_id:', clientId);
		  }
  
		  // Get request body
		  const body = await c.req.text();
		  const params = new URLSearchParams(body);
		  // Get grant type, code, code verifier, redirect URI, and refresh token
		  const grantType = params.get('grant_type');
		  const code = params.get('code');
		  const codeVerifier = params.get('code_verifier');
		  const redirectUri = params.get('redirect_uri');
		  const refreshToken = params.get('refresh_token');
  
		  // If client_id was not in Basic Auth, try to get it from the body
		  if (!clientId) {
			  clientId = params.get('client_id');
		  }
		  // If client_secret was not in Basic Auth, try to get it from the body
		  if (!clientSecret) {
			  clientSecret = params.get('client_secret');
		  }
  
		  console.log('🔵 TOKEN: Exchange request received');
  
		  // Handle refresh_token grant type
		  if (grantType === 'refresh_token') {
			  if (!refreshToken) {
				  console.error('🔴 TOKEN ERROR: Missing refresh_token');
				  return c.json({ error: 'invalid_request' }, 400);
			  }
  
			  // Retrieve refresh token data from KV
			  const refreshDataStr = await c.env.OAUTH_KV.get(`refresh_token:${await hashSecret(refreshToken)}`);
			  if (!refreshDataStr) {
			   console.error('🔴 TOKEN ERROR: Invalid or expired refresh token');
			   return c.json({ error: 'invalid_grant' }, 400);
			  }
  
			  // Decrypt refresh token data
			  const encryptedRefreshData = JSON.parse(refreshDataStr);
			  const unwrappedRefreshKey = await crypto.subtle.unwrapKey(
				  'raw',
				  base64ToArrayBuffer(encryptedRefreshData.wrappedKey),
				  await deriveKeyFromToken(refreshToken),
				  { name: 'AES-KW' },
				  { name: 'AES-GCM' },
				  false,
				  ['decrypt']
			  );
			  // Decrypt refresh token data
			  const refreshData = await decryptProps(encryptedRefreshData.encryptedData, encryptedRefreshData.iv, unwrappedRefreshKey);
			  console.log('🔵 TOKEN: Decrypted refresh data retrieved for user:', refreshData.userId);
  
			  // Generate new access token
			  const newAccessToken = crypto.randomUUID();
			  console.log('🔵 TOKEN: Generated new access token');
  
			  // Generate new refresh token (rotation)
			  const newRefreshToken = crypto.randomUUID();
			  console.log('🔵 TOKEN: Generated new refresh token');
  
			  // Store new encrypted access token
			  const tokenData = {
				  userId: refreshData.userId,
				  privyUser: refreshData.privyUser,
				  clientId: refreshData.clientId,
				  scope: refreshData.scope,
				  createdAt: Date.now(),
			  };
  
			  // Encrypt access token data
			  const { encryptedData: newEncAccessData, iv: newAccessIv, key: newAccessKey } = await encryptProps(tokenData);
			  const newWrappedAccessKey = await wrapKeyWithToken(newAccessToken, newAccessKey);
			  const newEncryptedTokenData = { encryptedData: newEncAccessData, iv: newAccessIv, wrappedKey: newWrappedAccessKey };
			  await c.env.OAUTH_KV.put(`access_token:${await hashSecret(newAccessToken)}`, JSON.stringify(newEncryptedTokenData), { expirationTtl: 36000 });
			  console.log('🔵 TOKEN: Encrypted access token (new) stored');
  
			  // Store new encrypted refresh token
			  const newRefreshData = {
				  userId: refreshData.userId,
				  privyUser: refreshData.privyUser,
				  clientId: refreshData.clientId,
				  scope: refreshData.scope,
				  previousRefreshToken: await hashSecret(refreshToken),
				  createdAt: Date.now(),
			  };
  
			  // Encrypt refresh token data
			  const { encryptedData: newEncRefreshData, iv: newRefreshIv, key: newRefreshKey } = await encryptProps(newRefreshData);
			  const newWrappedRefreshKey = await wrapKeyWithToken(newRefreshToken, newRefreshKey);
			  const newEncryptedRefreshData = { encryptedData: newEncRefreshData, iv: newRefreshIv, wrappedKey: newWrappedRefreshKey };
			  await c.env.OAUTH_KV.put(`refresh_token:${await hashSecret(newRefreshToken)}`, JSON.stringify(newEncryptedRefreshData));
			  console.log('🔵 TOKEN: Encrypted refresh token (new) stored');
  
			  // Invalidate old refresh token after successful rotation
			  await c.env.OAUTH_KV.delete(`refresh_token:${await hashSecret(refreshToken)}`);
			  console.log('🔵 TOKEN: Old refresh token invalidated');
  
			  // Return new access token and refresh token
			  return c.json({
				  access_token: newAccessToken,
				  token_type: 'Bearer',
				  expires_in: 36000,
				  refresh_token: newRefreshToken,
				  scope: refreshData.scope,
			  });
		  }
  
		  // Handle authorization_code grant type
		  if (grantType !== 'authorization_code') {
			  console.error('🔴 TOKEN ERROR: Unsupported grant type:', grantType);
			  return c.json({ error: 'unsupported_grant_type', error_description: 'The authorization grant type is not supported by the authorization server.' }, 400);
		  }
  
		  if (!code || !clientId || !codeVerifier) {
			  console.error('🔴 TOKEN ERROR: Missing required parameters (code, clientId, codeVerifier)');
			  return c.json({ error: 'invalid_request', error_description: 'Missing required parameters (code, client_id, code_verifier).' }, 400);
		  }
		
		  // Retrieve auth data from KV
		  const authDataStr = await c.env.OAUTH_KV.get(`auth_code:${code}`);
		  if (!authDataStr) {
		   console.error('🔴 TOKEN ERROR: Invalid or expired authorization code');
		   return c.json({ error: 'invalid_grant' }, 400);
		  }
  
		  // Decrypt auth data
		  const encryptedAuthData = JSON.parse(authDataStr);
		  const unwrappedKey = await crypto.subtle.unwrapKey(
			  'raw',
			  base64ToArrayBuffer(encryptedAuthData.wrappedKey),
			  await deriveKeyFromToken(code),
			  { name: 'AES-KW' },
			  { name: 'AES-GCM' },
			  false,
			  ['decrypt']
		  );
		  const authData = await decryptProps(encryptedAuthData.encryptedData, encryptedAuthData.iv, unwrappedKey);
		  console.log('🔵 TOKEN: Successfully decrypted auth data for User:', authData.userId);
  
		  // Validate PKCE
		  if (authData.codeChallenge && authData.codeChallengeMethod === 'S256') {
			  const encoder = new TextEncoder();
			  const data = encoder.encode(codeVerifier);
			  const digest = await crypto.subtle.digest('SHA-256', data);
			  const base64Digest = btoa(String.fromCharCode(...new Uint8Array(digest)))
				  .replace(/\+/g, '-')
				  .replace(/\//g, '_')
				  .replace(/=/g, '');
			
			  if (base64Digest !== authData.codeChallenge) {
				  console.error('🔴 TOKEN ERROR: PKCE validation failed');
				  return c.json({ error: 'invalid_grant', error_description: 'PKCE validation failed.' }, 400);
			  }
			  console.log('🔵 TOKEN: Successfully validated PKCE');
		  }
  
		  // Validate client and redirect URI
		  if (authData.clientId !== clientId || authData.redirectUri !== redirectUri) {
			  console.error('🔴 TOKEN ERROR: Client ID or redirect URI mismatch');
			  return c.json({ error: 'invalid_grant', error_description: 'Client ID or redirect URI mismatch.' }, 400);
		  }
  
		  // Generate access token
		  const accessToken = crypto.randomUUID();
		  console.log('🔵 TOKEN: Generated access token for user:', authData.userId);
		  
		  // Store token data in KV
		  const tokenData = {
			  userId: authData.privyUser.id,
			  privyUser: authData.privyUser,
			  clientId: authData.clientId,
			  scope: authData.scope,
			  createdAt: Date.now(),
		  };
		  
		  // Encrypt access token data
		  const { encryptedData: encAccessData, iv: accessIv, key: accessKey } = await encryptProps(tokenData);
		  const wrappedAccessKey = await wrapKeyWithToken(accessToken, accessKey);
		  const encryptedTokenData = { encryptedData: encAccessData, iv: accessIv, wrappedKey: wrappedAccessKey };
		  await c.env.OAUTH_KV.put(`access_token:${await hashSecret(accessToken)}`, JSON.stringify(encryptedTokenData), { expirationTtl: 36000 });

  
		  // Generate refresh token
		  const newRefreshToken = crypto.randomUUID();
		  const refreshData = {
			  userId: authData.userId,
			  privyUser: authData.privyUser,
			  clientId: authData.clientId,
			  scope: authData.scope,
			  createdAt: Date.now(),
		  };
		  
		  // Encrypt refresh token data
		  const { encryptedData: encRefreshData, iv: refreshIv, key: refreshKey } = await encryptProps(refreshData);
		  const wrappedRefreshKey = await wrapKeyWithToken(newRefreshToken, refreshKey);
		  const encryptedRefreshData = { encryptedData: encRefreshData, iv: refreshIv, wrappedKey: wrappedRefreshKey };
		  await c.env.OAUTH_KV.put(`refresh_token:${await hashSecret(newRefreshToken)}`, JSON.stringify(encryptedRefreshData));
		  console.log('🔵 TOKEN: Encrypted Access, Identity, and Refresh tokens stored in KV');
  
		  // Clean up authorization code
		  await c.env.OAUTH_KV.delete(`auth_code:${code}`);
  
		  // Return access token and refresh token
		  return c.json({
			  access_token: accessToken,
			  token_type: 'Bearer',
			  expires_in: 36000,
			  refresh_token: newRefreshToken,
			  scope: authData.scope,
		  });
	  } catch (error) {
		  console.error('🔴 TOKEN ERROR: Token exchange failed:', error);
		  return c.json({ 
			  error: 'server_error', 
			  error_description: `An unexpected error occurred: ${error instanceof Error ? error.message : String(error)}`
		  }, 500);
	  }
	});
  
	// Client Registration (OAuth Dynamic Registration)
	app.post('/reg', async (c) => {
	  try {
		const body = await c.req.json();
		  
		  // Validate required fields per RFC 7591
		  if (!body.redirect_uris || !Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0) {
			  console.error('🔴 REG ERROR: Missing or invalid redirect_uris');
			  return c.json({ error: 'invalid_client_metadata' }, 400);
		}

		// Generate client ID and secret
		const clientId = crypto.randomUUID();
		const clientSecret = crypto.randomUUID();
		const hashedSecret = await hashSecret(clientSecret);
		const clientData = {
		  ...body,
		  client_id: clientId,
		  client_secret: hashedSecret,
		  client_id_issued_at: Math.floor(Date.now() / 1000)
		};

		// Encrypt client data	
		const { encryptedData: encClientData, iv: clientIv, key: clientKey } = await encryptProps(clientData);
		const wrappedClientKey = await wrapKeyWithToken(clientId, clientKey);
		const encryptedClientData = { encryptedData: encClientData, iv: clientIv, wrappedKey: wrappedClientKey };
		await c.env.OAUTH_KV.put(`client:${clientId}`, JSON.stringify(encryptedClientData));
		console.log('🔵 REG: Successfully stored encrypted client data in KV');
		return c.json({...clientData, client_secret: clientSecret});
	  } catch (error) {
		console.error('🔴 REG ERROR: Client registration failed:', error);
		return c.json({error: 'server_error'}, 500);
	  }
	});
	
	// Token Revocation / Logout
	app.post('/revoke', async (c) => {
	  try {
		  const body = await c.req.text();
		  const params = new URLSearchParams(body);
		  const token = params.get('token');
		  
		  if (!token) {
			  return c.json({ error: 'invalid_request' }, 400);
		  }
		  // Hash token for lookup
		  const hashedToken = await hashSecret(token);
		  await c.env.OAUTH_KV.delete(`access_token:${hashedToken}`);
		  await c.env.OAUTH_KV.delete(`refresh_token:${hashedToken}`);
		  await c.env.OAUTH_KV.delete(`auth_code:${hashedToken}`);
		  
		  return c.json({});
	  } catch (error) {
		  console.error('🔴 REVOKE ERROR: Token revocation failed:', error);
		  return c.json({ 
			  error: 'server_error', 
			  details: error instanceof Error ? error.message : String(error) 
		  }, 500);
	  }
	});
}

// Auth middleware
export const requireAuth = async (c: Context<{ Bindings: Env }>, next: any) => {
  // Validate OAuth Bearer token
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('🔴 MCP ERROR: Missing or invalid Authorization header');
    const url = new URL(c.req.url);
    const resourceMetadataUrl = `${url.origin}/.well-known/oauth-protected-resource`;
    c.header('WWW-Authenticate', `Bearer realm="mcp", resource_metadata="${resourceMetadataUrl}"`);
    return c.json({ error: 'invalid_token', error_description: 'Missing or invalid Authorization header.' }, 401);
  }

  const token = authHeader.substring(7); // Remove "Bearer " prefix

  // Hash token for lookup
  const hashedToken = await hashSecret(token);

  // Retrieve token data from KV
  const tokenDataStr = await c.env.OAUTH_KV.get(`access_token:${hashedToken}`);
  if (!tokenDataStr) {
    console.error('🔴 MCP ERROR: Invalid or expired access token');
    c.header('WWW-Authenticate', 'Bearer realm="mcp"');
    return c.text('Unauthorized', 401);
  }

  // Decrypt token data
  const encryptedTokenData = JSON.parse(tokenDataStr);
  const unwrappedTokenKey = await crypto.subtle.unwrapKey(
    'raw',
    base64ToArrayBuffer(encryptedTokenData.wrappedKey),
    await deriveKeyFromToken(token),
    { name: 'AES-KW' },
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );
  const tokenData = await decryptProps(encryptedTokenData.encryptedData, encryptedTokenData.iv, unwrappedTokenKey);
  console.log('🔵 MCP: Successfully validated decrypted token for user:', tokenData.privyUser.id);

  // Set user context
  c.env.privyUser = tokenData.privyUser;

  await next();
};

// Cryptographic Functions
export async function hashSecret(secret: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(secret);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Encrypt properties
export async function encryptProps(data: any): Promise<{ encryptedData: string; iv: string; key: CryptoKey }> {
	const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']) as CryptoKey;
	const iv = crypto.getRandomValues(new Uint8Array(12)); // Generate random IV for security
	const jsonData = JSON.stringify(data);
	const encoder = new TextEncoder();
	const encodedData = encoder.encode(jsonData);
	const encryptedBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encodedData);
	return {
	  encryptedData: arrayBufferToBase64(encryptedBuffer),
	  iv: arrayBufferToBase64(iv),
	  key,
	};
}

// Decrypt properties
export async function decryptProps(encryptedData: string, iv: string, key: CryptoKey): Promise<any> {
	const encryptedBuffer = base64ToArrayBuffer(encryptedData);
	const ivBuffer = base64ToArrayBuffer(iv);
	const decryptedBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBuffer }, key, encryptedBuffer);
	const decoder = new TextDecoder();
	const jsonData = decoder.decode(decryptedBuffer);
	return JSON.parse(jsonData);
}

// Convert base64 to array buffer
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
	const binaryString = atob(base64);
	const bytes = new Uint8Array(binaryString.length);
	for (let i = 0; i < binaryString.length; i++) {
	  bytes[i] = binaryString.charCodeAt(i);
	}
	return bytes.buffer;
}

// Convert array buffer to base64
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
	return btoa(String.fromCharCode(...Array.from(new Uint8Array(buffer))));
}

// Wrap key with token
export async function wrapKeyWithToken(tokenStr: string, keyToWrap: CryptoKey): Promise<string> {
	const wrappingKey = await deriveKeyFromToken(tokenStr);
	const wrappedKeyBuffer = await crypto.subtle.wrapKey('raw', keyToWrap, wrappingKey, { name: 'AES-KW' });
	return arrayBufferToBase64(wrappedKeyBuffer);
}

// Derive key from token
export async function deriveKeyFromToken(tokenStr: string): Promise<CryptoKey> {
	const encoder = new TextEncoder();
	// Use a derived static key from the token string itself for key wrapping
	// In production, you might want to use an environment variable as additional salt
	const salt = encoder.encode('privium-mcp-kdf-salt-v1');
	const keyMaterial = await crypto.subtle.importKey(
	  'raw',
	  encoder.encode(tokenStr),
	  { name: 'PBKDF2' },
	  false,
	  ['deriveKey']
	);
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
	);
}