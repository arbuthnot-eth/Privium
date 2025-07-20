export default {
  async fetch(request) {
    const url = new URL(request.url);
    const backendBase = import.meta.env.VITE_BACKEND_URL; // Replace with your backend URL

    if (url.pathname === '/.well-known/oauth-authorization-server') {
      return Response.json({
        issuer: url.origin,
        authorization_endpoint: `${url.origin}/authorize`,
        token_endpoint: `${url.origin}/token`,
        registration_endpoint: `${url.origin}/reg`, // If DCR supported
        scopes_supported: ['mcp'],
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        code_challenge_methods_supported: ['S256'], // PKCE requirement for MCP/OAuth 2.1
        // Add more per RFC 8414 as needed
      });
    }

    if (url.pathname === '/token' || url.pathname === '/reg') {
      const proxyUrl = new URL(backendBase + url.pathname);
      proxyUrl.search = url.search; // Forward query params if any
      const proxyHeaders = new Headers(request.headers);
      // Optional: Add CORS headers if needed for cross-origin
      proxyHeaders.set('Origin', url.origin); // Spoof origin if backend checks it
      return fetch(proxyUrl, {
        method: request.method,
        headers: proxyHeaders,
        body: request.body,
        redirect: 'manual', // Prevent auto-redirects
      });
    }

    if (url.pathname.startsWith("/api/")) {
      return Response.json({
        name: "Cloudflare",
      });
    }
    // Fallback for static assets/SPA
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;