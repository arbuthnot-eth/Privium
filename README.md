[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/install-mcp?name=Privium(local)&config=eyJ1cmwiOiJodHRwOi8vbG9jYWxob3N0Ojg3ODcvbWNwIn0%3D)


Button to add Privium remote mcp to Cursor

[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/install-mcp?name=Privium&config=eyJ1cmwiOiJodHRwczovL3ByaXZpdW0uaW1iaWJlZC53b3JrZXJzLmRldi9tY3AifQ==)

# Privium - Authenticated MCP Server with Privy Integration

Privium is a secure Model Context Protocol (MCP) server that provides authenticated access to tools and resources with Privy wallet integration. Unlike the basic MCP server examples, Privium implements a full OAuth 2.1 flow with PKCE for secure client authentication.

## Key Features

- **Secure Authentication**: Full OAuth 2.1 implementation with PKCE for secure client authentication
- **Privy Integration**: Built-in support for wallet-based authentication and user management
- **MCP Tools & Resources**: Pre-built tools for calculations, user management, and wallet access
- **Frontend Authorization Flow**: Complete React-based authorization interface
- **Token Management**: Access tokens with refresh token rotation for enhanced security
- **Resource Access**: Direct access to user profiles and wallet information via MCP resources

## Get Started

[![Deploy to Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/arbuthnot-eth/Privium)

This will deploy your MCP server to a URL like: `privium.<your-account>.workers.dev`

Alternatively, you can use the command line to get the project set up locally:
```bash
git clone https://github.com/arbuthnot-eth/Privium.git
cd Privium
npm install
npm run build
```

## Project Structure

- `src/` - Cloudflare Worker backend with MCP server implementation
- `frontend/` - React frontend for authentication and authorization flows
- `src/authMiddleware.ts` - Complete OAuth 2.1 implementation with PKCE
- `src/mcp_tools.ts` - Pre-built MCP tools and resources

## Available MCP Tools

- **Calculator Tools**: Addition, subtraction, multiplication, division operations
- **User Management**: Get current user information and profile data
- **Wallet Access**: Retrieve connected wallet information
- **Greeting Tools**: Simple greeting functionality

## Available MCP Resources

- `user://me` - Complete user profile with all Privy data
- `wallets://me` - User's connected wallets
- `greeting://{name}` - Dynamic greeting generator

## Authentication Flow

1. **Authorization**: Users authenticate via the frontend authorization interface
2. **Token Exchange**: OAuth 2.1 authorization code flow with PKCE
3. **Access**: Clients use Bearer tokens to access MCP tools and resources
4. **Refresh**: Automatic token refresh with secure rotation

## Environment Variables

To run this project, you'll need to set up the following environment variables in your Cloudflare Worker:

- `PRIVY_APP_ID` - Your Privy application ID
- `PRIVY_APP_SECRET` - Your Privy application secret
- `AUTH_PRIVATE_KEY` - Private key for wallet authentication
- `OAUTH_KV` - Cloudflare KV namespace for storing OAuth data

## Connecting MCP Clients

### Cloudflare AI Playground

1. Go to https://playground.ai.cloudflare.com/
2. Enter your deployed MCP server URL (`privium.<your-account>.workers.dev/mcp`)
3. Complete the OAuth authorization flow when prompted
4. Use your MCP tools directly from the playground!

### Claude Desktop

To connect to your MCP server from Claude Desktop, follow [Anthropic's Quickstart](https://modelcontextprotocol.io/quickstart/user) and within Claude Desktop go to Settings > Developer > Edit Config.

Update with this configuration:

```json
{
  "mcpServers": {
    "privium": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://privium.<your-account>.workers.dev/mcp"
      ]
    }
  }
}
```

Restart Claude and you should see the tools become available.

### Cursor

To connect to Privium from Cursor, you can use either the remote or local server:

```json
{
  "Privium": {
    "url": "https://privium.imbibed.workers.dev/mcp"
  },
  "Privium_local": {
    "url": "http://localhost:8787/mcp"
  }
}
```

### Roo Code

To connect to your local Privium server from Roo Code, add the following to your MCP configuration:

```json
{
  "Privium": {
    "type": "streamable-http",
    "url": "http://localhost:8787/mcp",
    "headers": {
      "authorization": "Bearer <your-token-here>"
    }
  }
}
```

## Running Locally

You can run your own MCP Server locally by cloning the repository and using Wrangler:

```bash
git clone https://github.com/arbuthnot-eth/Privium.git
cd Privium
npm install
npm run build
npx wrangler dev
```

This will start the server on `http://localhost:8787` and you can connect to it using any of the above client configurations.

## Customizing Your MCP Server

To add your own tools to the MCP server, define each tool inside the `registerTools()` function in `src/mcp_tools.ts` using `server.registerTool()`.

To add resources, use `server.registerResource()` in the same file.

## Configuration

The server name and version are centralized in `src/config.ts` for consistency across the application. When updating the server name or version, ensure all references are updated accordingly.

## Security Features

- **PKCE Implementation**: Protection against authorization code interception
- **Token Encryption**: All tokens are encrypted at rest in Cloudflare KV
- **Key Wrapping**: Cryptographic key wrapping for enhanced security
- **Token Rotation**: Refresh tokens are rotated to prevent replay attacks
- **Secure Storage**: Encrypted storage of sensitive authentication data

