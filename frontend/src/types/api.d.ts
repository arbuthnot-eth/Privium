interface RegisterClientResponse {
  client_id: string
  client_secret: string
}

interface ExchangeTokenResponse {
  access_token: string
  token_type: string
  expires_in: number
  refresh_token?: string
  scope?: string
}

interface CompleteAuthResponse {
  redirectTo: string
}