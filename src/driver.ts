import { randomBytes } from 'node:crypto'
import { type ApiRequest, Oauth2Driver } from '@adonisjs/ally'
import type {
  AllyDriverContract,
  AllyUserContract,
  ApiRequestContract,
  RedirectRequestContract,
} from '@adonisjs/ally/types'
import type { HttpContext } from '@adonisjs/core/http'
import { CLIENT_ASSERTION_TYPE, createClientAssertion } from './client_assertion.js'
import { assertValidConfig, LOGIN_URL } from './config.js'
import { E_ENTRA_TOKEN_REFRESH_FAILED, type EntraTokenErrorDetails } from './errors.js'
import { verifyIdToken } from './id_token.js'
import type {
  EntraAccessToken,
  EntraCertificate,
  EntraConfig,
  EntraRefreshedToken,
  EntraScopes,
  EntraUser,
} from './types.js'

const GRAPH_ME_URL = 'https://graph.microsoft.com/v1.0/me'

/**
 * Ally driver for Microsoft Entra ID.
 */
export class EntraDriver
  extends Oauth2Driver<EntraAccessToken, EntraScopes>
  implements AllyDriverContract<EntraAccessToken, EntraScopes>
{
  protected authorizeUrl: string
  protected accessTokenUrl: string
  protected userInfoUrl = GRAPH_ME_URL

  protected codeParamName = 'code'
  protected errorParamName = 'error'
  protected stateParamName = 'state'
  protected scopeParamName = 'scope'
  protected scopesSeparator = ' '

  protected stateCookieName = 'entra_oauth_state'

  /**
   * Defining this cookie name enables PKCE in Ally.
   */
  protected codeVerifierCookieName = 'entra_oauth_code_verifier'

  protected nonceCookieName = 'entra_oauth_nonce'

  /**
   * Nonce read from the cookie when the user comes back from Microsoft.
   */
  #nonce?: string

  /**
   * Ally expects a string here, which stays empty with a certificate.
   */
  declare config: Omit<EntraConfig, 'clientSecret' | 'certificate'> & {
    clientSecret: string
    certificate?: EntraCertificate
  }

  constructor(ctx: HttpContext, config: EntraConfig) {
    super(ctx, { ...config, clientSecret: config.clientSecret ?? '' } as EntraDriver['config'])
    assertValidConfig(config)

    this.authorizeUrl = `${LOGIN_URL}/${config.tenantId}/oauth2/v2.0/authorize`
    this.accessTokenUrl = `${LOGIN_URL}/${config.tenantId}/oauth2/v2.0/token`

    /**
     * Reads then clears the state and PKCE cookies. Do not remove.
     */
    this.loadState()

    this.#nonce = ctx.request.encryptedCookie(this.nonceCookieName)
    ctx.response.clearCookie(this.nonceCookieName)
  }

  protected configureRedirectRequest(request: RedirectRequestContract<EntraScopes>) {
    const nonce = randomBytes(32).toString('base64url')
    this.ctx.response.encryptedCookie(this.nonceCookieName, nonce, {
      sameSite: false,
      httpOnly: true,
    })

    request.scopes(['openid', 'profile', 'email', 'User.Read'])
    request.param('response_type', 'code')
    request.param('nonce', nonce)
  }

  protected configureAccessTokenRequest(request: ApiRequestContract) {
    this.#authenticateClient(request, this.config.accessTokenUrl || this.accessTokenUrl)
  }

  /**
   * Proves the application identity with the certificate, or the client secret.
   */
  #authenticateClient(request: ApiRequestContract, tokenUrl: string) {
    const { certificate, clientId, clientSecret } = this.config

    if (!certificate) {
      request.field('client_secret', clientSecret)
      return
    }

    request.clearField('client_secret')
    request.field('client_assertion_type', CLIENT_ASSERTION_TYPE)
    request.field(
      'client_assertion',
      createClientAssertion(certificate, { clientId, audience: tokenUrl })
    )
  }

  accessDenied() {
    return this.ctx.request.input(this.errorParamName) === 'access_denied'
  }

  /**
   * A return without the nonce cookie cannot be validated, so it is refused
   * like a missing state cookie.
   */
  stateMisMatch() {
    return super.stateMisMatch() || (!this.isStateless && !this.#nonce)
  }

  /**
   * Exchanges the authorization code for tokens and validates the ID token.
   */
  async accessToken(callback?: (request: ApiRequestContract) => void) {
    const token = await super.accessToken(callback)
    const idTokenClaims = await verifyIdToken(token.id_token, {
      clientId: this.config.clientId,
      tenantId: this.config.tenantId,
      allowedTenants: this.config.allowedTenants,
      nonce: this.#nonce,
    })

    return { ...token, idTokenClaims }
  }

  /**
   * Exchanges a refresh token for new tokens. It requires the `offline_access`
   * scope at sign-in, and the returned `refreshToken` must replace the old one.
   */
  async refreshAccessToken(
    refreshToken: string,
    callback?: (request: ApiRequestContract) => void
  ): Promise<EntraRefreshedToken> {
    if (!refreshToken) {
      throw new E_ENTRA_TOKEN_REFRESH_FAILED({ error: 'missing_refresh_token' })
    }

    const tokenUrl = this.config.accessTokenUrl || this.accessTokenUrl
    const request = this.httpClient(tokenUrl)
    request.parseAs('json')
    request.field('grant_type', 'refresh_token')
    request.field('client_id', this.config.clientId)
    request.field('refresh_token', refreshToken)
    this.#authenticateClient(request, tokenUrl)

    if (typeof callback === 'function') {
      callback(request)
    }

    const body = await this.#postTokenRequest(request)
    if (!body.access_token) {
      throw new E_ENTRA_TOKEN_REFRESH_FAILED()
    }

    return {
      token: body.access_token,
      type: body.token_type,
      expiresIn: body.expires_in,
      expiresAt: body.expires_in ? new Date(Date.now() + body.expires_in * 1000) : undefined,
      refreshToken: body.refresh_token ?? refreshToken,
      scope: body.scope,
    }
  }

  /**
   * Sends a token request and turns a refusal into a typed error.
   */
  async #postTokenRequest(request: ApiRequest) {
    try {
      return await request.post()
    } catch (error) {
      const response: Response | undefined = (error as { response?: Response }).response
      const details = await response?.json().catch(() => undefined)
      throw new E_ENTRA_TOKEN_REFRESH_FAILED((details ?? {}) as EntraTokenErrorDetails, {
        cause: error,
      })
    }
  }

  /**
   * Fetches the signed-in user from Microsoft Graph and maps the response
   * to the Ally user format.
   */
  protected async getUserInfo(token: string, callback?: (request: ApiRequestContract) => void) {
    const request = this.httpClient(this.config.userInfoUrl || this.userInfoUrl)
    request.header('Authorization', `Bearer ${token}`)
    request.header('Accept', 'application/json')
    request.parseAs('json')

    /**
     * Called last, so that the caller can override the request.
     */
    if (typeof callback === 'function') {
      callback(request)
    }

    const body = await request.get()
    const name: string = body.displayName ?? body.userPrincipalName

    return {
      id: body.id as string,
      nickName: name,
      name,
      email: (body.mail ?? null) as string | null,
      emailVerificationState: 'unsupported' as const,
      avatarUrl: null,
      original: body,
    }
  }

  /**
   * Returns the signed-in user, with the tenant, roles and groups read from
   * the validated ID token.
   */
  async user(callback?: (request: ApiRequestContract) => void): Promise<EntraUser> {
    const token = await this.accessToken(callback)
    const user = await this.getUserInfo(token.token, callback)
    const claims = token.idTokenClaims

    return {
      ...user,
      tenantId: claims.tid,
      roles: claims.roles ?? [],
      groups: claims.groups ?? [],
      hasGroupsOverage: Boolean(claims.hasgroups || claims._claim_names?.groups),
      token,
    }
  }

  /**
   * Returns the user that owns an existing access token. There is no ID token
   * here, so the tenant, roles and groups are not available.
   */
  async userFromToken(
    accessToken: string,
    callback?: (request: ApiRequestContract) => void
  ): Promise<AllyUserContract<{ token: string; type: 'bearer' }>> {
    const user = await this.getUserInfo(accessToken, callback)

    return { ...user, token: { token: accessToken, type: 'bearer' } }
  }
}

/**
 * The factory function to reference the driver inside the "config/ally.ts" file.
 */
export function EntraService(config: EntraConfig): (ctx: HttpContext) => EntraDriver {
  assertValidConfig(config)
  return (ctx) => new EntraDriver(ctx, config)
}
