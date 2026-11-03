import { randomBytes } from 'node:crypto'
import { Oauth2Driver } from '@adonisjs/ally'
import type {
  AllyDriverContract,
  AllyUserContract,
  ApiRequestContract,
  RedirectRequestContract,
} from '@adonisjs/ally/types'
import type { HttpContext } from '@adonisjs/core/http'
import { assertValidConfig, LOGIN_URL } from './config.js'
import { verifyIdToken } from './id_token.js'
import type { EntraAccessToken, EntraConfig, EntraScopes, EntraUser } from './types.js'

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

  constructor(
    ctx: HttpContext,
    public config: EntraConfig
  ) {
    super(ctx, config)
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
