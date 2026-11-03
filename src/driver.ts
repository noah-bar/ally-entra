/*
|--------------------------------------------------------------------------
| Ally Oauth driver
|--------------------------------------------------------------------------
|
| Make sure you through the code and comments properly and make necessary
| changes as per the requirements of your implementation.
|
*/

import { Oauth2Driver } from '@adonisjs/ally'
import type { HttpContext } from '@adonisjs/core/http'
import type {
  AllyDriverContract,
  AllyUserContract,
  ApiRequestContract,
  RedirectRequestContract,
} from '@adonisjs/ally/types'

/**
 *
 * Access token returned by your driver implementation. An access
 * token must have "token" and "type" properties and you may
 * define additional properties (if needed)
 */
export type EntraAccessToken = {
  token: string
  type: 'bearer'
}

/**
 * Scopes accepted by the driver implementation.
 */
export type EntraScopes = string

/**
 * The configuration accepted by the driver implementation.
 */
export type EntraConfig = {
  clientId: string
  clientSecret: string
  callbackUrl: string
  tenantId: string
  authorizeUrl?: string
  accessTokenUrl?: string
  userInfoUrl?: string
}

/**
 * Driver implementation. It is mostly configuration driven except the API call
 * to get user info.
 */
export class EntraDriver
  extends Oauth2Driver<EntraAccessToken, EntraScopes>
  implements AllyDriverContract<EntraAccessToken, EntraScopes>
{
  /**
   * The URL for the redirect request. The user will be redirected on this page
   * to authorize the request.
   *l
   * Do not define query strings in this URL.
   */
  protected authorizeUrl: string

  /**
   * The URL to hit to exchange the authorization code for the access token
   *
   * Do not define query strings in this URL.
   */
  protected accessTokenUrl: string

  /**
   * The URL to hit to get the user details
   *
   * Do not define query strings in this URL.
   */
  protected userInfoUrl = 'https://graph.microsoft.com/v1.0/me'

  /**
   * The param name for the authorization code. Read the documentation of your oauth
   * provider and update the param name to match the query string field name in
   * which the oauth provider sends the authorization_code post redirect.
   */
  protected codeParamName = 'code'

  /**
   * The param name for the error. Read the documentation of your oauth provider and update
   * the param name to match the query string field name in which the oauth provider sends
   * the error post redirect
   */
  protected errorParamName = 'error'

  /**
   * Cookie name for storing the CSRF token. Make sure it is always unique. So a better
   * approach is to prefix the oauth provider name to `oauth_state` value. For example:
   * For example: "facebook_oauth_state"
   */
  protected stateCookieName = 'entra_oauth_state'

  /**
   * Parameter name to be used for sending and receiving the state from.
   * Read the documentation of your oauth provider and update the param
   * name to match the query string used by the provider for exchanging
   * the state.
   */
  protected stateParamName = 'state'

  /**
   * Parameter name for sending the scopes to the oauth provider.
   */
  protected scopeParamName = 'scope'

  /**
   * The separator indentifier for defining multiple scopes
   */
  protected scopesSeparator = ' '

  constructor(
    ctx: HttpContext,
    public config: EntraConfig
  ) {
    super(ctx, config)

    this.authorizeUrl = `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/authorize`
    this.accessTokenUrl = `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`

    /**
     * Extremely important to call the following method to clear the
     * state set by the redirect request.
     *
     * DO NOT REMOVE THE FOLLOWING LINE
     */
    this.loadState()
  }

  /**
   * Optionally configure the authorization redirect request. The actual request
   * is made by the base implementation of "Oauth2" driver and this is a
   * hook to pre-configure the request.
   */
  protected configureRedirectRequest(request: RedirectRequestContract<EntraScopes>) {
    request.scopes(['openid', 'profile', 'email', 'User.Read'])
    request.param('response_type', 'code')
  }

  /**
   * Optionally configure the access token request. The actual request is made by
   * the base implementation of "Oauth2" driver and this is a hook to pre-configure
   * the request
   */
  // protected configureAccessTokenRequest(request: ApiRequest) {}

  /**
   * Update the implementation to tell if the error received during redirect
   * means "ACCESS DENIED".
   */
  accessDenied() {
    return this.ctx.request.input('error') === 'access_denied'
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
     * Allow end user to configure the request. This should be called after your custom
     * configuration, so that the user can override them (if needed)
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
   * Exchanges the authorization code for tokens and returns the signed-in user.
   */
  async user(
    callback?: (request: ApiRequestContract) => void
  ): Promise<AllyUserContract<EntraAccessToken>> {
    const token = await this.accessToken(callback)
    const user = await this.getUserInfo(token.token, callback)

    return { ...user, token }
  }

  /**
   * Returns the user that owns an existing access token.
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
 * The factory function to reference the driver implementation
 * inside the "config/ally.ts" file.
 */
export function EntraService(config: EntraConfig): (ctx: HttpContext) => EntraDriver {
  return (ctx) => new EntraDriver(ctx, config)
}
