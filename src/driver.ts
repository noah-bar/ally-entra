import { randomBytes } from 'node:crypto'
import { Oauth2Driver } from '@adonisjs/ally'
import type {
  AllyDriverContract,
  AllyUserContract,
  ApiRequestContract,
  RedirectRequestContract,
} from '@adonisjs/ally/types'
import type { HttpContext } from '@adonisjs/core/http'
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose'
import {
  E_ENTRA_INVALID_CONFIG,
  E_ENTRA_INVALID_ID_TOKEN,
  E_ENTRA_TENANT_NOT_ALLOWED,
} from './errors.js'

const LOGIN_URL = 'https://login.microsoftonline.com'
const GRAPH_ME_URL = 'https://graph.microsoft.com/v1.0/me'

/**
 * Authorities accepting accounts from several tenants.
 */
const SHARED_AUTHORITIES = ['common', 'organizations', 'consumers']
const TENANT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/**
 * Tolerated difference between this server clock and the Microsoft one.
 */
const CLOCK_TOLERANCE_SECONDS = 60

/**
 * Claims of an ID token that passed validation.
 */
export type EntraIdTokenClaims = JWTPayload & {
  tid: string
  oid?: string
  name?: string
  email?: string
  preferred_username?: string
  roles?: string[]
  groups?: string[]
  hasgroups?: boolean
  _claim_names?: { groups?: string }
}

/**
 * Tokens returned by Microsoft, with the validated ID token claims.
 */
export type EntraAccessToken = {
  token: string
  type: string
  expiresIn?: number
  expiresAt?: Date
  /**
   * Only returned when the `offline_access` scope is requested.
   */
  refreshToken?: string
  scope?: string
  id_token: string
  idTokenClaims: EntraIdTokenClaims
}

export type EntraScopes = string

export type EntraConfig = {
  clientId: string
  clientSecret: string
  callbackUrl: string
  /**
   * The Directory (tenant) ID as a GUID, to accept a single tenant. Or one of
   * `common`, `organizations` and `consumers`, which require `allowedTenants`.
   */
  tenantId: string
  /**
   * The tenant IDs accepted when `tenantId` is a shared authority.
   */
  allowedTenants?: string[]
  authorizeUrl?: string
  accessTokenUrl?: string
  userInfoUrl?: string
}

/**
 * Fields added to the Ally user from the validated ID token.
 */
export type EntraUserFields = {
  tenantId: string
  /**
   * App roles assigned to the user.
   */
  roles: string[]
  /**
   * Group IDs, when the app registration is configured to emit them.
   */
  groups: string[]
  /**
   * When true, the user has too many groups for the token: `groups` is
   * incomplete and must not be used to make an access decision.
   */
  hasGroupsOverage: boolean
}

export type EntraUser = AllyUserContract<EntraAccessToken> & EntraUserFields

function assertValidConfig({ tenantId, allowedTenants }: EntraConfig) {
  const isSharedAuthority = SHARED_AUTHORITIES.includes(tenantId)

  if (!isSharedAuthority && !TENANT_ID_PATTERN.test(tenantId)) {
    throw new E_ENTRA_INVALID_CONFIG([
      `"tenantId" must be a tenant GUID or one of ${SHARED_AUTHORITIES.join(', ')}`,
    ])
  }
  if (isSharedAuthority && !allowedTenants?.length) {
    throw new E_ENTRA_INVALID_CONFIG([`"allowedTenants" is required with "${tenantId}"`])
  }
  if (!isSharedAuthority && allowedTenants) {
    throw new E_ENTRA_INVALID_CONFIG(['"allowedTenants" requires a shared "tenantId" authority'])
  }
  if (allowedTenants?.some((tenant) => !TENANT_ID_PATTERN.test(tenant))) {
    throw new E_ENTRA_INVALID_CONFIG(['"allowedTenants" must only contain tenant GUIDs'])
  }
}

/**
 * Microsoft signing keys are kept across requests, since a driver instance
 * only lives for one request.
 */
const signingKeys = new Map<string, ReturnType<typeof createRemoteJWKSet>>()

function getSigningKeys(tenantId: string) {
  let keys = signingKeys.get(tenantId)
  if (!keys) {
    keys = createRemoteJWKSet(new URL(`${LOGIN_URL}/${tenantId}/discovery/v2.0/keys`))
    signingKeys.set(tenantId, keys)
  }
  return keys
}

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
    return { ...token, idTokenClaims: await this.verifyIdToken(token.id_token) }
  }

  /**
   * Checks the signature, audience, expiry, issuer, nonce and tenant.
   */
  protected async verifyIdToken(idToken: unknown): Promise<EntraIdTokenClaims> {
    if (typeof idToken !== 'string' || !idToken) {
      throw new E_ENTRA_INVALID_ID_TOKEN(['Microsoft returned none, keep the "openid" scope'])
    }

    let claims: JWTPayload
    try {
      const verified = await jwtVerify(idToken, getSigningKeys(this.config.tenantId), {
        audience: this.config.clientId,
        algorithms: ['RS256'],
        clockTolerance: CLOCK_TOLERANCE_SECONDS,
        requiredClaims: ['exp', 'iss', 'tid'],
      })
      claims = verified.payload
    } catch (error) {
      throw new E_ENTRA_INVALID_ID_TOKEN([(error as Error).message], { cause: error })
    }

    const tenantId = claims.tid
    if (typeof tenantId !== 'string' || claims.iss !== `${LOGIN_URL}/${tenantId}/v2.0`) {
      throw new E_ENTRA_INVALID_ID_TOKEN(['unexpected issuer'])
    }
    if (!this.#nonce || claims.nonce !== this.#nonce) {
      throw new E_ENTRA_INVALID_ID_TOKEN(['unexpected nonce'])
    }
    if (!this.#isTenantAllowed(tenantId)) {
      throw new E_ENTRA_TENANT_NOT_ALLOWED([tenantId])
    }

    return claims as EntraIdTokenClaims
  }

  #isTenantAllowed(tenantId: string) {
    const accepted = this.config.allowedTenants ?? [this.config.tenantId]
    return accepted.some((tenant) => tenant.toLowerCase() === tenantId.toLowerCase())
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
