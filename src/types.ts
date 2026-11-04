import type { AllyUserContract } from '@adonisjs/ally/types'
import type { JWTPayload } from 'jose'

/**
 * Claims of an ID token that passed validation.
 */
export type EntraIdTokenClaims = JWTPayload & {
  tid: string
  oid?: string
  name?: string
  email?: string
  preferred_username?: string
  /**
   * Only present when the `login_hint` optional claim is enabled.
   */
  login_hint?: string
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

/**
 * Options of the Microsoft sign-out.
 */
export type EntraLogoutOptions = {
  /**
   * Where Microsoft sends the user afterwards. It must be registered as a
   * redirect URI of the application.
   */
  postLogoutRedirectUrl?: string
  /**
   * Signs out without an account picker. It must be the value of the
   * `login_hint` claim, never a user principal name.
   */
  logoutHint?: string
}

/**
 * Tokens obtained from a refresh token. Microsoft documents the ID token
 * returned here as not reliable for security, so it is left out.
 */
export type EntraRefreshedToken = {
  token: string
  type: string
  expiresIn?: number
  expiresAt?: Date
  /**
   * The token to store for the next refresh. It replaces the previous one.
   */
  refreshToken: string
  scope?: string
}

/**
 * A certificate registered on the application, as PEM contents.
 */
export type EntraCertificate = {
  /**
   * The public X.509 certificate.
   */
  certificate: string
  /**
   * The unencrypted RSA private key. Keep it out of the source code.
   */
  privateKey: string
}

/**
 * How the application proves its identity to Microsoft: exactly one of both.
 */
export type EntraCredentials =
  | { clientSecret: string; certificate?: undefined }
  | { certificate: EntraCertificate; clientSecret?: undefined }

export type EntraConfig = EntraCredentials & {
  clientId: string
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
