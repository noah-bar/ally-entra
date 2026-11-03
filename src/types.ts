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
