import { createRemoteJWKSet, errors as joseErrors, jwtVerify, type JWTPayload } from 'jose'
import { LOGIN_URL } from './config.js'
import {
  E_ENTRA_INVALID_ID_TOKEN,
  E_ENTRA_REQUEST_FAILED,
  E_ENTRA_TENANT_NOT_ALLOWED,
} from './errors.js'
import type { EntraIdTokenClaims } from './types.js'

/**
 * Tolerated difference between this server clock and the Microsoft one.
 */
const CLOCK_TOLERANCE_SECONDS = 60

/**
 * Microsoft signing keys are kept across requests, since a driver instance
 * only lives for one request.
 */
const signingKeys = new Map<string, ReturnType<typeof createRemoteJWKSet>>()

/**
 * Errors caused by the token itself. Any other error means that the signing
 * keys could not be read, which says nothing about the token.
 */
const INVALID_TOKEN_ERRORS = [
  joseErrors.JOSEAlgNotAllowed,
  joseErrors.JOSENotSupported,
  joseErrors.JWKSMultipleMatchingKeys,
  joseErrors.JWKSNoMatchingKey,
  joseErrors.JWSInvalid,
  joseErrors.JWSSignatureVerificationFailed,
  joseErrors.JWTClaimValidationFailed,
  joseErrors.JWTExpired,
  joseErrors.JWTInvalid,
]

function getSigningKeys(tenantId: string) {
  let keys = signingKeys.get(tenantId)
  if (!keys) {
    keys = createRemoteJWKSet(new URL(`${LOGIN_URL}/${tenantId}/discovery/v2.0/keys`))
    signingKeys.set(tenantId, keys)
  }
  return keys
}

export type IdTokenExpectations = {
  clientId: string
  tenantId: string
  allowedTenants?: string[]
  /**
   * The nonce sent to Microsoft when the sign-in started.
   */
  nonce?: string
}

function isTenantAllowed(
  tenantId: string,
  { tenantId: authority, allowedTenants }: IdTokenExpectations
) {
  const accepted = allowedTenants ?? [authority]
  return accepted.some((tenant) => tenant.toLowerCase() === tenantId.toLowerCase())
}

/**
 * Checks the signature, audience, expiry, issuer, nonce and tenant of an
 * ID token, then returns its claims.
 */
export async function verifyIdToken(
  idToken: unknown,
  expected: IdTokenExpectations
): Promise<EntraIdTokenClaims> {
  if (typeof idToken !== 'string' || !idToken) {
    throw new E_ENTRA_INVALID_ID_TOKEN(['Microsoft returned none, keep the "openid" scope'])
  }

  let claims: JWTPayload
  try {
    const verified = await jwtVerify(idToken, getSigningKeys(expected.tenantId), {
      audience: expected.clientId,
      algorithms: ['RS256'],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
      requiredClaims: ['exp', 'iss', 'tid'],
    })
    claims = verified.payload
  } catch (error) {
    /**
     * The original error is not kept, since it holds the claims of the token,
     * which are personal data that could end up in the logs.
     */
    const { message } = error as Error
    if (!INVALID_TOKEN_ERRORS.some((invalidToken) => error instanceof invalidToken)) {
      throw new E_ENTRA_REQUEST_FAILED({}, { cause: new Error(message) })
    }
    throw new E_ENTRA_INVALID_ID_TOKEN([message])
  }

  const tenantId = claims.tid
  if (typeof tenantId !== 'string' || claims.iss !== `${LOGIN_URL}/${tenantId}/v2.0`) {
    throw new E_ENTRA_INVALID_ID_TOKEN(['unexpected issuer'])
  }
  if (!expected.nonce || claims.nonce !== expected.nonce) {
    throw new E_ENTRA_INVALID_ID_TOKEN(['unexpected nonce'])
  }
  if (!isTenantAllowed(tenantId, expected)) {
    throw new E_ENTRA_TENANT_NOT_ALLOWED([tenantId])
  }

  return claims as EntraIdTokenClaims
}
