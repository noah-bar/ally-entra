import { createError, Exception } from '@adonisjs/core/exceptions'

/**
 * Microsoft errors meaning that the user has to sign in again.
 */
const SIGN_IN_REQUIRED_ERRORS = new Set([
  'consent_required',
  'interaction_required',
  'invalid_grant',
  'login_required',
])

/**
 * The driver configuration is unsafe or incomplete.
 */
export const E_ENTRA_INVALID_CONFIG = createError<[string]>(
  'Invalid Entra driver configuration: %s',
  'E_ENTRA_INVALID_CONFIG',
  500
)

/**
 * The ID token is missing or did not pass validation.
 */
export const E_ENTRA_INVALID_ID_TOKEN = createError<[string]>(
  'Invalid Entra ID token: %s',
  'E_ENTRA_INVALID_ID_TOKEN',
  401
)

/**
 * The user signed in from a tenant the application does not accept.
 */
export const E_ENTRA_TENANT_NOT_ALLOWED = createError<[string]>(
  'Entra tenant "%s" is not allowed',
  'E_ENTRA_TENANT_NOT_ALLOWED',
  403
)

/**
 * The error body returned by the Microsoft token endpoint.
 */
export type EntraTokenErrorDetails = {
  error?: string
  error_description?: string
  trace_id?: string
  correlation_id?: string
}

/**
 * Microsoft did not exchange the refresh token for new tokens.
 */
// eslint-disable-next-line @typescript-eslint/naming-convention
export class E_ENTRA_TOKEN_REFRESH_FAILED extends Exception {
  static status = 401
  static code = 'E_ENTRA_TOKEN_REFRESH_FAILED'

  /**
   * The Microsoft error code, such as `invalid_grant`.
   */
  microsoftError?: string
  description?: string
  traceId?: string
  correlationId?: string

  constructor(details: EntraTokenErrorDetails = {}, options?: ErrorOptions) {
    super(`Unable to refresh the Entra tokens: ${details.error ?? 'unexpected response'}`, options)
    this.microsoftError = details.error
    this.description = details.error_description
    this.traceId = details.trace_id
    this.correlationId = details.correlation_id
  }

  /**
   * True when retrying is useless and the user has to sign in again.
   */
  get requiresSignIn() {
    return SIGN_IN_REQUIRED_ERRORS.has(this.microsoftError ?? '')
  }
}
