import { createError, Exception } from '@adonisjs/core/exceptions'

/**
 * Microsoft errors meaning that the user has to sign in again.
 */
const SIGN_IN_REQUIRED_ERRORS = new Set([
  'access_denied',
  'consent_required',
  'interaction_required',
  'InvalidAuthenticationToken',
  'invalid_grant',
  'login_required',
  'missing_refresh_token',
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
 * The error details returned by Microsoft, on the token endpoint or in the
 * query string of the callback.
 */
export type EntraErrorDetails = {
  error?: unknown
  error_description?: unknown
  error_codes?: unknown
  trace_id?: unknown
  correlation_id?: unknown
}

const asText = (value: unknown) => (typeof value === 'string' ? value : undefined)

/**
 * Reads the `AADSTS` code, which is what the Microsoft documentation refers to.
 */
function readAadstsCode({ error_codes: codes, error_description: description }: EntraErrorDetails) {
  const code: unknown = Array.isArray(codes) ? codes[0] : undefined
  if (typeof code === 'number') {
    return `AADSTS${code}`
  }

  return asText(description)?.match(/\bAADSTS\d+\b/)?.[0]
}

/**
 * Microsoft refused a sign-in or a token request. The message only holds the
 * error codes: the callback query string can be forged by anyone, so the free
 * text description stays out of it.
 */
export const E_ENTRA_REQUEST_FAILED = class extends Exception {
  static code = 'E_ENTRA_REQUEST_FAILED'

  /**
   * The Microsoft error code, such as `invalid_grant`.
   */
  microsoftError?: string
  /**
   * The detailed Microsoft code, such as `AADSTS7000215`.
   */
  aadstsCode?: string
  description?: string
  traceId?: string
  correlationId?: string
  /**
   * The HTTP status of the Microsoft response.
   */
  responseStatus?: number

  constructor(details: EntraErrorDetails = {}, options?: ErrorOptions) {
    const error = asText(details.error)
    const aadstsCode = readAadstsCode(details)
    const safeError = error && /^\w+$/.test(error) ? error : 'unexpected response'
    const suffix = aadstsCode ? ` (${aadstsCode})` : ''

    super(`Microsoft refused the request: ${safeError}${suffix}`, {
      ...options,
      status: SIGN_IN_REQUIRED_ERRORS.has(error ?? '') ? 401 : 500,
    })

    this.microsoftError = error
    this.aadstsCode = aadstsCode
    this.description = asText(details.error_description)
    this.traceId = asText(details.trace_id)
    this.correlationId = asText(details.correlation_id)
  }

  /**
   * True when retrying is useless and the user has to sign in again.
   */
  get requiresSignIn() {
    return SIGN_IN_REQUIRED_ERRORS.has(this.microsoftError ?? '')
  }
}
