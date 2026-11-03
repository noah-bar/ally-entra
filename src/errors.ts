import { createError } from '@adonisjs/core/exceptions'

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
