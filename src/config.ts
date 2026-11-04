import { assertUsableCertificate } from './client_assertion.js'
import { E_ENTRA_INVALID_CONFIG } from './errors.js'
import type { EntraConfig } from './types.js'

export const LOGIN_URL = 'https://login.microsoftonline.com'

/**
 * Authorities accepting accounts from several tenants.
 */
const SHARED_AUTHORITIES = ['common', 'organizations', 'consumers']
const TENANT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/**
 * Configurations already checked, since a driver is created for each request.
 */
const validConfigs = new WeakSet<EntraConfig>()

/**
 * Refuses a configuration that would accept unexpected tenants.
 */
export function assertValidConfig(config: EntraConfig) {
  if (validConfigs.has(config)) {
    return
  }

  const { tenantId, allowedTenants, clientSecret, certificate } = config

  if (Boolean(clientSecret) === Boolean(certificate)) {
    throw new E_ENTRA_INVALID_CONFIG(['define either "clientSecret" or "certificate"'])
  }
  if (certificate) {
    try {
      assertUsableCertificate(certificate)
    } catch (error) {
      throw new E_ENTRA_INVALID_CONFIG([`"certificate" is not usable: ${(error as Error).message}`])
    }
  }

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

  validConfigs.add(config)
}
