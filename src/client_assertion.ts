import { constants, createPrivateKey, randomUUID, sign, X509Certificate } from 'node:crypto'
import type { EntraCertificate } from './types.js'

/**
 * Lifetime of a signed assertion. Microsoft advises 5 to 10 minutes at most.
 */
const LIFETIME_SECONDS = 300

export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url')

/**
 * Throws when the certificate cannot be used to sign an assertion.
 */
export function assertUsableCertificate({ certificate, privateKey }: EntraCertificate) {
  const key = createPrivateKey(privateKey)
  if (key.asymmetricKeyType !== 'rsa') {
    throw new Error('the private key must be an RSA key')
  }
  if (!new X509Certificate(certificate).checkPrivateKey(key)) {
    throw new Error('the private key does not match the certificate')
  }
}

/**
 * Builds the signed JWT that proves the application identity to Microsoft.
 * It is signed synchronously, since Ally request hooks cannot be awaited.
 *
 * https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials
 */
export function createClientAssertion(
  { certificate, privateKey }: EntraCertificate,
  { clientId, audience }: { clientId: string; audience: string }
) {
  const thumbprint = Buffer.from(
    new X509Certificate(certificate).fingerprint256.replaceAll(':', ''),
    'hex'
  ).toString('base64url')
  const now = Math.floor(Date.now() / 1000)

  const signingInput = [
    encode({ 'alg': 'PS256', 'typ': 'JWT', 'x5t#S256': thumbprint }),
    encode({
      aud: audience,
      iss: clientId,
      sub: clientId,
      jti: randomUUID(),
      iat: now,
      nbf: now,
      exp: now + LIFETIME_SECONDS,
    }),
  ].join('.')

  const signature = sign('sha256', Buffer.from(signingInput), {
    key: createPrivateKey(privateKey),
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
  })

  return `${signingInput}.${signature.toString('base64url')}`
}
