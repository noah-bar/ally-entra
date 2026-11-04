import { generateKeyPairSync, X509Certificate } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from '@japa/runner'
import { decodeProtectedHeader, jwtVerify } from 'jose'
import { EntraService, errors, type EntraConfig } from '../index.js'
import { browserCookies, createContext, mockFetch, publishedKeys, signIdToken } from './helpers.js'

type RequestError = InstanceType<typeof errors.E_ENTRA_REQUEST_FAILED>

const fixture = (name: string) => readFileSync(new URL(`fixtures/${name}`, import.meta.url), 'utf8')

const TENANT = '11111111-1111-4111-8111-111111111111'
const LOGIN = 'https://login.microsoftonline.com'
const TOKEN_URL = `${LOGIN}/${TENANT}/oauth2/v2.0/token`
const KEYS_URL = `${LOGIN}/${TENANT}/discovery/v2.0/keys`
const GRAPH_URL = 'https://graph.microsoft.com/v1.0/me'
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

const certificate = { certificate: fixture('test_cert.pem'), privateKey: fixture('test_key.pem') }

const base = {
  clientId: 'client-id',
  callbackUrl: 'https://app.test/sso/azure/callback',
  tenantId: TENANT,
}
const withSecret: EntraConfig = { ...base, clientSecret: 'client-secret' }
const withCertificate: EntraConfig = { ...base, certificate }

test.group('EntraDriver | credentials configuration', () => {
  test('checks the certificate once, not for each request', ({ assert }) => {
    let reads = 0
    const counted: EntraConfig = {
      ...base,
      certificate: {
        certificate: certificate.certificate,
        get privateKey() {
          reads++
          return certificate.privateKey
        },
      },
    }

    const createDriver = EntraService(counted)
    createDriver(createContext())
    createDriver(createContext())

    assert.equal(reads, 1)
  })

  test('refuses {title}')
    .with([
      { title: 'no credentials', credentials: {} },
      { title: 'an empty secret', credentials: { clientSecret: '' } },
      { title: 'a secret and a certificate', credentials: { clientSecret: 'secret', certificate } },
      {
        title: 'an unreadable private key',
        credentials: { certificate: { ...certificate, privateKey: 'not-a-key' } },
      },
      {
        title: 'an unreadable certificate',
        credentials: { certificate: { ...certificate, certificate: 'not-a-certificate' } },
      },
    ])
    .run(({ assert }, { credentials }) => {
      assert.throws(
        () => EntraService({ ...base, ...credentials } as EntraConfig),
        /Invalid Entra driver configuration/
      )
    })

  test('refuses a private key of another certificate', ({ assert }) => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const otherKey = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()

    assert.throws(
      () => EntraService({ ...base, certificate: { ...certificate, privateKey: otherKey } }),
      /does not match the certificate/
    )
  })

  test('refuses a non RSA private key', ({ assert }) => {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const ecKey = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()

    assert.throws(
      () => EntraService({ ...base, certificate: { ...certificate, privateKey: ecKey } }),
      /must be an RSA key/
    )
  })

  test('does not reveal the private key in configuration errors', ({ assert }) => {
    const privateKey = 'super-secret-key-material'

    let message = ''
    try {
      EntraService({ ...base, certificate: { ...certificate, privateKey } })
    } catch (error) {
      message = (error as Error).message
    }

    assert.match(message, /Invalid Entra driver configuration/)
    assert.notInclude(message, privateKey)
  })
})

test.group('EntraDriver | authentication with a certificate', (group) => {
  let http: ReturnType<typeof mockFetch>
  let nonce: string

  group.each.setup(() => {
    const now = Math.floor(Date.now() / 1000)
    http = mockFetch({
      [TOKEN_URL]: {
        body: async () => ({
          access_token: 'access-token',
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: 'new-refresh-token',
          id_token: await signIdToken({
            aud: 'client-id',
            iss: `${LOGIN}/${TENANT}/v2.0`,
            tid: TENANT,
            nonce,
            exp: now + 3600,
          }),
        }),
      },
      [KEYS_URL]: { body: publishedKeys },
      [GRAPH_URL]: { body: { id: 'object-id', displayName: 'Ada' } },
    })
    return () => http.restore()
  })

  /**
   * Runs a full sign-in and returns the token request sent to Microsoft.
   */
  async function signIn(config: EntraConfig) {
    const start = createContext('/sso/azure')
    await EntraService(config)(start).redirect()

    const location = new URL(String(start.response.getHeader('location')))
    nonce = location.searchParams.get('nonce')!
    const state = encodeURIComponent(location.searchParams.get('state')!)

    const callback = createContext(`/callback?code=auth-code&state=${state}`, browserCookies(start))
    await EntraService(config)(callback).user()

    return http.requests.find(({ url }) => url === TOKEN_URL)!
  }

  test('sends a client secret when configured with one', async ({ assert }) => {
    const { body } = await signIn(withSecret)

    assert.equal(body.get('client_secret'), 'client-secret')
    assert.isNull(body.get('client_assertion'))
    assert.isNull(body.get('client_assertion_type'))
  })

  test('sends a signed assertion instead of a secret', async ({ assert }) => {
    const { body } = await signIn(withCertificate)

    assert.isNull(body.get('client_secret'))
    assert.equal(body.get('client_assertion_type'), ASSERTION_TYPE)
    assert.isNotEmpty(body.get('client_assertion'))
  })

  test('signs the assertion in the format Microsoft documents', async ({ assert }) => {
    const { body } = await signIn(withCertificate)
    const assertion = body.get('client_assertion')!
    const x509 = new X509Certificate(certificate.certificate)

    const { payload } = await jwtVerify(assertion, x509.publicKey, {
      algorithms: ['PS256'],
      audience: TOKEN_URL,
      issuer: 'client-id',
      subject: 'client-id',
      requiredClaims: ['jti', 'iat', 'nbf', 'exp'],
    })
    assert.isAtMost(payload.exp! - payload.nbf!, 600)
    assert.equal(payload.exp! - payload.nbf!, 360)
    assert.equal(payload.iat, payload.nbf)

    const expectedThumbprint = Buffer.from(x509.fingerprint256.replaceAll(':', ''), 'hex').toString(
      'base64url'
    )
    assert.deepEqual(decodeProtectedHeader(assertion), {
      'alg': 'PS256',
      'typ': 'JWT',
      'x5t#S256': expectedThumbprint,
    })
  })

  test('uses a unique identifier for each assertion', async ({ assert }) => {
    const driver = EntraService(withCertificate)(createContext())

    const identifiers = []
    for (const refreshToken of ['first', 'second']) {
      await driver.refreshAccessToken(refreshToken)
      const { payload } = await jwtVerify(
        http.requests.at(-1)!.body.get('client_assertion')!,
        new X509Certificate(certificate.certificate).publicKey
      )
      identifiers.push(payload.jti)
    }

    assert.notEqual(identifiers[0], identifiers[1])
  })
})

test.group('EntraDriver | refreshAccessToken', (group) => {
  let http: ReturnType<typeof mockFetch>

  const mock = (status: number, body: unknown) => {
    http = mockFetch({ [TOKEN_URL]: { status, body } })
  }
  const driverFor = (config: EntraConfig = withSecret) => EntraService(config)(createContext())

  /**
   * Returns the error thrown by a refresh, or undefined when it succeeds.
   */
  const refreshFailure = (driver: ReturnType<typeof driverFor>) =>
    driver.refreshAccessToken('old-refresh-token').then(
      () => undefined,
      (error: RequestError) => error
    )

  group.each.setup(() => {
    mock(200, {
      access_token: 'new-access-token',
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: 'new-refresh-token',
      scope: 'User.Read',
      id_token: 'unsigned-id-token',
    })
    return () => http.restore()
  })

  test('sends the refresh request to the tenant with the client secret', async ({ assert }) => {
    await driverFor().refreshAccessToken('old-refresh-token')

    assert.lengthOf(http.requests, 1)
    const { method, url, body } = http.requests[0]
    assert.equal(`${method} ${url}`, `POST ${TOKEN_URL}`)
    assert.equal(body.get('grant_type'), 'refresh_token')
    assert.equal(body.get('refresh_token'), 'old-refresh-token')
    assert.equal(body.get('client_id'), 'client-id')
    assert.equal(body.get('client_secret'), 'client-secret')
  })

  test('authenticates with the certificate when configured', async ({ assert }) => {
    await driverFor(withCertificate).refreshAccessToken('old-refresh-token')

    const { body } = http.requests[0]
    assert.isNull(body.get('client_secret'))
    assert.equal(body.get('client_assertion_type'), ASSERTION_TYPE)

    const { payload } = await jwtVerify(
      body.get('client_assertion')!,
      new X509Certificate(certificate.certificate).publicKey,
      { audience: TOKEN_URL }
    )
    assert.equal(payload.sub, 'client-id')
  })

  test('returns the new tokens, without the ID token', async ({ assert }) => {
    const before = Date.now()
    const token = await driverFor().refreshAccessToken('old-refresh-token')

    assert.equal(token.token, 'new-access-token')
    assert.equal(token.type, 'Bearer')
    assert.equal(token.refreshToken, 'new-refresh-token')
    assert.equal(token.expiresIn, 3600)
    assert.equal(token.scope, 'User.Read')
    assert.isAtLeast(token.expiresAt!.getTime(), before + 3600 * 1000)
    assert.notProperty(token, 'id_token')
  })

  test('keeps the current refresh token when Microsoft sends no new one', async ({ assert }) => {
    http.restore()
    mock(200, { access_token: 'new-access-token', token_type: 'Bearer' })

    const token = await driverFor().refreshAccessToken('old-refresh-token')

    assert.equal(token.refreshToken, 'old-refresh-token')
    assert.isUndefined(token.expiresAt)
  })

  test('lets the caller customize the request', async ({ assert }) => {
    await driverFor().refreshAccessToken('old-refresh-token', (request) =>
      request.field('scope', 'User.Read')
    )

    assert.equal(http.requests[0].body.get('scope'), 'User.Read')
  })

  test('asks for a new sign-in on {error}')
    .with([
      { error: 'invalid_grant' },
      { error: 'interaction_required' },
      { error: 'consent_required' },
      { error: 'login_required' },
    ])
    .run(async ({ assert }, { error }) => {
      http.restore()
      mock(400, { error })

      const failure = await refreshFailure(driverFor())

      assert.instanceOf(failure, errors.E_ENTRA_REQUEST_FAILED)
      assert.isTrue(failure!.requiresSignIn)
    })

  test('exposes the Microsoft error details without any token', async ({ assert }) => {
    http.restore()
    mock(400, {
      error: 'invalid_client',
      error_description: 'AADSTS7000215: Invalid client secret',
      trace_id: 'trace-id',
      correlation_id: 'correlation-id',
    })

    const failure = await refreshFailure(driverFor())

    assert.instanceOf(failure, errors.E_ENTRA_REQUEST_FAILED)
    assert.equal(failure!.microsoftError, 'invalid_client')
    assert.equal(failure!.description, 'AADSTS7000215: Invalid client secret')
    assert.equal(failure!.traceId, 'trace-id')
    assert.equal(failure!.correlationId, 'correlation-id')
    assert.isFalse(failure!.requiresSignIn)
    assert.notInclude(failure!.message, 'old-refresh-token')
  })

  test('refuses {title}')
    .with([
      { title: 'a server error without details', status: 503, body: 'unavailable' },
      { title: 'a response without an access token', status: 200, body: { token_type: 'Bearer' } },
    ])
    .run(async ({ assert }, { status, body }) => {
      http.restore()
      mock(status, body)

      await assert.rejects(
        () => driverFor().refreshAccessToken('old-refresh-token'),
        errors.E_ENTRA_REQUEST_FAILED
      )
    })

  test('refuses an empty refresh token without calling Microsoft', async ({ assert }) => {
    await assert.rejects(() => driverFor().refreshAccessToken(''), errors.E_ENTRA_REQUEST_FAILED)
    assert.lengthOf(http.requests, 0)
  })
})
