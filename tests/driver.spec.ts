import { generateKeyPair, SignJWT, UnsecuredJWT } from 'jose'
import { createHash } from 'node:crypto'
import { errors as allyErrors } from '@adonisjs/ally'
import type { HttpContext } from '@adonisjs/core/http'
import { test } from '@japa/runner'
import { EntraService, errors, type EntraConfig } from '../index.js'
import {
  browserCookies,
  cookieChanges,
  createContext,
  mockFetch,
  publishedKeys,
  signIdToken,
} from './helpers.js'

const TENANT = '11111111-1111-4111-8111-111111111111'
const OTHER_TENANT = '22222222-2222-4222-8222-222222222222'
const LOGIN = 'https://login.microsoftonline.com'

const config: EntraConfig = {
  clientId: 'client-id',
  clientSecret: 'client-secret',
  callbackUrl: 'https://app.test/sso/azure/callback',
  tenantId: TENANT,
}

const AUTHORIZE_URL = `${LOGIN}/${TENANT}/oauth2/v2.0/authorize`
const TOKEN_URL = `${LOGIN}/${TENANT}/oauth2/v2.0/token`
const KEYS_URL = `${LOGIN}/${TENANT}/discovery/v2.0/keys`
const GRAPH_URL = 'https://graph.microsoft.com/v1.0/me'

const profile = {
  id: 'object-id',
  displayName: 'Ada Lovelace',
  mail: 'ada@contoso.com',
  userPrincipalName: 'ada_contoso.com#EXT#@contoso.onmicrosoft.com',
}

const STATE_COOKIE = 'entra_oauth_state'
const VERIFIER_COOKIE = 'entra_oauth_code_verifier'
const NONCE_COOKIE = 'entra_oauth_nonce'

const driverFor = (ctx: HttpContext, driverConfig: EntraConfig = config) =>
  EntraService(driverConfig)(ctx)

/**
 * Starts a sign-in and returns what the browser holds when Microsoft sends
 * the user back.
 */
async function startSignIn(driverConfig: EntraConfig = config) {
  const ctx = createContext('/sso/azure')
  await driverFor(ctx, driverConfig).redirect()

  const location = new URL(String(ctx.response.getHeader('location')))
  const state = location.searchParams.get('state')!
  const nonce = location.searchParams.get('nonce')!

  return { ctx, location, state, nonce, cookies: browserCookies(ctx) }
}

const callbackUrl = (state: string) => `/callback?code=auth-code&state=${encodeURIComponent(state)}`

/**
 * Keeps only some cookies of a Cookie header.
 */
const withoutCookie = (cookies: string, name: string) =>
  cookies
    .split('; ')
    .filter((cookie) => !cookie.startsWith(`${name}=`))
    .join('; ')

test.group('EntraDriver | configuration', () => {
  test('refuses {title}')
    .with([
      { title: 'a tenant name', tenantId: 'contoso.onmicrosoft.com', allowedTenants: undefined },
      { title: 'a shared authority without allowedTenants', tenantId: 'common' },
      { title: 'an empty allowedTenants', tenantId: 'organizations', allowedTenants: [] },
      { title: 'allowedTenants with one tenant', tenantId: TENANT, allowedTenants: [TENANT] },
      { title: 'a non GUID allowed tenant', tenantId: 'common', allowedTenants: ['contoso.com'] },
    ])
    .run(({ assert }, { tenantId, allowedTenants }) => {
      assert.throws(
        () => EntraService({ ...config, tenantId, allowedTenants }),
        /Invalid Entra driver configuration/
      )
    })
})

test.group('EntraDriver | redirect', () => {
  test('sends the user to the configured tenant with the sign-in parameters', async ({
    assert,
  }) => {
    const { location } = await startSignIn()

    assert.equal(`${location.origin}${location.pathname}`, AUTHORIZE_URL)
    assert.equal(location.searchParams.get('client_id'), 'client-id')
    assert.equal(location.searchParams.get('redirect_uri'), config.callbackUrl)
    assert.equal(location.searchParams.get('response_type'), 'code')
    assert.deepEqual(location.searchParams.getAll('scope'), ['openid profile email User.Read'])
    assert.isNotEmpty(location.searchParams.get('state'))
  })

  test('sets the state, PKCE and nonce cookies', async ({ assert }) => {
    const { ctx } = await startSignIn()

    assert.deepEqual(cookieChanges(ctx).set, [VERIFIER_COOKIE, NONCE_COOKIE, STATE_COOKIE])
  })

  test('uses a new random nonce for each sign-in', async ({ assert }) => {
    const first = await startSignIn()
    const second = await startSignIn()

    assert.isAtLeast(first.nonce.length, 32)
    assert.notEqual(first.nonce, second.nonce)
  })

  test('lets the caller replace the default scopes', async ({ assert }) => {
    const url = new URL(
      await driverFor(createContext()).redirectUrl((request) =>
        request.clearScopes().scopes(['openid'])
      )
    )

    assert.deepEqual(url.searchParams.getAll('scope'), ['openid'])
  })
})

test.group('EntraDriver | callback checks', () => {
  test('accessDenied is true for access_denied', ({ assert }) => {
    const driver = driverFor(createContext('/callback?error=access_denied'))

    assert.isTrue(driver.accessDenied())
    assert.isTrue(driver.hasError())
  })

  test('other Microsoft errors are errors, not denials', ({ assert }) => {
    const driver = driverFor(createContext('/callback?error=server_error'))

    assert.isFalse(driver.accessDenied())
    assert.equal(driver.getError(), 'server_error')
  })

  test('a legitimate return passes every check', async ({ assert }) => {
    const { state, cookies } = await startSignIn()
    const driver = driverFor(createContext(callbackUrl(state), cookies))

    assert.isFalse(driver.stateMisMatch())
    assert.isFalse(driver.hasError())
    assert.isFalse(driver.accessDenied())
  })

  test('a forged state is a mismatch', async ({ assert }) => {
    const { cookies } = await startSignIn()
    const driver = driverFor(createContext(callbackUrl('forged'), cookies))

    assert.isTrue(driver.stateMisMatch())
  })

  test('a return without the {title} cookie is a mismatch')
    .with([
      { title: 'state', cookie: STATE_COOKIE },
      { title: 'PKCE', cookie: VERIFIER_COOKIE },
      { title: 'nonce', cookie: NONCE_COOKIE },
    ])
    .run(async ({ assert }, { cookie }) => {
      const { state, cookies } = await startSignIn()
      const driver = driverFor(createContext(callbackUrl(state), withoutCookie(cookies, cookie)))

      assert.isTrue(driver.stateMisMatch())
    })
})

test.group('EntraDriver | user', (group) => {
  let http: ReturnType<typeof mockFetch>
  let idTokenFor: (nonce: string) => Promise<string | undefined>
  let tokenStatus: number
  let graphBody: unknown
  let nonce: string

  /**
   * Claims of a valid ID token for the current sign-in.
   */
  const validClaims = (currentNonce: string) => {
    const now = Math.floor(Date.now() / 1000)
    return {
      aud: 'client-id',
      iss: `${LOGIN}/${TENANT}/v2.0`,
      tid: TENANT,
      oid: 'object-id',
      nonce: currentNonce,
      iat: now,
      nbf: now,
      exp: now + 3600,
    }
  }

  const tokenReply = () => ({
    status: tokenStatus,
    body: async () => ({
      access_token: 'access-token',
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: await idTokenFor(nonce),
    }),
  })

  const mock = (urls: Record<string, ReturnType<typeof tokenReply> | { body: unknown }> = {}) => {
    http = mockFetch({
      [TOKEN_URL]: tokenReply(),
      [KEYS_URL]: { body: publishedKeys },
      [GRAPH_URL]: { body: () => graphBody },
      ...urls,
    })
  }

  /**
   * Requests other than the signing keys download, which is cached.
   */
  const signInRequests = () => http.requests.filter(({ url }) => !url.endsWith('/keys'))

  /**
   * Returns the driver of a legitimate return from Microsoft.
   */
  const signedInDriver = async (driverConfig: EntraConfig = config) => {
    const signIn = await startSignIn(driverConfig)
    nonce = signIn.nonce
    return driverFor(createContext(callbackUrl(signIn.state), signIn.cookies), driverConfig)
  }

  const signedInUser = async (driverConfig?: EntraConfig) => {
    const driver = await signedInDriver(driverConfig)
    return driver.user()
  }

  group.each.setup(() => {
    tokenStatus = 200
    graphBody = profile
    idTokenFor = (currentNonce) => signIdToken(validClaims(currentNonce))
    mock()
    return () => http.restore()
  })

  test('completes the sign-in against the real Microsoft addresses', async ({ assert }) => {
    const { location, state, nonce: signInNonce, cookies } = await startSignIn()
    nonce = signInNonce

    const user = await driverFor(createContext(callbackUrl(state), cookies)).user()

    assert.deepEqual(
      signInRequests().map(({ method, url }) => `${method} ${url}`),
      [`POST ${TOKEN_URL}`, `GET ${GRAPH_URL}`]
    )

    const { body } = signInRequests()[0]
    assert.equal(body.get('grant_type'), 'authorization_code')
    assert.equal(body.get('code'), 'auth-code')
    assert.equal(body.get('client_id'), 'client-id')
    assert.equal(body.get('client_secret'), 'client-secret')
    assert.equal(body.get('redirect_uri'), config.callbackUrl)

    assert.equal(location.searchParams.get('code_challenge_method'), 'S256')
    assert.equal(
      location.searchParams.get('code_challenge'),
      createHash('sha256').update(body.get('code_verifier')!).digest('base64url')
    )

    assert.equal(signInRequests()[1].headers.get('authorization'), 'Bearer access-token')

    assert.equal(user.id, 'object-id')
    assert.equal(user.token.token, 'access-token')
    assert.equal(user.token.type, 'Bearer')
  })

  test('clears the sign-in cookies on return, so a replay is refused', async ({ assert }) => {
    const signIn = await startSignIn()
    nonce = signIn.nonce
    const url = callbackUrl(signIn.state)
    const ctx = createContext(url, signIn.cookies)

    await driverFor(ctx).user()
    assert.deepEqual(cookieChanges(ctx).cleared, [VERIFIER_COOKIE, NONCE_COOKIE, STATE_COOKIE])

    http.requests.length = 0
    const replay = driverFor(createContext(url, browserCookies(ctx)))

    await assert.rejects(() => replay.user(), allyErrors.E_OAUTH_STATE_MISMATCH)
    assert.lengthOf(http.requests, 0)
  })

  test('maps the Graph profile to the Ally user format', async ({ assert }) => {
    const user = await signedInUser()

    assert.equal(user.name, 'Ada Lovelace')
    assert.equal(user.nickName, 'Ada Lovelace')
    assert.equal(user.email, 'ada@contoso.com')
    assert.equal(user.emailVerificationState, 'unsupported')
    assert.isNull(user.avatarUrl)
    assert.deepEqual(user.original, profile)
  })

  test('returns a null email instead of the userPrincipalName', async ({ assert }) => {
    graphBody = { ...profile, mail: null }

    const user = await signedInUser()

    assert.isNull(user.email)
    assert.equal(user.original.userPrincipalName, profile.userPrincipalName)
  })

  test('falls back to the userPrincipalName when displayName is missing', async ({ assert }) => {
    graphBody = { ...profile, displayName: null }

    const user = await signedInUser()

    assert.equal(user.name, profile.userPrincipalName)
    assert.equal(user.nickName, profile.userPrincipalName)
  })

  test('exposes the tenant, roles and groups of the ID token', async ({ assert }) => {
    idTokenFor = (currentNonce) =>
      signIdToken({ ...validClaims(currentNonce), roles: ['admin'], groups: ['group-id'] })

    const user = await signedInUser()

    assert.equal(user.tenantId, TENANT)
    assert.deepEqual(user.roles, ['admin'])
    assert.deepEqual(user.groups, ['group-id'])
    assert.isFalse(user.hasGroupsOverage)
    assert.equal(user.token.idTokenClaims.oid, 'object-id')
  })

  test('defaults roles and groups to empty lists', async ({ assert }) => {
    const user = await signedInUser()

    assert.deepEqual(user.roles, [])
    assert.deepEqual(user.groups, [])
  })

  test('reports a groups overage when {title}')
    .with([
      { title: 'the token links to the group list', claim: { _claim_names: { groups: 'src1' } } },
      { title: 'the token has the hasgroups claim', claim: { hasgroups: true } },
    ])
    .run(async ({ assert }, { claim }) => {
      idTokenFor = (currentNonce) => signIdToken({ ...validClaims(currentNonce), ...claim })

      const user = await signedInUser()

      assert.isTrue(user.hasGroupsOverage)
    })

  test('accessToken validates the ID token too', async ({ assert }) => {
    idTokenFor = (currentNonce) => signIdToken({ ...validClaims(currentNonce), aud: 'other-app' })
    const driver = await signedInDriver()

    await assert.rejects(() => driver.accessToken(), errors.E_ENTRA_INVALID_ID_TOKEN)
  })

  test('refuses an ID token with {title}')
    .with([
      { title: 'another audience', claims: { aud: 'other-app' } },
      { title: 'another issuer', claims: { iss: 'https://evil.example/v2.0' } },
      { title: 'the issuer of another tenant', claims: { iss: `${LOGIN}/${OTHER_TENANT}/v2.0` } },
      { title: 'a v1 issuer', claims: { iss: `https://sts.windows.net/${TENANT}/` } },
      { title: 'an expired date', claims: { exp: Math.floor(Date.now() / 1000) - 3600 } },
      { title: 'a future start date', claims: { nbf: Math.floor(Date.now() / 1000) + 3600 } },
      { title: 'another nonce', claims: { nonce: 'replayed-nonce' } },
      { title: 'no nonce', claims: { nonce: undefined } },
      { title: 'no tenant', claims: { tid: undefined } },
      { title: 'no expiry', claims: { exp: undefined } },
    ])
    .run(async ({ assert }, { claims }) => {
      idTokenFor = (currentNonce) => signIdToken({ ...validClaims(currentNonce), ...claims })
      const driver = await signedInDriver()

      await assert.rejects(() => driver.user(), errors.E_ENTRA_INVALID_ID_TOKEN)
      assert.notInclude(
        http.requests.map(({ url }) => url),
        GRAPH_URL
      )
    })

  test('tolerates a small clock difference with Microsoft', async ({ assert }) => {
    const now = Math.floor(Date.now() / 1000)
    idTokenFor = (currentNonce) =>
      signIdToken({ ...validClaims(currentNonce), nbf: now + 30, iat: now + 30 })

    const user = await signedInUser()

    assert.equal(user.id, 'object-id')
  })

  test('refuses an ID token signed with another key', async ({ assert }) => {
    const attacker = await generateKeyPair('RS256')
    idTokenFor = (currentNonce) => signIdToken(validClaims(currentNonce), attacker.privateKey)
    const driver = await signedInDriver()

    await assert.rejects(() => driver.user(), errors.E_ENTRA_INVALID_ID_TOKEN)
  })

  test('refuses an unsigned ID token', async ({ assert }) => {
    idTokenFor = async (currentNonce) => new UnsecuredJWT(validClaims(currentNonce)).encode()
    const driver = await signedInDriver()

    await assert.rejects(() => driver.user(), errors.E_ENTRA_INVALID_ID_TOKEN)
  })

  test('refuses an ID token signed with a shared secret', async ({ assert }) => {
    idTokenFor = (currentNonce) =>
      new SignJWT(validClaims(currentNonce))
        .setProtectedHeader({ alg: 'HS256', kid: 'test-key' })
        .sign(new TextEncoder().encode('a-secret-known-by-the-attacker-of-32b'))
    const driver = await signedInDriver()

    await assert.rejects(() => driver.user(), errors.E_ENTRA_INVALID_ID_TOKEN)
  })

  test('refuses a missing ID token', async ({ assert }) => {
    idTokenFor = async () => undefined
    const driver = await signedInDriver()

    await assert.rejects(() => driver.user(), errors.E_ENTRA_INVALID_ID_TOKEN)
  })

  test('refuses another tenant on a single tenant application', async ({ assert }) => {
    idTokenFor = (currentNonce) =>
      signIdToken({
        ...validClaims(currentNonce),
        tid: OTHER_TENANT,
        iss: `${LOGIN}/${OTHER_TENANT}/v2.0`,
      })
    const driver = await signedInDriver()

    await assert.rejects(() => driver.user(), errors.E_ENTRA_TENANT_NOT_ALLOWED)
  })

  test('uses the shared authority addresses and checks allowedTenants', async ({ assert }) => {
    const shared: EntraConfig = { ...config, tenantId: 'organizations', allowedTenants: [TENANT] }
    const sharedTokenUrl = `${LOGIN}/organizations/oauth2/v2.0/token`
    const sharedKeysUrl = `${LOGIN}/organizations/discovery/v2.0/keys`
    http.restore()
    mock({ [sharedTokenUrl]: tokenReply(), [sharedKeysUrl]: { body: publishedKeys } })

    const user = await signedInUser(shared)
    assert.equal(user.tenantId, TENANT)
    assert.includeMembers(
      http.requests.map(({ url }) => url),
      [sharedTokenUrl, sharedKeysUrl]
    )

    idTokenFor = (currentNonce) =>
      signIdToken({
        ...validClaims(currentNonce),
        tid: OTHER_TENANT,
        iss: `${LOGIN}/${OTHER_TENANT}/v2.0`,
      })
    const driver = await signedInDriver(shared)

    await assert.rejects(() => driver.user(), errors.E_ENTRA_TENANT_NOT_ALLOWED)
  })

  test('compares tenant IDs without regard to case', async ({ assert }) => {
    const shared: EntraConfig = {
      ...config,
      tenantId: 'organizations',
      allowedTenants: ['AAAAAAAA-1111-4111-8111-111111111111'],
    }
    const mixedCaseTenant = 'aaaaaaaa-1111-4111-8111-111111111111'
    http.restore()
    mock({
      [`${LOGIN}/organizations/oauth2/v2.0/token`]: tokenReply(),
      [`${LOGIN}/organizations/discovery/v2.0/keys`]: { body: publishedKeys },
    })
    idTokenFor = (currentNonce) =>
      signIdToken({
        ...validClaims(currentNonce),
        tid: mixedCaseTenant,
        iss: `${LOGIN}/${mixedCaseTenant}/v2.0`,
      })

    const user = await signedInUser(shared)

    assert.equal(user.tenantId, mixedCaseTenant)
  })

  test('applies the caller callback to both Microsoft requests', async ({ assert }) => {
    const driver = await signedInDriver()

    await driver.user((request) => request.header('x-custom', 'yes'))

    assert.deepEqual(
      signInRequests().map(({ headers }) => headers.get('x-custom')),
      ['yes', 'yes']
    )
  })

  test('sends nothing to Microsoft when the state is forged', async ({ assert }) => {
    const { cookies } = await startSignIn()
    const driver = driverFor(createContext(callbackUrl('forged'), cookies))

    await assert.rejects(() => driver.user(), allyErrors.E_OAUTH_STATE_MISMATCH)
    assert.lengthOf(http.requests, 0)
  })

  test('refuses a callback without a code', async ({ assert }) => {
    const { state, cookies } = await startSignIn()
    const url = `/callback?state=${encodeURIComponent(state)}`

    await assert.rejects(
      () => driverFor(createContext(url, cookies)).user(),
      allyErrors.E_OAUTH_MISSING_CODE
    )
    assert.lengthOf(http.requests, 0)
  })

  test('does not call Graph when Microsoft refuses the code', async ({ assert }) => {
    tokenStatus = 400
    http.restore()
    mock()
    const driver = await signedInDriver()

    await assert.rejects(() => driver.user(), errors.E_ENTRA_REQUEST_FAILED)
    assert.deepEqual(
      signInRequests().map(({ url }) => url),
      [TOKEN_URL]
    )
  })

  test('userFromToken reads the profile without any token exchange', async ({ assert }) => {
    const user = await driverFor(createContext()).userFromToken('existing-token')

    assert.deepEqual(
      http.requests.map(({ url }) => url),
      [GRAPH_URL]
    )
    assert.equal(http.requests[0].headers.get('authorization'), 'Bearer existing-token')
    assert.equal(user.id, 'object-id')
    assert.deepEqual(user.token, { token: 'existing-token', type: 'bearer' })
    assert.notProperty(user, 'tenantId')
  })

  test('userFromToken applies the caller callback', async ({ assert }) => {
    await driverFor(createContext()).userFromToken('existing-token', (request) =>
      request.header('x-custom', 'yes')
    )

    assert.equal(http.requests[0].headers.get('x-custom'), 'yes')
  })
})
