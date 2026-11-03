import { createHash } from 'node:crypto'
import { errors } from '@adonisjs/ally'
import type { HttpContext } from '@adonisjs/core/http'
import { test } from '@japa/runner'
import { EntraService, type EntraConfig } from '../index.js'
import { browserCookies, cookieChanges, createContext, mockFetch } from './helpers.js'

const config: EntraConfig = {
  clientId: 'client-id',
  clientSecret: 'client-secret',
  callbackUrl: 'https://app.test/sso/azure/callback',
  tenantId: 'tenant-id',
}

const AUTHORIZE_URL = 'https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize'
const TOKEN_URL = 'https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token'
const GRAPH_URL = 'https://graph.microsoft.com/v1.0/me'

const tokenReply = {
  body: { access_token: 'access-token', token_type: 'Bearer', expires_in: 3600 },
}
const profile = {
  id: 'object-id',
  displayName: 'Ada Lovelace',
  mail: 'ada@contoso.com',
  userPrincipalName: 'ada_contoso.com#EXT#@contoso.onmicrosoft.com',
}

const STATE_COOKIE = 'entra_oauth_state'
const VERIFIER_COOKIE = 'entra_oauth_code_verifier'

const driverFor = (ctx: HttpContext) => EntraService(config)(ctx)

/**
 * Starts a sign-in and returns what the browser holds when Microsoft sends
 * the user back.
 */
async function startSignIn() {
  const ctx = createContext('/sso/azure')
  await driverFor(ctx).redirect()

  const location = new URL(String(ctx.response.getHeader('location')))
  const state = location.searchParams.get('state')!

  return { ctx, location, state, cookies: browserCookies(ctx) }
}

/**
 * Returns the callback context of a legitimate sign-in.
 */
async function callbackContext(code: string = 'auth-code') {
  const { state, cookies } = await startSignIn()
  return createContext(`/callback?code=${code}&state=${encodeURIComponent(state)}`, cookies)
}

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

  test('sets the state and PKCE cookies', async ({ assert }) => {
    const { ctx } = await startSignIn()

    assert.deepEqual(cookieChanges(ctx).set, [VERIFIER_COOKIE, STATE_COOKIE])
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
    const driver = driverFor(await callbackContext())

    assert.isFalse(driver.stateMisMatch())
    assert.isFalse(driver.hasError())
    assert.isFalse(driver.accessDenied())
  })

  test('a forged state is a mismatch', async ({ assert }) => {
    const { cookies } = await startSignIn()
    const driver = driverFor(createContext('/callback?code=auth-code&state=forged', cookies))

    assert.isTrue(driver.stateMisMatch())
  })

  test('a return without the PKCE verifier cookie is a mismatch', async ({ assert }) => {
    const { state, cookies } = await startSignIn()
    const stateCookieOnly = cookies
      .split('; ')
      .filter((cookie) => cookie.startsWith(`${STATE_COOKIE}=`))
      .join('; ')
    const url = `/callback?code=auth-code&state=${encodeURIComponent(state)}`

    assert.isTrue(driverFor(createContext(url, stateCookieOnly)).stateMisMatch())
  })
})

test.group('EntraDriver | user', (group) => {
  let http: ReturnType<typeof mockFetch>

  const mock = (graphBody: unknown = profile, token: object = tokenReply) => {
    http = mockFetch({ [TOKEN_URL]: token as { body: unknown }, [GRAPH_URL]: { body: graphBody } })
    return http
  }

  group.each.setup(() => {
    mock()
    return () => http.restore()
  })

  test('completes the sign-in against the real Microsoft addresses', async ({ assert }) => {
    const { location, state, cookies } = await startSignIn()
    const ctx = createContext(
      `/callback?code=auth-code&state=${encodeURIComponent(state)}`,
      cookies
    )

    const user = await driverFor(ctx).user()

    assert.deepEqual(
      http.requests.map(({ method, url }) => `${method} ${url}`),
      [`POST ${TOKEN_URL}`, `GET ${GRAPH_URL}`]
    )

    const { body } = http.requests[0]
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

    assert.equal(http.requests[1].headers.get('authorization'), 'Bearer access-token')
    assert.equal(http.requests[1].headers.get('accept'), 'application/json')

    assert.equal(user.id, 'object-id')
    assert.equal(user.token.token, 'access-token')
    assert.equal(user.token.type, 'Bearer')
  })

  test('clears the sign-in cookies on return, so a replay is refused', async ({ assert }) => {
    const { state, cookies } = await startSignIn()
    const url = `/callback?code=auth-code&state=${encodeURIComponent(state)}`
    const ctx = createContext(url, cookies)

    await driverFor(ctx).user()
    assert.deepEqual(cookieChanges(ctx).cleared, [VERIFIER_COOKIE, STATE_COOKIE])

    http.requests.length = 0
    const replay = driverFor(createContext(url, browserCookies(ctx)))

    await assert.rejects(() => replay.user(), errors.E_OAUTH_STATE_MISMATCH)
    assert.lengthOf(http.requests, 0)
  })

  test('maps the Graph profile to the Ally user format', async ({ assert }) => {
    const user = await driverFor(await callbackContext()).user()

    assert.equal(user.name, 'Ada Lovelace')
    assert.equal(user.nickName, 'Ada Lovelace')
    assert.equal(user.email, 'ada@contoso.com')
    assert.equal(user.emailVerificationState, 'unsupported')
    assert.isNull(user.avatarUrl)
    assert.deepEqual(user.original, profile)
  })

  test('returns a null email instead of the userPrincipalName', async ({ assert }) => {
    http.restore()
    mock({ ...profile, mail: null })

    const user = await driverFor(await callbackContext()).user()

    assert.isNull(user.email)
    assert.equal(user.original.userPrincipalName, profile.userPrincipalName)
  })

  test('falls back to the userPrincipalName when displayName is missing', async ({ assert }) => {
    http.restore()
    mock({ ...profile, displayName: null })

    const user = await driverFor(await callbackContext()).user()

    assert.equal(user.name, profile.userPrincipalName)
    assert.equal(user.nickName, profile.userPrincipalName)
  })

  test('applies the caller callback to both Microsoft requests', async ({ assert }) => {
    const ctx = await callbackContext()

    await driverFor(ctx).user((request) => request.header('x-custom', 'yes'))

    assert.deepEqual(
      http.requests.map(({ headers }) => headers.get('x-custom')),
      ['yes', 'yes']
    )
  })

  test('sends nothing to Microsoft when the state is forged', async ({ assert }) => {
    const { cookies } = await startSignIn()
    const driver = driverFor(createContext('/callback?code=auth-code&state=forged', cookies))

    await assert.rejects(() => driver.user(), errors.E_OAUTH_STATE_MISMATCH)
    assert.lengthOf(http.requests, 0)
  })

  test('refuses a callback without a code', async ({ assert }) => {
    const { state, cookies } = await startSignIn()
    const url = `/callback?state=${encodeURIComponent(state)}`

    await assert.rejects(
      () => driverFor(createContext(url, cookies)).user(),
      errors.E_OAUTH_MISSING_CODE
    )
    assert.lengthOf(http.requests, 0)
  })

  test('does not call Graph when Microsoft refuses the code', async ({ assert }) => {
    http.restore()
    mock(profile, { status: 400, body: { error: 'invalid_grant' } })

    const driver = driverFor(await callbackContext())

    await assert.rejects(() => driver.user(), /400/)
    assert.deepEqual(
      http.requests.map(({ url }) => url),
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
  })

  test('userFromToken applies the caller callback', async ({ assert }) => {
    await driverFor(createContext()).userFromToken('existing-token', (request) =>
      request.header('x-custom', 'yes')
    )

    assert.equal(http.requests[0].headers.get('x-custom'), 'yes')
  })
})
