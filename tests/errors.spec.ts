import { inspect } from 'node:util'
import { errors as allyErrors } from '@adonisjs/ally'
import { test } from '@japa/runner'
import { EntraService, errors, type EntraConfig } from '../index.js'
import { browserCookies, createContext, mockFetch, type Reply } from './helpers.js'

type RequestError = InstanceType<typeof errors.E_ENTRA_REQUEST_FAILED>

const TENANT = '11111111-1111-4111-8111-111111111111'
const TOKEN_URL = `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`
const config: EntraConfig = {
  clientId: 'client-id',
  clientSecret: 'client-secret',
  callbackUrl: 'https://app.test/sso/azure/callback',
  tenantId: TENANT,
}

/**
 * Returns the driver of a browser coming back from Microsoft with `params`.
 */
async function callbackDriver(params: Record<string, string>, { validState = true } = {}) {
  const start = createContext('/sso/azure')
  await EntraService(config)(start).redirect()
  const state = new URL(String(start.response.getHeader('location'))).searchParams.get('state')!

  const query = new URLSearchParams({ ...params, ...(validState ? { state } : {}) })
  return EntraService(config)(createContext(`/callback?${query}`, browserCookies(start)))
}

test.group('EntraDriver | sign-in errors', (group) => {
  let http: ReturnType<typeof mockFetch>

  const mock = (reply: Reply) => {
    http = mockFetch({ [TOKEN_URL]: reply })
  }

  /**
   * Returns the error thrown by the sign-in.
   */
  const signInFailure = (driver: Awaited<ReturnType<typeof callbackDriver>>) =>
    driver.user().then(
      () => undefined,
      (error: RequestError) => error
    )

  group.each.setup(() => {
    mock({ status: 500, body: {} })
    return () => http.restore()
  })

  test('explains why Microsoft refused the code', async ({ assert }) => {
    http.restore()
    mock({
      status: 401,
      body: {
        error: 'invalid_client',
        error_description: 'AADSTS7000215: Invalid client secret provided',
        error_codes: [7000215],
        trace_id: 'trace-id',
        correlation_id: 'correlation-id',
      },
    })

    const failure = await signInFailure(await callbackDriver({ code: 'secret-code' }))

    assert.instanceOf(failure, errors.E_ENTRA_REQUEST_FAILED)
    assert.equal(failure!.message, 'Microsoft refused the request: invalid_client (AADSTS7000215)')
    assert.equal(failure!.name, 'E_ENTRA_REQUEST_FAILED')
    assert.equal(failure!.code, 'E_ENTRA_REQUEST_FAILED')
    assert.equal(failure!.microsoftError, 'invalid_client')
    assert.equal(failure!.aadstsCode, 'AADSTS7000215')
    assert.equal(failure!.description, 'AADSTS7000215: Invalid client secret provided')
    assert.equal(failure!.traceId, 'trace-id')
    assert.equal(failure!.correlationId, 'correlation-id')
    assert.equal(failure!.status, 500)
    assert.isFalse(failure!.requiresSignIn)
    assert.notInclude(failure!.message, 'secret-code')
    assert.lengthOf(http.requests, 1)
  })

  test('does not keep the credentials in a sign-in error', async ({ assert }) => {
    const failure = await signInFailure(await callbackDriver({ code: 'secret-code' }))

    const printed = inspect(failure, { depth: 20, showHidden: true })
    assert.notInclude(printed, 'client-secret')
    assert.notInclude(printed, 'secret-code')
    assert.equal(failure!.responseStatus, 500)
  })

  test('does not keep the credentials in a refresh error', async ({ assert }) => {
    const driver = EntraService(config)(createContext())

    const failure = await driver.refreshAccessToken('secret-refresh-token').then(
      () => undefined,
      (error: RequestError) => error
    )

    const printed = inspect(failure, { depth: 20, showHidden: true })
    assert.notInclude(printed, 'client-secret')
    assert.notInclude(printed, 'secret-refresh-token')
  })

  test('asks for a new sign-in when the code is no longer valid', async ({ assert }) => {
    http.restore()
    mock({ status: 400, body: { error: 'invalid_grant', error_codes: [70008] } })

    const failure = await signInFailure(await callbackDriver({ code: 'expired-code' }))

    assert.equal(failure!.aadstsCode, 'AADSTS70008')
    assert.equal(failure!.status, 401)
    assert.isTrue(failure!.requiresSignIn)
  })

  test('reads the AADSTS code from the description when needed', async ({ assert }) => {
    http.restore()
    mock({
      status: 400,
      body: { error: 'invalid_request', error_description: 'AADSTS900144: Missing parameter' },
    })

    const failure = await signInFailure(await callbackDriver({ code: 'code' }))

    assert.equal(failure!.aadstsCode, 'AADSTS900144')
  })

  test('handles a response that is not JSON', async ({ assert }) => {
    http.restore()
    mock({ body: new Response('Service unavailable', { status: 503 }) })

    const failure = await signInFailure(await callbackDriver({ code: 'code' }))

    assert.instanceOf(failure, errors.E_ENTRA_REQUEST_FAILED)
    assert.equal(failure!.message, 'Microsoft refused the request: unexpected response')
    assert.equal(failure!.responseStatus, 503)
  })

  test('handles a JSON response that is not an object: {title}')
    .with([
      { title: 'text', body: 'unavailable' },
      { title: 'null', body: null },
    ])
    .run(async ({ assert }, { body }) => {
      http.restore()
      mock({ status: 500, body })

      const failure = await signInFailure(await callbackDriver({ code: 'code' }))

      assert.instanceOf(failure, errors.E_ENTRA_REQUEST_FAILED)
      assert.isUndefined(failure!.microsoftError)
    })

  test('reports a network failure and keeps its cause', async ({ assert }) => {
    http.restore()
    http = mockFetch({})

    const failure = await signInFailure(await callbackDriver({ code: 'code' }))

    assert.instanceOf(failure, errors.E_ENTRA_REQUEST_FAILED)
    assert.match((failure!.cause as Error).message, /Unexpected request/)
  })

  test('does not hide a bug in the caller callback', async ({ assert }) => {
    const driver = await callbackDriver({ code: 'code' })
    const bug = new TypeError('bug in the callback')

    await assert.rejects(
      () =>
        driver.accessToken(() => {
          throw bug
        }),
      'bug in the callback'
    )
    assert.lengthOf(http.requests, 0)
  })

  test('keeps the Ally error when a success response has no token', async ({ assert }) => {
    http.restore()
    mock({ body: { token_type: 'Bearer' } })
    const failure = await signInFailure(await callbackDriver({ code: 'code' }))

    assert.equal(failure!.code, 'E_OAUTH_MISSING_TOKEN')
  })

  test('explains an error sent back by Microsoft on the callback', async ({ assert }) => {
    const driver = await callbackDriver({
      error: 'invalid_scope',
      error_description: 'AADSTS70011: The provided scope is not valid',
    })

    const failure = await signInFailure(driver)

    assert.instanceOf(failure, errors.E_ENTRA_REQUEST_FAILED)
    assert.equal(failure!.message, 'Microsoft refused the request: invalid_scope (AADSTS70011)')
    assert.equal(failure!.description, 'AADSTS70011: The provided scope is not valid')
    assert.lengthOf(http.requests, 0)
  })

  test('reports a refused consent without losing accessDenied()', async ({ assert }) => {
    const driver = await callbackDriver({ error: 'access_denied' })

    const failure = await signInFailure(driver)

    assert.isTrue(driver.accessDenied())
    assert.equal(failure!.microsoftError, 'access_denied')
    assert.isTrue(failure!.requiresSignIn)
  })

  test('does not trust a callback error without a valid state', async ({ assert }) => {
    const driver = await callbackDriver({ error: 'server_error' }, { validState: false })

    const failure = await signInFailure(driver)

    assert.notInstanceOf(failure, errors.E_ENTRA_REQUEST_FAILED)
    assert.instanceOf(failure, allyErrors.E_OAUTH_MISSING_CODE)
  })

  test('keeps forged text out of the message', async ({ assert }) => {
    const driver = await callbackDriver({
      error: '<script>alert(1)</script>',
      error_description: 'Your account is locked, call +00 000 000',
    })

    const failure = await signInFailure(driver)

    assert.equal(failure!.message, 'Microsoft refused the request: unexpected response')
  })

  test('keeps the Ally error when the code is missing', async ({ assert }) => {
    const driver = await callbackDriver({})

    await assert.rejects(() => driver.user(), allyErrors.E_OAUTH_MISSING_CODE)
  })
})

test.group('EntraDriver | refresh errors', () => {
  test('asks for a new sign-in without a refresh token', async ({ assert }) => {
    const driver = EntraService(config)(createContext())

    const failure = await driver.refreshAccessToken('').then(
      () => undefined,
      (error: RequestError) => error
    )

    assert.isTrue(failure!.requiresSignIn)
    assert.equal(failure!.status, 401)
  })
})
