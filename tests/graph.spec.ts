import { inspect } from 'node:util'
import { test } from '@japa/runner'
import { EntraService, errors, type EntraConfig } from '../index.js'
import { createContext, mockFetch, type Reply } from './helpers.js'

const GRAPH_URL = 'https://graph.microsoft.com/v1.0/me'
const SIZED_PHOTO_URL = `${GRAPH_URL}/photos/120x120/$value`
const DEFAULT_PHOTO_URL = `${GRAPH_URL}/photo/$value`

const config: EntraConfig = {
  clientId: 'client-id',
  clientSecret: 'client-secret',
  callbackUrl: 'https://app.test/sso/azure/callback',
  tenantId: '11111111-1111-4111-8111-111111111111',
}
const profile = { id: 'object-id', displayName: 'Ada', userPrincipalName: 'ada@contoso.com' }

const photo = Buffer.from('photo-bytes')
const photoAsDataUrl = `data:image/jpeg;base64,${photo.toString('base64')}`

const photoReply = (bytes: Uint8Array = photo, contentType: string = 'image/jpeg'): Reply => ({
  body: new Response(bytes, { headers: { 'content-type': contentType } }),
})
const statusReply = (status: number): Reply => ({ body: new Response(null, { status }) })

test.group('Microsoft Graph | avatar', (group) => {
  let http: ReturnType<typeof mockFetch> | undefined

  /**
   * Reads the user with the given photo replies.
   */
  const userWith = (replies: Record<string, Reply>, driverConfig: EntraConfig = config) => {
    http = mockFetch({ [GRAPH_URL]: { body: profile }, ...replies })
    return EntraService(driverConfig)(createContext()).userFromToken('access-token')
  }
  const photoRequests = () =>
    http!.requests.filter(({ url }) => url !== GRAPH_URL).map(({ url }) => url)

  group.each.teardown(() => http?.restore())

  test('returns the small photo as a data URL', async ({ assert }) => {
    const user = await userWith({ [SIZED_PHOTO_URL]: photoReply() })

    assert.equal(user.avatarUrl, photoAsDataUrl)
    assert.deepEqual(photoRequests(), [SIZED_PHOTO_URL])
    const photoRequest = http!.requests.find(({ url }) => url === SIZED_PHOTO_URL)!
    assert.equal(photoRequest.headers.get('authorization'), 'Bearer access-token')
  })

  test('falls back to the default photo when the small one is missing', async ({ assert }) => {
    const user = await userWith({
      [SIZED_PHOTO_URL]: statusReply(404),
      [DEFAULT_PHOTO_URL]: photoReply(),
    })

    assert.equal(user.avatarUrl, photoAsDataUrl)
    assert.deepEqual(photoRequests(), [SIZED_PHOTO_URL, DEFAULT_PHOTO_URL])
  })

  test('returns null when the user has no photo', async ({ assert }) => {
    const user = await userWith({
      [SIZED_PHOTO_URL]: statusReply(404),
      [DEFAULT_PHOTO_URL]: statusReply(404),
    })

    assert.isNull(user.avatarUrl)
  })

  test('does not retry when Microsoft refuses access to the photo', async ({ assert }) => {
    const user = await userWith({
      [SIZED_PHOTO_URL]: statusReply(403),
      [DEFAULT_PHOTO_URL]: photoReply(),
    })

    assert.isNull(user.avatarUrl)
    assert.deepEqual(photoRequests(), [SIZED_PHOTO_URL])
  })

  test('ignores an image sent with an error status', async ({ assert }) => {
    const body = new Response(photo, { status: 500, headers: { 'content-type': 'image/jpeg' } })

    const user = await userWith({ [SIZED_PHOTO_URL]: { body } })

    assert.isNull(user.avatarUrl)
  })

  test('limits the time spent waiting for the photo', async ({ assert }) => {
    const originalFetch = globalThis.fetch
    const signals: (AbortSignal | null | undefined)[] = []
    const mockedFetch = () => {
      const mocked = globalThis.fetch
      globalThis.fetch = (input, init) => {
        if (String(input).includes('/photos/')) signals.push(init?.signal)
        return mocked(input, init)
      }
    }

    try {
      http = mockFetch({ [GRAPH_URL]: { body: profile }, [SIZED_PHOTO_URL]: photoReply() })
      mockedFetch()
      await EntraService(config)(createContext()).userFromToken('access-token')
    } finally {
      globalThis.fetch = originalFetch
    }

    assert.lengthOf(signals, 1)
    assert.instanceOf(signals[0], AbortSignal)
  })

  test('accepts a content type with parameters', async ({ assert }) => {
    const user = await userWith({ [SIZED_PHOTO_URL]: photoReply(photo, 'Image/PNG; charset=x') })

    assert.equal(user.avatarUrl, `data:image/png;base64,${photo.toString('base64')}`)
  })

  test('refuses {title}')
    .with([
      { title: 'an SVG, which can contain scripts', contentType: 'image/svg+xml' },
      { title: 'an HTML page', contentType: 'text/html' },
      { title: 'an empty content type', contentType: '' },
    ])
    .run(async ({ assert }, { contentType }) => {
      const body = new Response(photo)
      body.headers.delete('content-type')
      if (contentType) body.headers.set('content-type', contentType)

      const user = await userWith({ [SIZED_PHOTO_URL]: { body } })

      assert.isNull(user.avatarUrl)
    })

  test('accepts a photo at the size limit and refuses a larger one', async ({ assert }) => {
    const limit = 512 * 1024
    const atLimit = await userWith({ [SIZED_PHOTO_URL]: photoReply(Buffer.alloc(limit)) })
    assert.isNotNull(atLimit.avatarUrl)
    http!.restore()

    const tooLarge = await userWith({ [SIZED_PHOTO_URL]: photoReply(Buffer.alloc(limit + 1)) })
    assert.isNull(tooLarge.avatarUrl)
  })

  test('refuses an empty photo', async ({ assert }) => {
    const user = await userWith({ [SIZED_PHOTO_URL]: photoReply(Buffer.alloc(0)) })

    assert.isNull(user.avatarUrl)
  })

  test('still returns the user when the photo request fails', async ({ assert }) => {
    const user = await userWith({})

    assert.isNull(user.avatarUrl)
    assert.equal(user.id, 'object-id')
  })

  test('uses the configured Graph address for the photo too', async ({ assert }) => {
    const customUrl = 'https://graph.example.test/v1.0/me'

    const user = await userWith(
      {
        [customUrl]: { body: profile },
        [`${customUrl}/photos/120x120/$value`]: photoReply(),
      },
      { ...config, userInfoUrl: customUrl }
    )

    assert.equal(user.avatarUrl, photoAsDataUrl)
  })

  /**
   * Returns the error thrown when reading the profile.
   */
  const profileFailure = (reply: Reply) => {
    http = mockFetch({ [GRAPH_URL]: reply, [SIZED_PHOTO_URL]: photoReply() })
    return EntraService(config)(createContext())
      .userFromToken('secret-access-token')
      .then(
        () => undefined,
        (error: InstanceType<typeof errors.E_ENTRA_REQUEST_FAILED>) => error
      )
  }

  test('explains why the profile cannot be read', async ({ assert }) => {
    const failure = await profileFailure({
      status: 401,
      body: { error: { code: 'InvalidAuthenticationToken', message: 'Token expired' } },
    })

    assert.instanceOf(failure, errors.E_ENTRA_REQUEST_FAILED)
    assert.equal(failure!.message, 'Microsoft refused the request: InvalidAuthenticationToken')
    assert.equal(failure!.description, 'Token expired')
    assert.equal(failure!.responseStatus, 401)
    assert.isTrue(failure!.requiresSignIn)
  })

  test('handles a profile error that is not JSON', async ({ assert }) => {
    const failure = await profileFailure({ body: new Response('Bad gateway', { status: 403 }) })

    assert.instanceOf(failure, errors.E_ENTRA_REQUEST_FAILED)
    assert.equal(failure!.responseStatus, 403)
    assert.isFalse(failure!.requiresSignIn)
  })

  test('does not keep the access token in a profile error', async ({ assert }) => {
    const failure = await profileFailure({ status: 403, body: {} })

    assert.notInclude(inspect(failure, { depth: 20, showHidden: true }), 'secret-access-token')
  })

  test('does not keep the access token after a network failure', async ({ assert }) => {
    const originalFetch = globalThis.fetch
    globalThis.fetch = async (input, init) => {
      const request = new Request(input, init)
      throw Object.assign(new Error('Request timed out'), { request })
    }

    try {
      const failure = await EntraService(config)(createContext())
        .userFromToken('secret-access-token')
        .then(
          () => undefined,
          (error: InstanceType<typeof errors.E_ENTRA_REQUEST_FAILED>) => error
        )

      assert.instanceOf(failure, errors.E_ENTRA_REQUEST_FAILED)
      assert.equal((failure!.cause as Error).message, 'Request timed out')
      assert.notInclude(inspect(failure, { depth: 20, showHidden: true }), 'secret-access-token')
    } finally {
      globalThis.fetch = originalFetch
    }
  })

  test('does not hide a bug in the caller callback', async ({ assert }) => {
    http = mockFetch({ [GRAPH_URL]: { body: profile }, [SIZED_PHOTO_URL]: photoReply() })
    const driver = EntraService(config)(createContext())

    await assert.rejects(
      () =>
        driver.userFromToken('token', () => {
          throw new TypeError('bug in the callback')
        }),
      'bug in the callback'
    )
  })
})
