import { IncomingMessage, ServerResponse } from 'node:http'
import { Socket } from 'node:net'
import { EncryptionFactory } from '@adonisjs/core/factories/encryption'
import { HttpContextFactory, RequestFactory, ResponseFactory } from '@adonisjs/core/factories/http'
import type { HttpContext } from '@adonisjs/core/http'
import { type CryptoKey, exportJWK, generateKeyPair, SignJWT } from 'jose'

const encryption = new EncryptionFactory().create()

/**
 * Creates a real HTTP context, so cookies go through the real encryption.
 */
export function createContext(url: string = '/', cookieHeader?: string): HttpContext {
  const req = new IncomingMessage(new Socket())
  const res = new ServerResponse(req)
  req.url = url
  req.method = 'GET'
  if (cookieHeader) {
    req.headers.cookie = cookieHeader
  }

  const request = new RequestFactory().merge({ req, res, encryption }).create()
  const response = new ResponseFactory().merge({ req, res, encryption }).create()
  return new HttpContextFactory().merge({ request, response }).create()
}

function setCookieHeaders(ctx: HttpContext) {
  return [ctx.response.getHeader('set-cookie') ?? []].flat().map(String)
}

/**
 * Names of the cookies the response sets, then of those it clears.
 */
export function cookieChanges(ctx: HttpContext) {
  const headers = setCookieHeaders(ctx)
  const names = (list: string[]) => list.map((cookie) => cookie.split('=')[0]).sort()

  return {
    set: names(headers.filter((cookie) => !cookie.includes('Max-Age=0'))),
    cleared: names(headers.filter((cookie) => cookie.includes('Max-Age=0'))),
  }
}

/**
 * Builds the Cookie header a browser would send back after this response.
 */
export function browserCookies(ctx: HttpContext) {
  return setCookieHeaders(ctx)
    .filter((cookie) => !cookie.includes('Max-Age=0'))
    .map((cookie) => cookie.split(';')[0])
    .join('; ')
}

export type RecordedRequest = {
  url: string
  method: string
  headers: Headers
  body: URLSearchParams
}

export type Reply = { status?: number; body: unknown | (() => unknown) }

/**
 * Replaces `fetch`, used by Ally for HTTP calls. Each URL must be declared,
 * so any request sent to an unexpected address makes the test fail.
 */
export function mockFetch(replies: Record<string, Reply>) {
  const originalFetch = globalThis.fetch
  const requests: RecordedRequest[] = []

  globalThis.fetch = async (input, init) => {
    const request = new Request(input, init)
    const reply = replies[request.url]
    if (!reply) {
      throw new Error(`Unexpected request to ${request.url}`)
    }

    requests.push({
      url: request.url,
      method: request.method,
      headers: request.headers,
      body: new URLSearchParams(await request.text()),
    })

    if (reply.body instanceof Response) {
      return reply.body.clone()
    }

    const body = typeof reply.body === 'function' ? await reply.body() : reply.body
    return Response.json(body, { status: reply.status ?? 200 })
  }

  return {
    requests,
    restore: () => {
      globalThis.fetch = originalFetch
    },
  }
}

const SIGNING_KEY_ID = 'test-key'
const signingKeyPair = await generateKeyPair('RS256', { extractable: true })

/**
 * The key set Microsoft would publish for tokens signed by `signIdToken`.
 */
export const publishedKeys = {
  keys: [
    {
      ...(await exportJWK(signingKeyPair.publicKey)),
      kid: SIGNING_KEY_ID,
      alg: 'RS256',
      use: 'sig',
    },
  ],
}

/**
 * Signs an ID token like Microsoft, or with another key when one is given.
 */
export async function signIdToken(
  claims: Record<string, unknown>,
  privateKey: CryptoKey = signingKeyPair.privateKey
) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: SIGNING_KEY_ID })
    .sign(privateKey)
}
