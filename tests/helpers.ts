import { IncomingMessage, ServerResponse } from 'node:http'
import { Socket } from 'node:net'
import { EncryptionFactory } from '@adonisjs/core/factories/encryption'
import { HttpContextFactory, RequestFactory, ResponseFactory } from '@adonisjs/core/factories/http'
import type { HttpContext } from '@adonisjs/core/http'

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

type Reply = { status?: number; body: unknown }

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

    return Response.json(reply.body, { status: reply.status ?? 200 })
  }

  return {
    requests,
    restore: () => {
      globalThis.fetch = originalFetch
    },
  }
}
