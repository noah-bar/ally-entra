import type { ApiRequest } from '@adonisjs/ally'
import type { ApiRequestContract } from '@adonisjs/ally/types'
import { E_ENTRA_REQUEST_FAILED } from './errors.js'

export const GRAPH_ME_URL = 'https://graph.microsoft.com/v1.0/me'

const PHOTO_TIMEOUT_MS = 5000

/**
 * The fields of the Graph `/me` response used by the driver.
 */
export type GraphUser = {
  id: string
  displayName?: string | null
  mail?: string | null
  userPrincipalName: string
}

type GraphErrorBody = { error?: { code?: unknown; message?: unknown } }

/**
 * Turns a failed Graph request into a typed error. The original error is not
 * kept, since its request holds the access token and could end up in the logs.
 */
async function toRequestError(error: unknown) {
  const { message, response } = error as { message?: string; response?: Response }
  if (!response) {
    return new E_ENTRA_REQUEST_FAILED({}, { cause: new Error(message) })
  }

  const body = (await response.json().catch(() => undefined)) as GraphErrorBody | null | undefined
  const failure = new E_ENTRA_REQUEST_FAILED({
    error: body?.error?.code,
    error_description: body?.error?.message,
  })
  failure.responseStatus = response.status

  return failure
}

/**
 * Calls Microsoft Graph on behalf of the signed-in user.
 */
export class GraphClient {
  #userUrl: string
  #token: string
  #createRequest: (url: string) => ApiRequest

  constructor(userUrl: string, token: string, createRequest: (url: string) => ApiRequest) {
    this.#userUrl = userUrl
    this.#token = token
    this.#createRequest = createRequest
  }

  /**
   * Fetches the signed-in user.
   */
  async fetchUser(callback?: (request: ApiRequestContract) => void): Promise<GraphUser> {
    const request = this.#createRequest(this.#userUrl)
    request.header('Authorization', `Bearer ${this.#token}`)
    request.header('Accept', 'application/json')
    request.parseAs('json')

    /**
     * Called last, so that the caller can override the request.
     */
    if (typeof callback === 'function') {
      callback(request)
    }

    try {
      return await request.get()
    } catch (error) {
      throw await toRequestError(error)
    }
  }

  /**
   * Fetches the photo of the signed-in user in the given size. Microsoft does
   * not store every size, hence the fallback on the default photo.
   */
  async fetchPhoto(size: string): Promise<Response> {
    const response = await this.#fetchBinary(`${this.#userUrl}/photos/${size}/$value`)

    return response.status === 404 ? this.#fetchBinary(`${this.#userUrl}/photo/$value`) : response
  }

  #fetchBinary(url: string) {
    return fetch(url, {
      headers: { Authorization: `Bearer ${this.#token}` },
      signal: AbortSignal.timeout(PHOTO_TIMEOUT_MS),
    })
  }
}
