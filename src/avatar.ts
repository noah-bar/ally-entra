import type { GraphClient } from './graph.js'

/**
 * Small enough for a data URL, and sharp enough for an avatar.
 */
const AVATAR_SIZE = '120x120'

/**
 * Larger photos are ignored, since a data URL is meant to stay small.
 */
const MAX_AVATAR_BYTES = 512 * 1024

/**
 * Types that are safe to display. SVG is left out, since it can contain scripts.
 */
const AVATAR_CONTENT_TYPES = new Set(['image/gif', 'image/jpeg', 'image/png', 'image/webp'])

/**
 * Turns a photo response into a data URL, or null when it is not acceptable.
 */
async function photoToDataUrl(response: Response): Promise<string | null> {
  if (!response.ok) {
    return null
  }

  const contentType = response.headers.get('content-type')?.split(';')[0].trim().toLowerCase()
  if (!contentType || !AVATAR_CONTENT_TYPES.has(contentType)) {
    return null
  }

  const photo = Buffer.from(await response.arrayBuffer())
  if (photo.length === 0 || photo.length > MAX_AVATAR_BYTES) {
    return null
  }

  return `data:${contentType};base64,${photo.toString('base64')}`
}

/**
 * Returns the user avatar as a data URL. Returns null when there is none or
 * when it cannot be read, since a photo must never block a sign-in.
 */
export async function fetchAvatar(graph: GraphClient): Promise<string | null> {
  try {
    return await photoToDataUrl(await graph.fetchPhoto(AVATAR_SIZE))
  } catch {
    return null
  }
}
