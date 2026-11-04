# @hxtc/ally-entra

[![gh-workflow-image]][gh-workflow-url] [![npm-image]][npm-url] ![][typescript-image] [![license-image]][license-url]

A [Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity-platform/) (formerly Azure AD) driver for [AdonisJS Ally](https://docs.adonisjs.com/guides/authentication/social-authentication).

It signs users in with OpenID Connect, validates what Microsoft returns, and gives your application the tenant, roles and groups of the user.

- **Secure sign-in:** authorization code flow with PKCE, `state` and `nonce`
- **ID token validation:** signature, audience, issuer, expiry, nonce and tenant
- **Authorization data:** `tenantId`, `roles` and `groups`, with groups overage detection
- **Client secret or certificate** authentication
- **Token refresh** with `refreshAccessToken()`
- **Sign-out** from Microsoft with `logoutUrl()`
- **Profile photo** as `avatarUrl`
- **Readable errors** that carry the Microsoft `AADSTS` code

This is a community package. It is not affiliated with Microsoft or AdonisJS.

## Requirements

- Node.js 24 or later
- AdonisJS 7
- `@adonisjs/ally` 6.3.2 or later

## Installation

```sh
node ace add @hxtc/ally-entra
```

This command:

- creates `config/ally.ts`, or adds the `entra` provider to your existing file
- registers the Ally provider in `adonisrc.ts`
- adds the `ENTRA_*` variables to `.env` and `.env.example`, without replacing existing values
- adds their validation to `start/env.ts`

The generated values are placeholders. Replace them after setting up Azure.

```dotenv
ENTRA_CLIENT_ID=placeholder
ENTRA_CLIENT_SECRET=placeholder
ENTRA_TENANT_ID=00000000-0000-0000-0000-000000000000
```

## Azure setup

In the [Microsoft Entra admin center](https://entra.microsoft.com), open **App registrations** and select **New registration**.

1. Choose the supported account types.
2. Add a **Web** redirect URI, such as `http://localhost:3333/oauth/entra/callback`. It must exactly match the `callbackUrl` of your configuration.
3. After creating the application, copy these values from **Overview**:
   - **Application (client) ID** into `ENTRA_CLIENT_ID`
   - **Directory (tenant) ID** into `ENTRA_TENANT_ID`
4. In **Certificates & secrets**, create a client secret and copy its **Value** into `ENTRA_CLIENT_SECRET`. To use a certificate instead, see [Certificate authentication](#certificate-authentication).

### Roles and groups

Both are optional, and both are read from the ID token.

- **Roles:** create them in **App roles**, for **Users/Groups**. Then assign them in **Enterprise applications**, under **Users and groups**.
- **Groups:** in **Token configuration**, select **Add groups claim**, and enable the group types you need under the **ID** token.

## Usage

```ts
import router from '@adonisjs/core/services/router'

router.get('/oauth/entra/redirect', ({ ally }) => {
  return ally.use('entra').redirect()
})

router.get('/oauth/entra/callback', async ({ ally }) => {
  const entra = ally.use('entra')

  if (entra.accessDenied()) {
    return 'You cancelled the sign-in'
  }
  if (entra.stateMisMatch()) {
    return 'The sign-in expired, please try again'
  }
  if (entra.hasError()) {
    return 'The sign-in failed, please try again'
  }

  const user = await entra.user()

  return {
    id: user.id,
    tenantId: user.tenantId,
    name: user.name,
    roles: user.roles,
  }
})
```

### The user object

| Property | Description |
| --- | --- |
| `id` | The Microsoft Graph ID of the user |
| `tenantId` | The tenant the user signed in to, from the validated ID token |
| `name`, `nickName` | The display name, or the user principal name if there is none |
| `email` | The `mail` Graph property, which is `null` for many accounts |
| `emailVerificationState` | Always `unsupported` |
| `avatarUrl` | The photo as a `data:` URL, or `null` |
| `roles` | The app roles assigned to the user |
| `groups` | The IDs of the groups of the user |
| `hasGroupsOverage` | `true` when `groups` is incomplete |
| `token` | The tokens, with `idTokenClaims` holding the validated claims |
| `original` | The raw Graph response, such as `original.userPrincipalName` |

A few rules when using it:

- Pick the properties you need: `user` holds the tokens, so never return it as a whole from a route or log it.
- Identify users with `tenantId` and `id`, never with `email` or `userPrincipalName`, which can change and are not always verified.
- When `hasGroupsOverage` is `true`, `groups` is incomplete, so do not use it for access decisions. The driver does not fetch the missing groups.

`userFromToken()` only returns the Graph data, since there is no ID token to read `tenantId`, `roles` and `groups` from.

> [!WARNING]
> **Never use `userFromToken()` to authenticate a user.** It accepts any valid Microsoft Graph token, even one issued to another application or from another tenant, and ignores `allowedTenants`. A malicious application could use a token obtained from a victim to sign in as them. Only use it with a token your application obtained itself.

### Avatar

`avatarUrl` holds the image itself as a `data:` URL, since Microsoft photos require an access token. It can reach about 680 KB, so **do not store it in a cookie or a cookie-based session**.

It is `null` when no suitable photo is available, and a photo never makes a sign-in fail.

The photo is read during the sign-in, and a slow Microsoft Graph can delay it by up to 10 seconds. If you do not use it, turn it off with `fetchAvatar: false` in the driver configuration. `avatarUrl` is then always `null`.

## Scopes

By default, the driver requests `openid`, `profile`, `email` and `User.Read`.

To change them for every sign-in, set `scopes` in the driver configuration:

```ts
EntraService({
  // ...
  scopes: ['openid', 'profile', 'email', 'User.Read', 'Calendars.Read'],
})
```

To change them for a single sign-in, **call `clearScopes()` first**:

```ts
import router from '@adonisjs/core/services/router'

router.get('/oauth/entra/redirect', ({ ally }) => {
  return ally.use('entra').redirect((request) => {
    request.clearScopes().scopes(['openid', 'profile', 'email', 'User.Read', 'Calendars.Read'])
  })
})
```

Without `clearScopes()`, the current `@poppinss/oauth-client` release sends the `scope` parameter twice, and Microsoft rejects the request with `AADSTS9000411`. The issue is fixed upstream, but not released yet. `mergeScopes()` has the same issue, so avoid it.

Keep `openid`, as the driver requires an ID token, and `User.Read`, as `user()` reads the Graph profile.

## Sign-in page

Microsoft sign-in parameters can be set when redirecting:

```ts
import router from '@adonisjs/core/services/router'

router.get('/oauth/entra/redirect', ({ ally }) => {
  return ally.use('entra').redirect((request) => {
    request.param('prompt', 'select_account')
  })
})
```

| Parameter | Effect |
| --- | --- |
| `prompt` | `select_account` always shows the account picker, `login` asks for credentials again, `consent` shows the consent screen, and `none` fails if the user would have to do anything |
| `login_hint` | Fills in the account name. The user can still change it, so it proves nothing |
| `domain_hint` | Skips the account lookup, and goes straight to the identity provider of that domain |

## Refreshing tokens

Request the `offline_access` scope to receive a refresh token:

```ts
import router from '@adonisjs/core/services/router'

router.get('/oauth/entra/redirect', ({ ally }) => {
  return ally.use('entra').redirect((request) => {
    request.clearScopes().scopes(['openid', 'profile', 'email', 'User.Read', 'offline_access'])
  })
})
```

`user.token.refreshToken` then holds a token to store securely, encrypted and on the server. Exchange it when the access token expires:

```ts
import type { HttpContext } from '@adonisjs/core/http'

export async function refreshTokens({ ally }: HttpContext, storedRefreshToken: string) {
  const tokens = await ally.use('entra').refreshAccessToken(storedRefreshToken)

  // Store it: it replaces the previous refresh token
  const nextRefreshToken = tokens.refreshToken

  return { accessToken: tokens.token, expiresAt: tokens.expiresAt, nextRefreshToken }
}
```

The result has no `tenantId`, `roles` or `groups`. Microsoft advises against relying on an ID token obtained from a refresh, so the driver leaves it out. These values are only as recent as the last sign-in.

## Signing out

Ending your own session does not end the Microsoft one, so the user may be signed back in without any prompt. To sign them out completely, do both:

```ts
import router from '@adonisjs/core/services/router'
import env from '#start/env'

router.post('/logout', ({ ally, response, session }) => {
  session.clear()

  const logoutUrl = ally.use('entra').logoutUrl({
    postLogoutRedirectUrl: `${env.get('APP_URL')}/`,
  })

  return response.redirect(logoutUrl)
})
```

Microsoft only redirects to an address registered as a redirect URI of your application. Otherwise, it shows its own sign-out page.

To skip the account picker, enable the `login_hint` optional claim in **Token configuration**, store `user.token.idTokenClaims.login_hint` at sign-in, and pass it as `logoutHint`.

## Certificate authentication

Use a certificate instead of a client secret by passing it to the driver. The private key stays on your server.

Generate a certificate. The private key must be RSA and unencrypted:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=my-app" -keyout entra.key -out entra.pem
```

In **Certificates & secrets**, upload `entra.pem` under **Certificates**. Keep `entra.key` out of Git. Then pass the contents of both files instead of `clientSecret`:

```ts
import { readFileSync } from 'node:fs'
import { EntraService } from '@hxtc/ally-entra'
import env from '#start/env'

export const entra = EntraService({
  clientId: env.get('ENTRA_CLIENT_ID'),
  tenantId: env.get('ENTRA_TENANT_ID'),
  callbackUrl: `${env.get('APP_URL')}/oauth/entra/callback`,
  certificate: {
    certificate: readFileSync('secrets/entra.pem', 'utf8'),
    privateKey: readFileSync('secrets/entra.key', 'utf8'),
  },
})
```

Define either `clientSecret` or `certificate`, not both. A configuration with an unreadable key, a non-RSA key, or a key that does not match the certificate is refused at boot.

## Multiple tenants

By default, `tenantId` is the GUID of your tenant, and only this tenant can sign in.

The shared authorities `organizations`, `common` and `consumers` accept accounts from other tenants, which is rarely what a business application wants. The driver therefore requires you to list the accepted tenants:

```ts
import { EntraService } from '@hxtc/ally-entra'
import env from '#start/env'

export const entra = EntraService({
  clientId: env.get('ENTRA_CLIENT_ID'),
  clientSecret: env.get('ENTRA_CLIENT_SECRET').release(),
  callbackUrl: `${env.get('APP_URL')}/oauth/entra/callback`,
  tenantId: 'organizations',
  allowedTenants: ['11111111-1111-4111-8111-111111111111'],
})
```

A sign-in from any other tenant fails with `E_ENTRA_TENANT_NOT_ALLOWED`.

## Errors

The errors are available from the `errors` export.

| Error | Status | When |
| --- | --- | --- |
| `E_ENTRA_REQUEST_FAILED` | 401 or 500 | Microsoft refused a sign-in, a token request or the Graph profile, or could not be reached |
| `E_ENTRA_INVALID_ID_TOKEN` | 401 | The ID token is missing or failed validation |
| `E_ENTRA_TENANT_NOT_ALLOWED` | 403 | The tenant is not in `allowedTenants` |
| `E_ENTRA_INVALID_CONFIG` | 500 | The driver configuration is invalid, at boot |

`E_ENTRA_REQUEST_FAILED` has these properties:

| Property | Description |
| --- | --- |
| `requiresSignIn` | `true` when the user has to sign in again |
| `microsoftError` | The OAuth error, such as `invalid_grant` |
| `aadstsCode` | The detailed code, such as `AADSTS7000215` |
| `description` | The full Microsoft description |
| `traceId`, `correlationId` | The identifiers to give to Microsoft support |
| `responseStatus` | The HTTP status of the Microsoft response |

```ts
import type { HttpContext } from '@adonisjs/core/http'
import logger from '@adonisjs/core/services/logger'
import { errors } from '@hxtc/ally-entra'

export async function callback({ ally, response }: HttpContext) {
  try {
    const user = await ally.use('entra').user()
    return { id: user.id, name: user.name }
  } catch (error) {
    if (error instanceof errors.E_ENTRA_REQUEST_FAILED) {
      logger.error({ code: error.aadstsCode, traceId: error.traceId }, error.message)

      if (error.requiresSignIn) {
        return response.redirect('/oauth/entra/redirect')
      }
    }

    throw error
  }
}
```

The error message only holds the codes, and is safe to show. Keep `description` for your logs: it is detailed, and with `stateless()` it comes from a URL that was not verified.

To use the error as a type, write `InstanceType<typeof errors.E_ENTRA_REQUEST_FAILED>`.

## Security notes

`stateless()` only disables the `state` check: the `nonce` cookie is still required.

The driver validates the sign-in, but you remain responsible for:

- authorizing users, as a valid Microsoft sign-in does not mean they may use your application
- storing refresh tokens and private keys securely
- not logging the driver object, which holds your credentials
- not enabling the Ally debug output in production, as it can print tokens
- enabling **Assignment required** in **Enterprise applications**, if only assigned users should be able to sign in

## Limitations

Not supported yet:

- fetching the groups of a user in overage
- national clouds, such as Azure Government or Azure China
- Azure AD B2C

## Contributing

Issues and pull requests are welcome. For a new feature, please open an issue first to discuss it.

This project follows the [AdonisJS contribution guide](https://github.com/adonisjs/.github/blob/main/docs/CONTRIBUTING.md). Before opening a pull request, run:

```sh
npm install
npm test
```

## License

[MIT](LICENSE)

[gh-workflow-image]: https://img.shields.io/github/actions/workflow/status/noah-bar/ally-entra/checks.yml?style=for-the-badge
[gh-workflow-url]: https://github.com/noah-bar/ally-entra/actions/workflows/checks.yml 'GitHub Actions'
[npm-image]: https://img.shields.io/npm/v/@hxtc/ally-entra/latest.svg?style=for-the-badge&logo=npm
[npm-url]: https://www.npmjs.com/package/@hxtc/ally-entra/v/latest 'npm'
[typescript-image]: https://img.shields.io/badge/Typescript-294E80.svg?style=for-the-badge&logo=typescript
[license-image]: https://img.shields.io/github/license/noah-bar/ally-entra?style=for-the-badge
[license-url]: LICENSE
