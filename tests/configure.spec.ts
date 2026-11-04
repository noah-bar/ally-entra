import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import Configure from '@adonisjs/core/commands/configure'
import { IgnitorFactory } from '@adonisjs/core/factories/core/ignitor'
import { test } from '@japa/runner'
import { configure, stubsRoot } from '../index.js'

const ENV_FILE = `import { Env } from '@adonisjs/core/env'

export default await Env.create(new URL('../', import.meta.url), {
  NODE_ENV: Env.schema.string(),
})
`
const RC_FILE = `import { defineConfig } from '@adonisjs/core/app'

export default defineConfig({})
`

test.group('configure', (group) => {
  let root: string

  group.each.setup(async () => {
    root = await mkdtemp(join(tmpdir(), 'ally-entra-'))
    await mkdir(join(root, 'start'))
    await mkdir(join(root, 'config'))
    await writeFile(join(root, 'tsconfig.json'), '{ "compilerOptions": {} }')
    await writeFile(join(root, 'adonisrc.ts'), RC_FILE)
    await writeFile(join(root, 'start/env.ts'), ENV_FILE)
    await writeFile(join(root, '.env'), 'NODE_ENV=development\n')
    return () => rm(root, { recursive: true, force: true })
  })

  const read = (path: string) => readFile(join(root, path), 'utf8')

  /**
   * Runs the configure hook against the temporary application.
   */
  async function run() {
    const ignitor = new IgnitorFactory()
      .withCoreProviders()
      .withCoreConfig()
      .create(pathToFileURL(`${root}/`))
    const app = ignitor.createApp('console')
    await app.init()
    await app.boot()

    const ace = await app.container.make('ace')
    ace.ui.switchMode('raw')

    const command = await ace.create(Configure, ['@hxtc/ally-entra'])
    await configure(command)

    return command
  }

  test('exports the hook and the stubs for the configure command', ({ assert }) => {
    assert.isFunction(configure)
    assert.match(stubsRoot, /stubs$/)
  })

  test('creates the configuration when there is none', async ({ assert }) => {
    await run()

    const config = await read('config/ally.ts')
    assert.include(config, "import { EntraService } from '@hxtc/ally-entra'")
    assert.include(config, "clientSecret: env.get('ENTRA_CLIENT_SECRET').release()")
    assert.include(config, "`${env.get('APP_URL')}/oauth/entra/callback`")
    assert.include(config, 'InferSocialProviders')
  })

  test('registers the Ally provider', async ({ assert }) => {
    await run()

    assert.include(await read('adonisrc.ts'), '@adonisjs/ally/ally_provider')
  })

  test('defines the variables, with a tenant the driver accepts', async ({ assert }) => {
    await run()

    const env = await read('.env')
    assert.include(env, 'ENTRA_CLIENT_ID=placeholder')
    assert.include(env, 'ENTRA_CLIENT_SECRET=placeholder')
    assert.include(env, 'ENTRA_TENANT_ID=00000000-0000-0000-0000-000000000000')
    assert.include(env, 'NODE_ENV=development')
  })

  test('declares the secret as a secret in the validations', async ({ assert }) => {
    await run()

    const validations = await read('start/env.ts')
    assert.include(validations, 'ENTRA_CLIENT_ID: Env.schema.string()')
    assert.include(validations, 'ENTRA_CLIENT_SECRET: Env.schema.secret()')
    assert.include(validations, 'ENTRA_TENANT_ID: Env.schema.string()')
  })

  test('keeps the values already defined', async ({ assert }) => {
    await writeFile(join(root, '.env'), 'ENTRA_CLIENT_SECRET=my-real-secret\n')

    await run()

    const env = await read('.env')
    assert.include(env, 'ENTRA_CLIENT_SECRET=my-real-secret')
    assert.notInclude(env, 'ENTRA_CLIENT_SECRET=placeholder')
    assert.include(env, 'ENTRA_CLIENT_ID=placeholder')
  })

  test('adds the driver to an existing configuration', async ({ assert }) => {
    await writeFile(
      join(root, 'config/ally.ts'),
      `import { defineConfig, services } from '@adonisjs/ally'

const allyConfig = defineConfig({
  github: services.github({ clientId: '', clientSecret: '', callbackUrl: '' }),
})

export default allyConfig
`
    )

    await run()

    const config = await read('config/ally.ts')
    assert.include(config, 'github: services.github(')
    assert.include(config, "\nimport { EntraService } from '@hxtc/ally-entra'\n")
    assert.include(config, "\nimport env from '#start/env'\n")
    assert.include(config, "\n  entra: EntraService({\n    clientId: env.get('ENTRA_CLIENT_ID'),\n")
  })

  test('does not import env twice', async ({ assert }) => {
    await writeFile(
      join(root, 'config/ally.ts'),
      `import env from '#start/env'
import { defineConfig } from '@adonisjs/ally'

export default defineConfig({})
`
    )

    await run()

    const config = await read('config/ally.ts')
    assert.lengthOf(config.match(/#start\/env/g)!, 1)
    assert.include(config, 'entra: EntraService({')
  })

  test('can run twice without changing anything', async ({ assert }) => {
    await run()
    const env = await read('.env')
    await writeFile(
      join(root, '.env'),
      env.replace('ENTRA_CLIENT_SECRET=placeholder', 'ENTRA_CLIENT_SECRET=real')
    )
    const firstConfig = await read('config/ally.ts')
    const firstRc = await read('adonisrc.ts')

    await run()

    assert.equal(await read('config/ally.ts'), firstConfig)
    assert.equal(await read('adonisrc.ts'), firstRc)
    assert.include(await read('.env'), 'ENTRA_CLIENT_SECRET=real')
    const validations = await read('start/env.ts')
    assert.lengthOf(validations.match(/ENTRA_CLIENT_ID:/g)!, 1)
  })

  test('keeps a configuration it cannot understand and explains what to add', async ({
    assert,
  }) => {
    const custom = 'export default { entra: true }\n'
    await writeFile(join(root, 'config/ally.ts'), custom)

    const command = await run()

    assert.equal(await read('config/ally.ts'), custom)
    const logs = command.logger.getLogs().map(({ message }) => message)
    assert.isTrue(logs.some((message) => message.includes('entra: EntraService({')))
  })
})
