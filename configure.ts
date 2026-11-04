import { access, readFile } from 'node:fs/promises'
import { parseEnv } from 'node:util'
import type Configure from '@adonisjs/core/commands/configure'
import type { FormatCodeSettings, ObjectLiteralExpression } from 'ts-morph'
import { stubsRoot } from './stubs/main.js'

type Codemods = Awaited<ReturnType<Configure['createCodemods']>>

/**
 * The tenant placeholder is a valid GUID, since the driver refuses an invalid
 * tenant at boot, which would prevent any ace command from running.
 */
const ENV_PLACEHOLDERS = {
  ENTRA_CLIENT_ID: 'placeholder',
  ENTRA_CLIENT_SECRET: 'placeholder',
  ENTRA_TENANT_ID: '00000000-0000-0000-0000-000000000000',
}

const DRIVER_CONFIG = `EntraService({
    clientId: env.get('ENTRA_CLIENT_ID'),
    clientSecret: env.get('ENTRA_CLIENT_SECRET').release(),
    tenantId: env.get('ENTRA_TENANT_ID'),
    callbackUrl: \`\${env.get('APP_URL')}/oauth/entra/callback\`,
  })`

/**
 * Same indentation as a new AdonisJS application, for the added entry only.
 */
const FORMAT_SETTINGS: FormatCodeSettings = { indentSize: 2 }

async function exists(path: string) {
  return access(path).then(
    () => true,
    () => false
  )
}

/**
 * Adds the missing variables only, since running the command again must not
 * replace the values the developer has already defined.
 */
async function defineMissingEnvVariables(command: Configure, codemods: Codemods) {
  const envPath = command.app.makePath('.env')
  const defined = (await exists(envPath)) ? parseEnv(await readFile(envPath, 'utf8')) : {}
  const missing = Object.entries(ENV_PLACEHOLDERS).filter(([name]) => !(name in defined))

  if (missing.length > 0) {
    await codemods.defineEnvVariables(Object.fromEntries(missing))
  }
}

/**
 * Finds the object given to `defineConfig`. Kinds are compared by name, since
 * ts-morph is only available when the application installs the assembler.
 */
function findProviders(
  codemodsProject: Awaited<ReturnType<Codemods['getTsMorphProject']>>,
  path: string
) {
  const source = codemodsProject?.addSourceFileAtPathIfExists(path)
  const call = source
    ?.getDescendants()
    .find(
      (node) =>
        node.getKindName() === 'CallExpression' && node.getText().startsWith('defineConfig(')
    )
  const providers = call
    ?.getDescendants()
    .find((node) => node.getKindName() === 'ObjectLiteralExpression')

  return source && providers
    ? { source, providers: providers as unknown as ObjectLiteralExpression }
    : undefined
}

/**
 * Adds the driver to an existing configuration file.
 */
async function addDriverToConfig(command: Configure, codemods: Codemods, configPath: string) {
  const found = findProviders(await codemods.getTsMorphProject(), configPath)

  if (!found) {
    command.logger.warning(
      `Cannot update "config/ally.ts". Add this entry to "defineConfig" manually:\n  entra: ${DRIVER_CONFIG}`
    )
    return
  }

  const { source, providers } = found
  if (providers.getProperty('entra')) {
    command.logger.info('The "entra" provider is already defined in "config/ally.ts"')
    return
  }

  const addImport = (moduleSpecifier: string, statement: string) => {
    if (!source.getImportDeclaration(moduleSpecifier)) {
      const lastImport = source.getImportDeclarations().at(-1)
      source.insertStatements(lastImport ? lastImport.getChildIndex() + 1 : 0, statement)
    }
  }
  addImport('@hxtc/ally-entra', "import { EntraService } from '@hxtc/ally-entra'")
  addImport('#start/env', "import env from '#start/env'")

  providers
    .addPropertyAssignment({ name: 'entra', initializer: DRIVER_CONFIG })
    .formatText(FORMAT_SETTINGS)
  await source.save()
  command.logger.action('update config/ally.ts').succeeded()
}

/**
 * Configures the package inside an AdonisJS application. It runs with
 * `node ace add @hxtc/ally-entra`.
 */
export async function configure(command: Configure) {
  const codemods = await command.createCodemods()
  const configPath = command.app.configPath('ally.ts')

  if (await exists(configPath)) {
    await addDriverToConfig(command, codemods, configPath)
  } else {
    await codemods.makeUsingStub(stubsRoot, 'config/ally.stub', {})
  }

  await codemods.updateRcFile((rcFile) => {
    rcFile.addProvider('@adonisjs/ally/ally_provider')
  })

  await defineMissingEnvVariables(command, codemods)
  await codemods.defineEnvValidations({
    leadingComment: 'Variables for configuring the Microsoft Entra driver',
    variables: {
      ENTRA_CLIENT_ID: 'Env.schema.string()',
      ENTRA_CLIENT_SECRET: 'Env.schema.secret()',
      ENTRA_TENANT_ID: 'Env.schema.string()',
    },
  })

  command.logger.info(
    'Replace the ENTRA_* placeholders in ".env", then add "<APP_URL>/oauth/entra/callback" as a Web redirect URI of your Azure application'
  )
}
