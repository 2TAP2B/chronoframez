import { settingsManager } from '~~/server/services/settings/settingsManager'

const _accessDeniedError = createError({
  statusCode: 403,
  statusMessage:
    'Access denied. Please contact the administrator to activate your account.',
})

async function onOIDCSuccess(event: any, { user }: { user: any }) {
  const db = useDB()
  const email = user.email || ''
  const userFromEmail = db
    .select()
    .from(tables.users)
    .where(eq(tables.users.email, email))
    .get()

  logger.chrono.info(
    'OIDC login:',
    email,
    userFromEmail ? 'Existing user' : 'New user',
  )

  if (!userFromEmail) {
    // Create a new user without admin permission
    db.insert(tables.users)
      .values({
        username: user.name || user.preferred_username || email,
        email,
        avatar: user.picture || null,
        createdAt: new Date(),
      })
      .returning()
      .get()
    // Reject login until an admin grants access
    throw _accessDeniedError
  }
  else if (userFromEmail.isAdmin === 0) {
    throw _accessDeniedError
  }
  else {
    await setUserSession(
      event,
      { user: userFromEmail },
      {
        cookie: {
          secure: false,
        },
      },
    )
  }
  return sendRedirect(event, '/')
}

function onOIDCError(_event: any, error: any) {
  logger.chrono.warn('OIDC login failed', error)
  throw createError({
    statusCode: 401,
    statusMessage: `Authentication failed: ${error.message || 'Unknown error'}`,
  })
}

export default eventHandler(async (event) => {
  const runtimeConfig = useRuntimeConfig(event) as any

  const enabled = await settingsManager.get<boolean>(
    'system',
    'auth.oidc.enabled' as any,
    Boolean(runtimeConfig.public?.oauth?.oidc?.enabled),
  )

  const clientId =
    (await settingsManager.get<string>('system', 'auth.oidc.clientId' as any, '')) ||
    runtimeConfig.oauth?.oidc?.clientId ||
    process.env.NUXT_OAUTH_OIDC_CLIENT_ID ||
    ''
  const clientSecret =
    (await settingsManager.get<string>('system', 'auth.oidc.clientSecret' as any, '')) ||
    runtimeConfig.oauth?.oidc?.clientSecret ||
    process.env.NUXT_OAUTH_OIDC_CLIENT_SECRET ||
    ''
  // openidConfig can be a full URL to the .well-known/openid-configuration endpoint
  const openidConfig =
    (await settingsManager.get<string>('system', 'auth.oidc.openidConfig' as any, '')) ||
    runtimeConfig.oauth?.oidc?.openidConfig ||
    process.env.NUXT_OAUTH_OIDC_OPENID_CONFIG ||
    ''

  if (!enabled) {
    throw createError({
      statusCode: 403,
      statusMessage: 'OIDC login is disabled.',
    })
  }

  if (!clientId || !clientSecret || !openidConfig) {
    throw createError({
      statusCode: 500,
      statusMessage:
        'OIDC is enabled but credentials are missing in system settings.',
    })
  }

  const handler = defineOAuthOidcEventHandler({
    config: {
      clientId,
      clientSecret,
      openidConfig,
      scope: ['openid', 'profile', 'email'],
    },
    onSuccess: onOIDCSuccess,
    onError: onOIDCError,
  })

  return handler(event)
})
