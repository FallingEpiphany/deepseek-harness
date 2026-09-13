/** MCP protocol adapter for the shared authorization lifecycle. */
import type { Context } from '@deepseek-ai/cordis'
import { AuthorizationService, AuthorizationDeclinedError } from '@deepseek-ai/dsh-authorization'
import { createOAuthSession, requireCredentials, serverRecords } from './oauth.ts'
import type { ResolvedOAuthConfig } from './oauth.ts'
import { startRedirectListener } from './oauth-redirect.ts'

const mounting = new WeakMap<object, Promise<void>>()

/** Register MCP login with the host's shared credential-obtaining flow registry.
 * @param ctx - Owning plugin context.
 * @param serverName - Credential namespace.
 * @param serverUrl - Configured MCP endpoint.
 * @param config - Validated OAuth options.
 * @param reconnect - Resume the supervised connection after a committed grant.
 */
export async function registerMcpAuthorization(
  ctx: Context, serverName: string, serverUrl: string, config: ResolvedOAuthConfig, reconnect: () => void,
): Promise<void> {
  const credentials = requireCredentials(ctx, `mcp-client(${serverName})`)
  if (ctx.root.get('authorization') === undefined) {
    let pending = mounting.get(ctx.root)
    if (pending === undefined) {
      pending = Promise.resolve(ctx.root.plugin(AuthorizationService)).then(() => {}, (error: unknown) => {
        mounting.delete(ctx.root)
        throw error
      })
      mounting.set(ctx.root, pending)
    }
    await pending
  }
  const authorization = ctx.get('authorization')
  if (authorization === undefined) throw new Error('MCP authorization service failed to initialize')
  ctx.effect(() => authorization.registerFlow({
    key: serverRecords(serverName).tokens,
    label: `MCP: ${serverName}`,
    methods: [{ id: 'oauth', label: 'OAuth' }],
    async run(interaction) {
      interaction.signal.throwIfAborted()
      let url: URL | undefined
      const oauth = createOAuthSession({
        credentials, serverName, config, signal: interaction.signal,
        presentAuthorization(value) { url = value },
      })
      const result = await oauth.authorize({ serverUrl })
      interaction.signal.throwIfAborted()
      if (result !== 'AUTHORIZED') {
        const state = await oauth.pendingState()
        if (url === undefined || state === undefined || config.redirectPort === undefined) {
          throw new Error('MCP browser authorization requires a configured loopback callback')
        }
        const listener = await startRedirectListener({
          port: config.redirectPort, path: config.redirectPath,
          expectedState: state, timeoutMs: config.authorizationTimeoutMs,
        })
        const cancel = (): void => { void listener.dispose() }
        interaction.signal.addEventListener('abort', cancel, { once: true })
        try {
          interaction.signal.throwIfAborted()
          interaction.notify({ message: 'Continue authorization in your browser', url: url.href })
          const outcome = await listener.settled
          interaction.signal.throwIfAborted()
          if (outcome.kind === 'denied') throw new AuthorizationDeclinedError(outcome.reason)
          if (outcome.kind === 'timeout') throw new Error('MCP authorization timed out; retry sign-in')
          const code = await oauth.acceptCallback(outcome)
          if (await oauth.authorize({ serverUrl, authorizationCode: code }) !== 'AUTHORIZED') {
            throw new Error('MCP authorization did not produce a grant')
          }
        } finally {
          interaction.signal.removeEventListener('abort', cancel)
          await listener.dispose()
        }
      }
      interaction.signal.throwIfAborted()
      reconnect()
    },
  }), 'mcp-client.authorization')
}
