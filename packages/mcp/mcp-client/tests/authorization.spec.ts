import { Context } from '@deepseek-ai/cordis'
import { credentialKey } from '@deepseek-ai/dsh-credentials'
import { expect, it, vi } from 'vitest'
import { MemoryCredentials } from '../../../credentials/authorization/tests/memory.ts'
import { resolveOAuthConfig } from '../src/oauth.ts'

const fixture = vi.hoisted(() => ({ bind: vi.fn() }))
vi.mock('../src/oauth-redirect.ts', () => ({ startRedirectListener: fixture.bind }))
vi.mock('../src/oauth.ts', async original => ({
  ...await original<typeof import('../src/oauth.ts')>(),
  createOAuthSession: (options: { presentAuthorization(url: URL): void }) => ({
    authorize: async () => { options.presentAuthorization(new URL('https://example.test/authorize')); return 'REDIRECT' },
    pendingState: async () => 'test-state',
  }),
}))
import { registerMcpAuthorization } from '../src/authorization.ts'

it('cancels while the callback port is binding without presenting a dead link or leaving the listener open', async () => {
  const ctx = new Context()
  await ctx.plugin(MemoryCredentials)
  const pending = Promise.withResolvers<{ settled: Promise<{ kind: 'timeout' }>; dispose(): Promise<void> }>()
  fixture.bind.mockReturnValue(pending.promise)
  const dispose = vi.fn(async () => {})
  const notify = vi.fn()
  const reconnect = vi.fn()
  try {
    await registerMcpAuthorization(ctx, 'fixture', 'https://example.test/mcp', resolveOAuthConfig({ redirectPort: 4000 }, 'fixture', 'test'), reconnect)
    const key = credentialKey('mcp-client', 'fixture')
    const attempt = ctx.authorization.begin({ key, interaction: { notify, prompt: async () => '' } })
    await expect.poll(() => fixture.bind.mock.calls.length).toBe(1)
    ctx.authorization.cancel(key)
    expect(await attempt).toEqual({ status: 'cancelled' })
    pending.resolve({ settled: new Promise(() => {}), dispose })
    await expect.poll(() => dispose.mock.calls.length).toBe(1)
    expect(notify).not.toHaveBeenCalled()
    expect(reconnect).not.toHaveBeenCalled()
    expect(await ctx.credentials.readRecord(key)).toBeUndefined()
  } finally { await ctx.fiber.dispose() }
})
