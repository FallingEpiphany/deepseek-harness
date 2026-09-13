import { Context } from '@deepseek-ai/cordis'
import AuthorizationService from '@deepseek-ai/dsh-authorization'
import { credentialKey } from '@deepseek-ai/dsh-credentials'
import { expect, it } from 'vitest'
import { MemoryCredentials } from '../../../credentials/authorization/tests/memory.ts'
import { AuthorizationSurface } from '../src/authorization.ts'

it('uses shared flows, isolates prompts by page, and reports success only after a credential commit', async () => {
  const ctx = new Context()
  await ctx.plugin(MemoryCredentials)
  await ctx.plugin(AuthorizationService)
  const surface = new AuthorizationSurface(ctx)
  const key = credentialKey('example', 'account')
  ctx.authorization.registerFlow({ key, label: 'Example', methods: [{ id: 'secret', label: 'Key' }],
    async run(session) {
      session.notify({ message: 'Enter a key' })
      const answer = await session.prompt({ kind: 'secret', message: 'Key' })
      await ctx.credentials.modifyRecord(key, () => Promise.resolve({ kind: 'grant', payload: { secret: answer } }))
    },
  })
  try {
    surface.begin('first', key, 'secret')
    expect(() => surface.begin('second', key, 'secret')).toThrow(/progress/)
    expect((await surface.list('first'))[0]?.prompt?.kind).toBe('secret')
    expect((await surface.list('second'))[0]).toMatchObject({ prompt: null, message: null, owned: false })
    expect(() => surface.respond('second', key, 'stolen')).toThrow(/belongs/)
    surface.respond('first', key, 'private-value')
    await expect.poll(async () => (await surface.list('first'))[0]?.state).toBe('credential-saved')
    expect(JSON.stringify(await surface.list('first'))).not.toContain('private-value')
    surface.begin('first', key, 'secret')
    surface.respond('first', key, null)
    await expect.poll(async () => (await surface.list('first'))[0]?.state).toBe('cancelled')
    expect(await ctx.credentials.readRecord(key)).toMatchObject({ payload: { secret: 'private-value' } })
  } finally { surface.dispose(); await ctx.fiber.dispose() }
})

it('does not mistake a previously saved credential for a newly committed authorization', async () => {
  const ctx = new Context()
  await ctx.plugin(MemoryCredentials)
  await ctx.plugin(AuthorizationService)
  const key = credentialKey('example', 'account')
  await ctx.credentials.modifyRecord(key, () => Promise.resolve({ kind: 'grant', payload: {} }))
  ctx.authorization.registerFlow({ key, label: 'Example', methods: [{ id: 'noop', label: 'No-op' }], run: async () => {} })
  const surface = new AuthorizationSurface(ctx)
  try {
    surface.begin('page', key, 'noop')
    await expect.poll(async () => (await surface.list('page'))[0]?.state).toBe('failed')
  } finally { surface.dispose(); await ctx.fiber.dispose() }
})
