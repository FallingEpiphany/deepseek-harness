/** Shared reads follow host ownership and cannot resolve another Agent's server. */
import { Context } from '@deepseek-ai/cordis'
import { createScope } from '@deepseek-ai/dsh-scope'
import { expect, it } from 'vitest'
import { McpConnections } from '../src/connections.ts'

it('isolates Agent servers, inherits global servers, and unregisters on disposal', async () => {
  const root = new Context()
  const fiber = root.plugin(McpConnections)
  await fiber
  const first = createScope(root, {})
  const second = createScope(root, {})
  const connection = { async metadata() { return {} }, async request() { return {} } }
  try {
    const registry = root.get('mcpConnections')!
    const remove = registry.register(first.ctx, 'private', connection)
    expect(registry.resolve(first.ctx, 'private')).toBe(connection)
    expect(() => registry.resolve(second.ctx, 'private')).toThrow(/not configured/)
    expect(() => registry.register(first.ctx, 'private', connection)).toThrow(/already registered/)
    const removeGlobal = registry.register(root, 'global', connection)
    expect(registry.resolve(second.ctx, 'global')).toBe(connection)
    remove()
    expect(() => registry.resolve(first.ctx, 'private')).toThrow(/not configured/)
    removeGlobal()
  } finally {
    await first.dispose()
    await second.dispose()
    await root.fiber.dispose()
  }
})
