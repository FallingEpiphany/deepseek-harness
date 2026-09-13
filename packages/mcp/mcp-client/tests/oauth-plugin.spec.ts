/** Exercises the plugin entry, SDK discovery/exchange, and connection supervisor together. */
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import type { Context } from '@deepseek-ai/cordis'
import express from 'express'
import { afterEach, expect, it, vi } from 'vitest'
import { DemoInMemoryAuthProvider } from '@modelcontextprotocol/sdk/examples/server/demoInMemoryOAuthProvider.js'
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js'
import type { RedirectOutcome } from '../src/oauth-redirect.ts'
import type { McpConnection } from '../src/connections.ts'

const callback = vi.hoisted(() => ({ start: vi.fn() }))
vi.mock('../src/oauth-redirect.ts', () => ({ startRedirectListener: callback.start }))
import { apply } from '../src/index.ts'

afterEach(() => { vi.restoreAllMocks() })

it('keeps strict startup alive for authorization and reconnects after the callback', async () => {
  const app = express()
  app.use(express.json())
  app.use(express.urlencoded({ extended: true }))
  const server = createServer(app)
  await new Promise<void>((resolve) => { server.listen(0, '127.0.0.1', resolve) })
  const issuer = new URL(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)
  const presented: PromiseWithResolvers<URL> = Promise.withResolvers()
  const redirected: PromiseWithResolvers<RedirectOutcome> = Promise.withResolvers()
  const registered: PromiseWithResolvers<string> = Promise.withResolvers()
  const effects: Array<() => unknown> = []
  const records = new Map<string, unknown>()
  let shared: McpConnection | undefined
  callback.start.mockImplementation(async () => ({
    port: 41874,
    settled: redirected.promise,
    async dispose() { redirected.resolve({ kind: 'timeout' }) },
  }))
  app.use(mcpAuthRouter({ provider: new DemoInMemoryAuthProvider(), issuerUrl: issuer, scopesSupported: ['mcp:tools'] }))
  app.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => {
    res.json({ resource: `${issuer.origin}/mcp`, authorization_servers: [issuer.origin], scopes_supported: ['mcp:tools'] })
  })
  app.post('/mcp', (req, res) => {
    if (!req.headers.authorization) {
      res.setHeader('WWW-Authenticate', `Bearer resource_metadata="${issuer.origin}/.well-known/oauth-protected-resource/mcp"`)
      res.status(401).end()
      return
    }
    const request = req.body as { id?: number; method: string }
    if (request.id === undefined) { res.status(202).end(); return }
    const result = request.method === 'resources/read' ? { contents: [{ uri: 'test://protocol', text: 'shared protocol' }] }
      : request.method === 'prompts/get' ? { messages: [{ role: 'user', content: { type: 'text', text: 'shared prompt' } }] }
        : request.method === 'initialize'
          ? { protocolVersion: '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'fixture', version: '1' } }
          : { tools: [{ name: 'ping', inputSchema: { type: 'object' } }] }
    res.json({ jsonrpc: '2.0', id: request.id, result })
  })
  const context = {
    root: {},
    get: (name: string) => name === 'mcpConnections' ? { register: (_ctx: unknown, _name: string, value: McpConnection) => { shared = value; return () => {} } } : ({
      async readRecord(key: string) { return records.get(key) },
      async modifyRecord(key: string, mutate: (old: unknown) => Promise<unknown>) {
        const value = await mutate(records.get(key)); records.set(key, value); return value
      },
      async deleteRecord(key: string) { records.delete(key) },
    }),
    effect(fn: () => (() => unknown)) { const dispose = fn(); effects.push(dispose); return dispose },
    logger: { info() {}, error() {}, warn(message: string) {
      const match = /authorization required — open (\S+)/.exec(message)
      if (match?.[1]) presented.resolve(new URL(match[1]))
    } },
    tools: { register(tool: { name: string }) { registered.resolve(tool.name); return () => {} } },
  }
  try {
    await expect(apply(context as unknown as Context, {
      transport: 'streamable-http', serverName: 'fixture', url: `${issuer.origin}/mcp`, headers: {},
      failOnStartupError: true, toolCallTimeoutMs: 5000, reconnect: { enabled: false },
      oauth: { redirectPort: 41874, scopes: ['mcp:tools'] },
    })).resolves.toBeUndefined()
    const authorization = await presented.promise
    expect(callback.start).toHaveBeenCalledOnce()
    const response = await fetch(authorization, { redirect: 'manual' })
    const location = new URL(response.headers.get('location') ?? '')
    redirected.resolve({ kind: 'code', code: location.searchParams.get('code') ?? '', state: location.searchParams.get('state') ?? '' })
    expect(await registered.promise).toBe('mcp__fixture__ping')
    expect(records.has('mcp-client/fixture')).toBe(true)
    expect(await shared?.request('resources/read', { uri: 'test://protocol' })).toMatchObject({ contents: [{ text: 'shared protocol' }] })
    expect(await shared?.request('prompts/get', { name: 'workflow' })).toMatchObject({ messages: [{ content: { text: 'shared prompt' } }] })
  } finally {
    redirected.resolve({ kind: 'timeout' })
    for (const dispose of effects.reverse()) await dispose()
    await new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => { resolve() }) })
  }
})
