/**
 * The authorization-code flow against a real authorization server.
 *
 * The server is the MCP SDK's own in-memory provider mounted on the SDK's own
 * router, so the client is exercised against the protocol implementation it
 * will meet in production rather than against this repository's idea of one.
 * The express app is built here rather than through the SDK's `setupAuthServer`
 * helper because that helper starts its listener without returning a handle,
 * and a spec that cannot close a port is a spec that leaks one.
 *
 * Discovery is pre-seeded through the provider's own discovery record, which is
 * the supported way to skip RFC 9728 without a resource server in the test.
 */

import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import express from 'express'
import { describe, expect, it } from 'vitest'
import { DemoInMemoryAuthProvider } from '@modelcontextprotocol/sdk/examples/server/demoInMemoryOAuthProvider.js'
import { InvalidGrantError } from '@modelcontextprotocol/sdk/server/auth/errors.js'
import { createOAuthMetadata, mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js'
import type { CredentialKey, CredentialProvider, CredentialRecord } from '@deepseek-ai/dsh-credentials'
import { createOAuthSession } from '../src/oauth.ts'
import { resolveOAuthConfig } from '../src/oauth.ts'

/** Records-only stand-in for the credentials seam. */
function createFakeCredentials() {
  const stored = new Map<string, CredentialRecord>()
  return {
    stored,
    credentials: {
      async readRecord(key: CredentialKey) { return stored.get(String(key)) },
      async describeRecord(key: CredentialKey) {
        const record = stored.get(String(key))
        return { configured: record !== undefined, writable: true, ...record === undefined ? {} : { kind: record.kind } }
      },
      async listRecords() { return [...stored].map(([key, record]) => ({ key, kind: record.kind })) },
      async modifyRecord(key: CredentialKey, mutate: (current: CredentialRecord | undefined) => Promise<CredentialRecord | undefined>) {
        const next = await mutate(stored.get(String(key)))
        if (next === undefined) return stored.get(String(key))
        stored.set(String(key), next)
        return next
      },
      async deleteRecord(key: CredentialKey) { stored.delete(String(key)) },
    } as unknown as CredentialProvider,
  }
}

/** A running authorization server: the SDK's router plus the port it answers on. */
async function startAuthorizationServer(options: { refuseRefresh?: boolean } = {}) {
  const app = express()
  app.use(express.json())
  app.use(express.urlencoded({ extended: true }))
  const httpServer = createServer(app)
  await new Promise<void>((resolve) => { httpServer.listen(0, '127.0.0.1', resolve) })
  const port = (httpServer.address() as AddressInfo).port
  const issuerUrl = new URL(`http://127.0.0.1:${port}`)
  const provider = new DemoInMemoryAuthProvider()
  if (options.refuseRefresh === true) {
    // The demo provider answers any refresh token with a fresh grant, so it can
    // never produce the refusal this scenario needs; only that one method is
    // replaced, and the rest of the flow stays the SDK's own implementation.
    provider.exchangeRefreshToken = async () => {
      throw new InvalidGrantError('the refresh token was revoked')
    }
  }
  const scopes = ['mcp:tools']
  app.use(mcpAuthRouter({ provider, issuerUrl, scopesSupported: scopes }))
  return {
    issuerUrl,
    metadata: createOAuthMetadata({ provider, issuerUrl, scopesSupported: scopes }),
    async close() { await new Promise<void>((resolve) => { httpServer.closeAllConnections(); httpServer.close(() => { resolve() }) }) },
  }
}

/** One session wired to a fake store, with the issued authorization URLs captured. */
async function createSession(serverUrl: string, options: { scopes?: string[] } = {}) {
  const fake = createFakeCredentials()
  const presented: URL[] = []
  const session = createOAuthSession({
    credentials: fake.credentials,
    serverName: 'alpha',
    config: resolveOAuthConfig({ redirectPort: 41_901, scopes: options.scopes ?? ['mcp:tools'] }, 'alpha', 'test.oauth'),
    presentAuthorization: (url) => { presented.push(url) },
  })
  return { ...fake, session, presented, serverUrl }
}

/** Follow the authorization URL to the code the server issues on its redirect. */
async function followAuthorization(authorizationUrl: URL): Promise<{ code: string; state: string }> {
  const response = await fetch(authorizationUrl, { redirect: 'manual' })
  const location = response.headers.get('location')
  expect(location, `expected the authorization server to redirect, got HTTP ${response.status}`).toBeTruthy()
  const redirect = new URL(location ?? '')
  return { code: redirect.searchParams.get('code') ?? '', state: redirect.searchParams.get('state') ?? '' }
}

describe('authorization-code flow end to end', () => {
  it('runs discovery, registration, redirect, and exchange, then stores the grant', async () => {
    const authServer = await startAuthorizationServer()
    const serverUrl = 'https://mcp.example/mcp'
    const run = await createSession(serverUrl)
    try {
      // Pre-seeding discovery is the supported way to skip RFC 9728 here; the
      // metadata is the same document the server advertises.
      await run.session.provider.saveDiscoveryState?.({
        authorizationServerUrl: authServer.issuerUrl.href,
        authorizationServerMetadata: authServer.metadata,
      })

      const first = await run.session.authorize({ serverUrl })
      expect(first).toBe('REDIRECT')
      expect(run.session.awaitingUser).toBe(true)
      expect(run.presented).toHaveLength(1)

      const callback = await followAuthorization(run.presented[0] as URL)
      const code = await run.session.acceptCallback(callback)
      const second = await run.session.authorize({ serverUrl, authorizationCode: code })

      expect(second).toBe('AUTHORIZED')
      expect(run.session.awaitingUser).toBe(false)
      const tokens = await run.session.provider.tokens()
      expect(typeof tokens?.access_token).toBe('string')
      expect(tokens?.access_token).not.toBe('')
      expect(await run.session.provider.clientInformation()).toBeTruthy()
    } finally {
      await authServer.close()
    }
  })

  it('runs the same flow for a server that requests no scope', async () => {
    const authServer = await startAuthorizationServer()
    const serverUrl = 'https://mcp.example/mcp'
    const run = await createSession(serverUrl, { scopes: [] })
    try {
      await run.session.provider.saveDiscoveryState?.({
        authorizationServerUrl: authServer.issuerUrl.href,
        authorizationServerMetadata: authServer.metadata,
      })
      expect(await run.session.authorize({ serverUrl })).toBe('REDIRECT')
      // No scope is requested, so the authorization URL carries none.
      expect(run.presented[0]?.searchParams.get('scope')).toBeNull()

      const code = await run.session.acceptCallback(await followAuthorization(run.presented[0] as URL))
      expect(await run.session.authorize({ serverUrl, authorizationCode: code })).toBe('AUTHORIZED')
      expect(await run.session.provider.tokens()).toBeTruthy()
    } finally {
      await authServer.close()
    }
  })

  it('clears the stored grant and asks for authorization again when a refresh is refused', async () => {
    const authServer = await startAuthorizationServer({ refuseRefresh: true })
    const serverUrl = 'https://mcp.example/mcp'
    const run = await createSession(serverUrl)
    try {
      await run.session.provider.saveDiscoveryState?.({
        authorizationServerUrl: authServer.issuerUrl.href,
        authorizationServerMetadata: authServer.metadata,
      })
      const first = await run.session.authorize({ serverUrl })
      expect(first).toBe('REDIRECT')
      const code = await run.session.acceptCallback(await followAuthorization(run.presented[0] as URL))
      await run.session.authorize({ serverUrl, authorizationCode: code })

      // A refresh token the server will not honour stands in for a revoked
      // grant: the SDK reports invalid_grant, invalidates the tokens, and
      // restarts the flow instead of retrying with the same dead token.
      const granted = await run.session.provider.tokens()
      expect(granted?.access_token).toBeTruthy()
      await run.session.provider.saveTokens({ ...granted, access_token: granted?.access_token ?? '', token_type: granted?.token_type ?? 'bearer', refresh_token: 'revoked-refresh-token' })
      const afterFailedRefresh = await run.session.authorize({ serverUrl })

      expect(afterFailedRefresh).toBe('REDIRECT')
      expect(await run.session.provider.tokens()).toBeUndefined()
    } finally {
      await authServer.close()
    }
  })
})
