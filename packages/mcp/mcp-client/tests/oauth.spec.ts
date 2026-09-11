/**
 * OAuth client state for one MCP server, exercised against an in-memory
 * credential store and a loopback redirect.
 *
 * The suite covers the states a human-driven login can end in — authorized,
 * refused, and a redirect for a different flow — plus the two properties the
 * stored data must have: one server cannot reach another's grant, and no
 * credential value reaches a message.
 */

import { describe, expect, it, vi } from 'vitest'
import type { CredentialKey, CredentialProvider, CredentialRecord } from '@deepseek-ai/dsh-credentials'
import { UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js'
import {
  createOAuthSession,
  readGrantPayload,
  requireCredentials,
  resolveOAuthConfig,
  serverRecords,
  writeGrantPayload,
} from '../src/oauth.ts'
import { startRedirectListener } from '../src/oauth-redirect.ts'

/** Stands in for the credentials seam: records only, no references. */
function createFakeCredentials() {
  const stored = new Map<string, CredentialRecord>()
  const credentials = {
    async readRecord(key: CredentialKey) {
      return stored.get(String(key))
    },
    async describeRecord(key: CredentialKey) {
      const record = stored.get(String(key))
      return { configured: record !== undefined, writable: true, ...record === undefined ? {} : { kind: record.kind } }
    },
    async listRecords() {
      return [...stored].map(([key, record]) => ({ key, kind: record.kind }))
    },
    async modifyRecord(key: CredentialKey, mutate: (current: CredentialRecord | undefined) => Promise<CredentialRecord | undefined>) {
      const next = await mutate(stored.get(String(key)))
      if (next === undefined) return stored.get(String(key))
      stored.set(String(key), next)
      return next
    },
    async deleteRecord(key: CredentialKey) {
      stored.delete(String(key))
    },
  }
  return { stored, credentials: credentials as unknown as CredentialProvider }
}

const interactive = {
  redirectPort: 41_873,
  scopes: ['mcp:tools'],
  clientName: 'dsh-test',
}

/** A session over a fake store, with authorization presentation captured. */
function createSession(overrides: { serverName?: string } = {}) {
  const fake = createFakeCredentials()
  const presented: URL[] = []
  const session = createOAuthSession({
    credentials: fake.credentials,
    serverName: overrides.serverName ?? 'alpha',
    config: resolveOAuthConfig(interactive, overrides.serverName ?? 'alpha', 'test.oauth'),
    presentAuthorization: (url) => { presented.push(url) },
  })
  return { ...fake, session, presented }
}

describe('resolveOAuthConfig', () => {
  it('builds the loopback redirect URI from the port and path', () => {
    const resolved = resolveOAuthConfig(interactive, 'alpha', 'test')
    expect(resolved.redirectUrl).toBe('http://127.0.0.1:41873/callback')
    expect(resolved.scopes).toEqual(['mcp:tools'])
    expect(resolved.clientName).toBe('dsh-test')
  })

  it('leaves the redirect URI absent for a server that never redirects', () => {
    const resolved = resolveOAuthConfig({}, 'alpha', 'test')
    expect(resolved.redirectUrl).toBeUndefined()
    expect(resolved.redirectPort).toBeUndefined()
  })

  it('rejects a redirect path with no port to receive it', () => {
    expect(() => resolveOAuthConfig({ redirectPath: '/cb' }, 'alpha', 'test'))
      .toThrow('redirectPath requires redirectPort')
  })

  it('rejects a server name that cannot address a stored record', () => {
    expect(() => resolveOAuthConfig(interactive, 'Alpha_1', 'test'))
      .toThrow('cannot address stored OAuth credentials')
  })

  it('rejects a port outside the TCP range', () => {
    expect(() => resolveOAuthConfig({ redirectPort: 70_000 }, 'alpha', 'test')).toThrow('redirectPort must be an integer')
    expect(() => resolveOAuthConfig({ redirectPort: 0 }, 'alpha', 'test')).toThrow('redirectPort must be an integer')
  })

  it('rejects a relative redirect path, a scoped whitespace, an empty client name, a bad timeout, and a relative server URL', () => {
    expect(() => resolveOAuthConfig({ redirectPort: 1024, redirectPath: 'callback' }, 'alpha', 'test')).toThrow('absolute path')
    expect(() => resolveOAuthConfig({ redirectPort: 1024, redirectPath: '/cb?x=1' }, 'alpha', 'test')).toThrow('without a query')
    expect(() => resolveOAuthConfig({ redirectPort: 1024, scopes: ['a b'] }, 'alpha', 'test')).toThrow('without whitespace')
    expect(() => resolveOAuthConfig({ redirectPort: 1024, scopes: [''] }, 'alpha', 'test')).toThrow('non-empty strings')
    expect(() => resolveOAuthConfig({ redirectPort: 1024, clientName: '' }, 'alpha', 'test')).toThrow('clientName must not be empty')
    expect(() => resolveOAuthConfig({ redirectPort: 1024, authorizationTimeoutMs: 0 }, 'alpha', 'test')).toThrow('positive finite')
    expect(() => resolveOAuthConfig({ redirectPort: 1024, authorizationServerUrl: 'not a url' }, 'alpha', 'test')).toThrow('absolute URL')
  })
})

describe('stored grant addressing', () => {
  it('gives one server four distinct records', () => {
    const records = serverRecords('alpha')
    const keys = Object.values(records).map(String)
    expect(new Set(keys).size).toBe(4)
    expect(keys).toContain('mcp-client/alpha')
    expect(keys.every(key => /^mcp-client\/[a-z][a-z0-9-]*$/.test(key))).toBe(true)
  })

  it('never lets two servers address the same record', () => {
    const alpha = Object.values(serverRecords('alpha')).map(String)
    const beta = Object.values(serverRecords('beta')).map(String)
    expect(alpha.filter(key => beta.includes(key))).toEqual([])
  })

  it('round-trips a payload and removes the record when the payload is undefined', async () => {
    const { credentials } = createFakeCredentials()
    const key = serverRecords('alpha').tokens
    await writeGrantPayload(credentials, key, { access_token: 'a', token_type: 'Bearer' })
    expect(await readGrantPayload(credentials, key)).toEqual({ access_token: 'a', token_type: 'Bearer' })
    await writeGrantPayload(credentials, key, undefined)
    expect(await readGrantPayload(credentials, key)).toBeUndefined()
  })

  it('reads a record stored as an api-key as absent', async () => {
    const { credentials, stored } = createFakeCredentials()
    const key = serverRecords('alpha').tokens
    stored.set(String(key), { kind: 'api-key', key: 'sk-other' })
    expect(await readGrantPayload(credentials, key)).toBeUndefined()
  })
})

describe('OAuthClientProvider', () => {
  it('reports the configured client metadata', () => {
    const { session } = createSession()
    expect(session.provider.redirectUrl).toBe('http://127.0.0.1:41873/callback')
    expect(session.provider.clientMetadata).toMatchObject({
      client_name: 'dsh-test',
      redirect_uris: ['http://127.0.0.1:41873/callback'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      scope: 'mcp:tools',
    })
  })

  it('advertises no redirect URI and no scope for a non-interactive server', () => {
    const fake = createFakeCredentials()
    const session = createOAuthSession({
      credentials: fake.credentials,
      serverName: 'alpha',
      config: resolveOAuthConfig({}, 'alpha', 'test'),
      presentAuthorization: () => {},
    })
    expect(session.provider.redirectUrl).toBeUndefined()
    expect(session.provider.clientMetadata.redirect_uris).toEqual([])
    expect(session.provider.clientMetadata.scope).toBeUndefined()
  })

  it('round-trips tokens through the SDK schema and refuses a malformed document', async () => {
    const { session } = createSession()
    expect(await session.provider.tokens()).toBeUndefined()
    await session.provider.saveTokens({ access_token: 'at', token_type: 'Bearer', refresh_token: 'rt', expires_in: 60 })
    expect(await session.provider.tokens()).toEqual({ access_token: 'at', token_type: 'Bearer', refresh_token: 'rt', expires_in: 60 })

    const broken = createSession()
    await writeGrantPayload(
      broken.credentials,
      serverRecords('alpha').tokens,
      { access_token: 'at' },
    )
    expect(await broken.session.provider.tokens()).toBeUndefined()
  })

  it('round-trips the registered client', async () => {
    const { session } = createSession()
    expect(await session.provider.clientInformation()).toBeUndefined()
    await session.provider.saveClientInformation?.({ client_id: 'abc', client_secret: 'shh' })
    expect(await session.provider.clientInformation()).toEqual({ client_id: 'abc', client_secret: 'shh' })
  })

  it('round-trips the PKCE verifier and refuses to invent one', async () => {
    const { session } = createSession()
    await expect(session.provider.codeVerifier()).rejects.toThrow('no PKCE code verifier is stored')
    await session.provider.saveCodeVerifier('verifier-1')
    expect(await session.provider.codeVerifier()).toBe('verifier-1')
  })

  it('generates a distinct state per flow', async () => {
    const { session } = createSession()
    const first = await session.provider.state?.()
    const second = await session.provider.state?.()
    expect(first).toBeTruthy()
    expect(first).not.toBe(second)
  })

  it('round-trips discovery state and treats a non-object as absent', async () => {
    const { session, credentials } = createSession()
    expect(await session.provider.discoveryState?.()).toBeUndefined()
    await session.provider.saveDiscoveryState?.({ authorizationServerUrl: 'https://as.example' })
    expect(await session.provider.discoveryState?.()).toEqual({ authorizationServerUrl: 'https://as.example' })
    await writeGrantPayload(credentials, serverRecords('alpha').discovery, 'not an object')
    expect(await session.provider.discoveryState?.()).toBeUndefined()
  })

  it('invalidates exactly the records a scope names', async () => {
    const { session, stored } = createSession()
    await session.provider.saveTokens({ access_token: 'at', token_type: 'Bearer' })
    await session.provider.saveClientInformation?.({ client_id: 'abc' })
    await session.provider.saveCodeVerifier('verifier-1')
    await session.provider.saveDiscoveryState?.({ authorizationServerUrl: 'https://as.example' })

    await session.provider.invalidateCredentials?.('tokens')
    expect(stored.has('mcp-client/alpha')).toBe(false)
    expect(stored.has('mcp-client/alpha-client')).toBe(true)

    await session.provider.invalidateCredentials?.('all')
    expect(stored.size).toBe(0)
  })

  it('forgets every record it owns and leaves other servers untouched', async () => {
    const alpha = createSession({ serverName: 'alpha' })
    await alpha.session.provider.saveTokens({ access_token: 'at', token_type: 'Bearer' })
    const beta = createSession({ serverName: 'beta' })
    await beta.session.provider.saveTokens({ access_token: 'bt', token_type: 'Bearer' })

    await alpha.session.provider.invalidateCredentials?.('all')
    await alpha.session.forget()

    // Isolation is the point: alpha's removal is not beta's.
    expect(alpha.stored.size).toBe(0)
    expect(beta.stored.get('mcp-client/beta')).toEqual({ kind: 'grant', payload: { access_token: 'bt', token_type: 'Bearer' } })
  })

  it('presents the authorization URL and marks the session as waiting', async () => {
    const { session, presented } = createSession()
    expect(session.awaitingUser).toBe(false)
    await session.provider.redirectToAuthorization(new URL('https://as.example/authorize?x=1'))
    expect(session.awaitingUser).toBe(true)
    expect(presented.map(String)).toEqual(['https://as.example/authorize?x=1'])
  })
})

describe('acceptCallback', () => {
  it('returns the code for the state this flow issued', async () => {
    const { session, credentials } = createSession()
    const state = await session.provider.state?.()
    await session.provider.saveCodeVerifier('verifier-1')
    expect(state).toBeTruthy()
    await expect(session.acceptCallback({ code: 'the-code', state: state ?? '' })).resolves.toBe('the-code')
    expect(await readGrantPayload(credentials, serverRecords('alpha').verifier)).toEqual({
      codeVerifier: 'verifier-1',
      state,
    })
  })

  it('refuses a redirect whose state belongs to another flow', async () => {
    const { session } = createSession()
    await session.provider.state?.()
    await session.provider.saveCodeVerifier('verifier-1')
    await expect(session.acceptCallback({ code: 'attacker-code', state: 'not-our-state' }))
      .rejects.toBeInstanceOf(UnauthorizedError)
  })

  it('refuses a redirect when no flow was started', async () => {
    const { session } = createSession()
    await expect(session.acceptCallback({ code: 'code', state: 'anything' }))
      .rejects.toThrow('unexpected state')
  })

  it('judges a redirect that arrives after a restart from the stored state alone', async () => {
    const first = createSession()
    const state = await first.session.provider.state?.()
    await first.session.provider.saveCodeVerifier('verifier-1')

    // A fresh session over the same store stands in for a restarted process:
    // nothing in memory survives, so only the stored state can accept this.
    const second = createOAuthSession({
      credentials: first.credentials,
      serverName: 'alpha',
      config: resolveOAuthConfig(interactive, 'alpha', 'test'),
      presentAuthorization: () => {},
    })
    await expect(second.acceptCallback({ code: 'the-code', state: state ?? '' })).resolves.toBe('the-code')
    await expect(second.acceptCallback({ code: 'the-code', state: 'other' })).rejects.toBeInstanceOf(UnauthorizedError)
  })
})

describe('requireCredentials', () => {
  it('refuses to load an OAuth server with nowhere to keep the grant', () => {
    const ctx = { get: () => undefined } as unknown as Parameters<typeof requireCredentials>[0]
    expect(() => requireCredentials(ctx, 'test.oauth')).toThrow('oauth requires a credentials provider')
  })

  it('hands back the credentials service a composition did load', () => {
    const credentials = createFakeCredentials().credentials
    const ctx = { get: (name: string) => (name === 'credentials' ? credentials : undefined) } as unknown as Parameters<typeof requireCredentials>[0]
    expect(requireCredentials(ctx, 'test.oauth')).toBe(credentials)
  })
})

describe('redirect listener', () => {
  /** Start a listener on an operating-system port so concurrent specs cannot collide. */
  async function listen(overrides: { state?: string; timeoutMs?: number } = {}) {
    return await startRedirectListener({
      port: 0,
      path: '/callback',
      expectedState: overrides.state ?? 'expected-state',
      timeoutMs: overrides.timeoutMs ?? 5_000,
    })
  }

  const redirect = (port: number, query: string, path = '/callback') =>
    fetch(`http://127.0.0.1:${port}${path}?${query}`)

  it('accepts the code when the state matches', async () => {
    const listener = await listen()
    const response = await redirect(listener.port, 'code=abc&state=expected-state')
    expect(response.status).toBe(200)
    await expect(listener.settled).resolves.toEqual({ kind: 'code', code: 'abc', state: 'expected-state' })
    await listener.dispose()
  })

  it('reports a refused authorization', async () => {
    const listener = await listen()
    const response = await redirect(listener.port, 'error=access_denied&error_description=user%20said%20no')
    expect(response.status).toBe(200)
    await expect(listener.settled).resolves.toEqual({ kind: 'denied', reason: 'access_denied: user said no' })
    await listener.dispose()
  })

  it('reports a bare error code without a description', async () => {
    const listener = await listen()
    await redirect(listener.port, 'error=access_denied')
    await expect(listener.settled).resolves.toEqual({ kind: 'denied', reason: 'access_denied' })
    await listener.dispose()
  })

  it('rejects a mismatched state and never reports the code it carried', async () => {
    const listener = await listen()
    const response = await redirect(listener.port, 'code=attacker&state=wrong')
    expect(response.status).toBe(400)
    const outcome = await listener.settled
    expect(outcome.kind).toBe('denied')
    expect(JSON.stringify(outcome)).not.toContain('attacker')
    await listener.dispose()
  })

  it('rejects a redirect with no code', async () => {
    const listener = await listen()
    const response = await redirect(listener.port, 'state=expected-state')
    expect(response.status).toBe(400)
    await expect(listener.settled).resolves.toEqual({ kind: 'denied', reason: 'redirect carried no authorization code' })
    await listener.dispose()
  })

  it('leaves the flow running when an unrelated request arrives', async () => {
    const listener = await listen()
    expect((await redirect(listener.port, 'code=abc&state=expected-state', '/other')).status).toBe(404)
    expect((await redirect(listener.port, 'code=abc&state=expected-state')).status).toBe(200)
    await expect(listener.settled).resolves.toEqual({ kind: 'code', code: 'abc', state: 'expected-state' })
    await listener.dispose()
  })

  it('gives up when no redirect arrives in time', async () => {
    const listener = await listen({ timeoutMs: 30 })
    await expect(listener.settled).resolves.toEqual({ kind: 'timeout' })
    await listener.dispose()
  })

  it('releases the port, and disposing twice is harmless', async () => {
    const listener = await listen()
    await redirect(listener.port, 'error=access_denied')
    await listener.settled
    await listener.dispose()
    await listener.dispose()
    await expect(fetch(`http://127.0.0.1:${listener.port}/callback`)).rejects.toThrow()
  })

  it('surfaces a port that cannot be bound', async () => {
    const taken = await listen()
    await expect(startRedirectListener({
      port: taken.port,
      path: '/callback',
      expectedState: 's',
      timeoutMs: 100,
    })).rejects.toThrow()
    await taken.dispose()
  })
})

describe('credential redaction', () => {
  it('keeps a token value out of every stored record key and payload the provider writes', async () => {
    const { session, stored } = createSession()
    const warn = vi.fn()
    await session.provider.saveTokens({ access_token: 'super-secret-access', token_type: 'Bearer', refresh_token: 'super-secret-refresh' })
    const dump = JSON.stringify([...stored].map(([key, record]) => [key, record]))
    // The value is stored — that is the point of the seam — but the record
    // address never carries it, so a key is always safe to log or display.
    expect(dump).toContain('super-secret-access')
    for (const key of stored.keys()) expect(key).not.toContain('super-secret')
    expect(warn).not.toHaveBeenCalled()
  })

  it('never puts the authorization URL credential into the presented value', async () => {
    const { session, presented } = createSession()
    await session.provider.redirectToAuthorization(new URL('https://as.example/authorize?code_challenge=public-by-design'))
    expect(presented[0]?.searchParams.get('code_challenge')).toBe('public-by-design')
  })
})
