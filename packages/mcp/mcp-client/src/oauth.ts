/**
 * OAuth 2.1 client state for one Streamable HTTP MCP server.
 *
 * The MCP SDK owns discovery, the authorization-code exchange with PKCE, the
 * RFC 8707 resource indicator, and refresh. This module owns what a host must
 * supply around it: where the client registration, tokens, PKCE verifier, and
 * discovery state live, and how an authorization URL reaches the user.
 *
 * Every value is stored through the credentials seam under `<scope>/<id>`. That
 * keeps tokens out of configuration, and it gives each server its own
 * addressing unit, so two servers can never read or overwrite each other's
 * grant.
 *
 * @module
 */

import { randomUUID } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { credentialKey, isCredentialKeySegment } from '@deepseek-ai/dsh-credentials'
import type { CredentialKey, CredentialProvider } from '@deepseek-ai/dsh-credentials'
import type { OAuthClientInformationMixed, OAuthClientMetadata, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js'
import { OAuthTokensSchema } from '@modelcontextprotocol/sdk/shared/auth.js'
import type { AuthResult, OAuthClientProvider, OAuthDiscoveryState } from '@modelcontextprotocol/sdk/client/auth.js'
import { auth, UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js'

/** Owner segment of every record this plugin stores. */
export const CREDENTIAL_SCOPE = 'mcp-client'

/** Longest authorization window a started flow may stay open by default. */
export const DEFAULT_AUTHORIZATION_TIMEOUT_MS = 300_000

/** Client name presented in dynamic registration when the config omits one. */
const DEFAULT_CLIENT_NAME = 'dsh'

/** Path the loopback redirect listener answers on when the config omits one. */
const DEFAULT_REDIRECT_PATH = '/callback'

/** Loopback host the redirect listener binds; RFC 8252 permits no other literal. */
const LOOPBACK_HOST = '127.0.0.1'

/** OAuth settings for one Streamable HTTP MCP server. */
export interface OAuthConfig {
  /**
   * Port the loopback redirect listener binds. Omit it for a grant that never
   * redirects a user agent — the SDK treats an absent `redirectUrl` as the
   * non-interactive case. When present, the port is a configured constant
   * rather than a per-flow choice: an authorization server validates the
   * redirect URI exactly, and a dynamically registered client must name the
   * same URI it will use.
   */
  redirectPort?: number
  /** Path of the loopback redirect endpoint (default `/callback`); requires `redirectPort`. */
  redirectPath?: string
  /** Scopes requested during authorization; omission requests none. */
  scopes?: string[]
  /** Client name presented in dynamic registration (default `dsh`). */
  clientName?: string
  /**
   * Authorization server to use instead of discovering one from the MCP
   * server. Set this only for a deployment whose authorization server is not
   * reachable through RFC 9728 metadata.
   */
  authorizationServerUrl?: string
  /** How long a started authorization flow may wait for the redirect (default 300000). */
  authorizationTimeoutMs?: number
}

/** Fully resolved OAuth configuration captured at plugin load. */
export interface ResolvedOAuthConfig {
  /** Loopback port the redirect listener binds; absent for a non-interactive grant. */
  readonly redirectPort?: number
  /** Redirect path, always beginning with `/`. */
  readonly redirectPath: string
  /** Requested scopes; empty means none. */
  readonly scopes: readonly string[]
  /** Client name presented in dynamic registration. */
  readonly clientName: string
  /** Explicit authorization server, or absent to discover one. */
  readonly authorizationServerUrl?: string
  /** Absolute redirect URI handed to the authorization server; absent when this server never redirects. */
  readonly redirectUrl?: string
  /** Bounded wait for one authorization flow. */
  readonly authorizationTimeoutMs: number
}

/**
 * Resolve the `oauth` config for one server, failing loud on any value the
 * authorization flow could not use.
 *
 * Programmatic construction may bypass Schemastery normalization, so every
 * bound is judged here as well as in the config schema.
 *
 * @param config - Raw `oauth` config from the plugin entry.
 * @param serverName - The server's namespace, which also names its records.
 * @param path - Diagnostic prefix naming the config location in thrown messages.
 * @returns The frozen resolved configuration.
 * @throws Error when a field is unusable, or when `serverName` cannot address a stored record.
 */
export function resolveOAuthConfig(config: OAuthConfig, serverName: string, path: string): ResolvedOAuthConfig {
  // A record key admits only `[a-z][a-z0-9-]*` segments. Rejecting a
  // serverName outside that grammar here is what keeps two servers from
  // aliasing onto one stored grant.
  if (!isCredentialKeySegment(serverName)) {
    throw new Error(
      `${path}: serverName "${serverName}" cannot address stored OAuth credentials — an OAuth server needs a credential key segment matching /^[a-z][a-z0-9-]*$/`,
    )
  }
  const { redirectPort } = config
  if (redirectPort !== undefined && (!Number.isInteger(redirectPort) || redirectPort < 1 || redirectPort > 65_535)) {
    throw new Error(`${path}.redirectPort must be an integer between 1 and 65535`)
  }
  if (redirectPort === undefined && config.redirectPath !== undefined) {
    throw new Error(`${path}.redirectPath requires redirectPort — a server with no redirect port never receives a redirect`)
  }
  const redirectPath = config.redirectPath ?? DEFAULT_REDIRECT_PATH
  if (!redirectPath.startsWith('/') || redirectPath.includes('?') || redirectPath.includes('#')) {
    throw new Error(`${path}.redirectPath must be an absolute path without a query or fragment`)
  }
  const scopes = config.scopes ?? []
  for (const scope of scopes) {
    if (typeof scope !== 'string' || scope === '' || /\s/.test(scope)) {
      throw new Error(`${path}.scopes entries must be non-empty strings without whitespace`)
    }
  }
  const clientName = config.clientName ?? DEFAULT_CLIENT_NAME
  if (clientName === '') throw new Error(`${path}.clientName must not be empty`)
  const authorizationTimeoutMs = config.authorizationTimeoutMs ?? DEFAULT_AUTHORIZATION_TIMEOUT_MS
  if (!Number.isFinite(authorizationTimeoutMs) || authorizationTimeoutMs <= 0) {
    throw new Error(`${path}.authorizationTimeoutMs must be a positive finite number`)
  }
  const authorizationServerUrl = config.authorizationServerUrl
  if (authorizationServerUrl !== undefined) {
    try {
      new URL(authorizationServerUrl)
    } catch {
      throw new Error(`${path}.authorizationServerUrl must be an absolute URL`)
    }
  }
  return Object.freeze({
    ...redirectPort === undefined ? {} : { redirectPort },
    redirectPath,
    scopes: Object.freeze([...scopes]),
    clientName,
    ...authorizationServerUrl === undefined ? {} : { authorizationServerUrl },
    ...redirectPort === undefined ? {} : { redirectUrl: `http://${LOOPBACK_HOST}:${redirectPort}${redirectPath}` },
    authorizationTimeoutMs,
  })
}

/** PKCE verifier and state for one started authorization flow. */
interface StoredVerifier {
  /** The PKCE code verifier the token exchange must present. */
  readonly codeVerifier: string
  /** The `state` handed to the authorization server, compared on redirect. */
  readonly state: string
}

/** Record address for each value one server stores. */
interface ServerRecords {
  /** Tokens from a completed authorization. */
  readonly tokens: CredentialKey
  /** Client registration returned by dynamic registration. */
  readonly client: CredentialKey
  /** The started flow's PKCE verifier and state. */
  readonly verifier: CredentialKey
  /** Cached discovery results. */
  readonly discovery: CredentialKey
}

/**
 * The four record addresses belonging to one server.
 *
 * @param serverName - The server's namespace, already known to be a valid key segment.
 * @returns The branded record addresses.
 */
export function serverRecords(serverName: string): ServerRecords {
  return {
    tokens: credentialKey(CREDENTIAL_SCOPE, serverName),
    client: credentialKey(CREDENTIAL_SCOPE, `${serverName}-client`),
    verifier: credentialKey(CREDENTIAL_SCOPE, `${serverName}-verifier`),
    discovery: credentialKey(CREDENTIAL_SCOPE, `${serverName}-discovery`),
  }
}

/**
 * Read one record's payload through the credentials seam.
 *
 * @param credentials - The credentials service.
 * @param key - The record address.
 * @returns The stored payload, or undefined when no grant record is stored.
 */
export async function readGrantPayload(credentials: CredentialProvider, key: CredentialKey): Promise<unknown> {
  const record = await credentials.readRecord(key)
  return record?.kind === 'grant' ? record.payload : undefined
}

/**
 * Replace one record's payload, or remove the record when the payload is undefined.
 *
 * The seam's `modifyRecord` is the only write path, so this is the single place
 * a token refresh and a token removal share.
 *
 * @param credentials - The credentials service.
 * @param key - The record address.
 * @param payload - The payload to store, or undefined to remove the record.
 */
export async function writeGrantPayload(
  credentials: CredentialProvider,
  key: CredentialKey,
  payload: unknown,
): Promise<void> {
  if (payload === undefined) {
    await credentials.deleteRecord(key)
    return
  }
  await credentials.modifyRecord(key, () => Promise.resolve({ kind: 'grant' as const, payload }))
}

/** Narrow a stored payload to the verifier shape, rejecting anything else. */
function asStoredVerifier(payload: unknown): StoredVerifier | undefined {
  if (typeof payload !== 'object' || payload === null) return undefined
  const candidate = payload as Partial<StoredVerifier>
  if (typeof candidate.codeVerifier !== 'string' || typeof candidate.state !== 'string') return undefined
  return { codeVerifier: candidate.codeVerifier, state: candidate.state }
}

/**
 * The value an authorization-server response returns to this plugin between a
 * redirect and the completed token exchange.
 */
export interface AuthorizationCallback {
  /** The authorization code from the redirect. */
  readonly code: string
  /** The `state` the authorization server echoed back. */
  readonly state: string
}

/** Handle over one server's OAuth state, used by the connection supervisor. */
export interface OAuthSession {
  /** The provider handed to the SDK transport. */
  readonly provider: OAuthClientProvider
  /**
   * Resolve how the flow should proceed for one request that the server
   * refused, performing discovery and, when possible, a refresh.
   *
   * @param options - The server URL and any authorization code from a redirect.
   * @returns The SDK's authorization result: authorized, or waiting on the user.
   */
  authorize(options: { serverUrl: string; authorizationCode?: string }): Promise<AuthResult>
  /**
   * Complete a started flow from a redirect, after validating its `state`.
   *
   * @param callback - The code and state received on the redirect URI.
   * @returns The authorization code to hand the authorization flow.
   * @throws UnauthorizedError when the state does not match the started flow.
   */
  acceptCallback(callback: AuthorizationCallback): Promise<string>
  /** Whether an authorization flow is currently waiting for a redirect. */
  readonly awaitingUser: boolean
  /**
   * The state the started flow expects on its redirect, read from the record
   * that holds the PKCE verifier. Absent when no flow is waiting, which is what
   * tells a listener there is nothing to receive.
   */
  pendingState(): Promise<string | undefined>
  /** Remove every record this server owns, leaving no stored grant behind. */
  forget(): Promise<void>
}

/**
 * Create the OAuth session for one MCP server.
 *
 * @param options - The credentials service, server identity, resolved config, and how an authorization URL reaches the user.
 * @returns The session the connection supervisor drives.
 */
export function createOAuthSession(options: {
  credentials: CredentialProvider
  serverName: string
  config: ResolvedOAuthConfig
  presentAuthorization: (url: URL) => void
}): OAuthSession {
  const { credentials, config } = options
  const records = serverRecords(options.serverName)
  let awaitingUser = false
  let expectedState: string | undefined

  const provider: OAuthClientProvider = {
    get redirectUrl() {
      return config.redirectUrl
    },
    get clientMetadata(): OAuthClientMetadata {
      return {
        client_name: config.clientName,
        // A non-interactive grant never receives a redirect, so it advertises
        // none; the field itself is required by the client metadata schema.
        redirect_uris: config.redirectUrl === undefined ? [] : [config.redirectUrl],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        // A loopback redirect with PKCE identifies the client without a
        // secret, so the client registers as public.
        token_endpoint_auth_method: 'none',
        ...config.scopes.length === 0 ? {} : { scope: config.scopes.join(' ') },
      }
    },
    state() {
      // The state is generated here rather than left to the SDK so the
      // redirect can be judged against the flow this plugin started.
      const state = randomUUID()
      expectedState = state
      return state
    },
    async clientInformation(): Promise<OAuthClientInformationMixed | undefined> {
      const stored = await readGrantPayload(credentials, records.client)
      return typeof stored === 'object' && stored !== null ? stored as OAuthClientInformationMixed : undefined
    },
    async saveClientInformation(clientInformation: OAuthClientInformationMixed) {
      await writeGrantPayload(credentials, records.client, clientInformation)
    },
    async tokens(): Promise<OAuthTokens | undefined> {
      // The SDK's own schema reads the stored document back, so a payload
      // written by an incompatible version reads as "no tokens" instead of
      // reaching the transport as a malformed token set.
      const parsed = OAuthTokensSchema.safeParse(await readGrantPayload(credentials, records.tokens))
      return parsed.success ? parsed.data : undefined
    },
    async saveTokens(tokens: OAuthTokens) {
      // Stored verbatim: the same schema validates it on the way out, so no
      // field of the token document is copied by hand here.
      await writeGrantPayload(credentials, records.tokens, tokens)
    },
    redirectToAuthorization(authorizationUrl: URL) {
      awaitingUser = true
      options.presentAuthorization(authorizationUrl)
    },
    async saveCodeVerifier(codeVerifier: string) {
      // The state is written with the verifier because the redirect cannot be
      // judged without it, and both must outlive the process that started the flow.
      await writeGrantPayload(credentials, records.verifier, {
        codeVerifier,
        state: expectedState ?? '',
      } satisfies StoredVerifier)
    },
    async codeVerifier(): Promise<string> {
      const stored = asStoredVerifier(await readGrantPayload(credentials, records.verifier))
      if (stored === undefined) {
        throw new Error('mcp-client: no PKCE code verifier is stored for this authorization flow — restart the flow')
      }
      return stored.codeVerifier
    },
    async saveDiscoveryState(state: OAuthDiscoveryState) {
      await writeGrantPayload(credentials, records.discovery, state)
    },
    async discoveryState(): Promise<OAuthDiscoveryState | undefined> {
      const stored = await readGrantPayload(credentials, records.discovery)
      return typeof stored === 'object' && stored !== null ? stored as OAuthDiscoveryState : undefined
    },
    async invalidateCredentials(scope) {
      if (scope === 'all' || scope === 'tokens') await credentials.deleteRecord(records.tokens)
      if (scope === 'all' || scope === 'client') await credentials.deleteRecord(records.client)
      if (scope === 'all' || scope === 'verifier') await credentials.deleteRecord(records.verifier)
      if (scope === 'all' || scope === 'discovery') await credentials.deleteRecord(records.discovery)
    },
  }

  return {
    provider,
    get awaitingUser() {
      return awaitingUser
    },
    async pendingState() {
      const stored = asStoredVerifier(await readGrantPayload(credentials, records.verifier))
      return stored?.state
    },
    async authorize({ serverUrl, authorizationCode }) {
      const result = await auth(provider, {
        serverUrl,
        ...authorizationCode === undefined ? {} : { authorizationCode },
        ...config.scopes.length === 0 ? {} : { scope: config.scopes.join(' ') },
      })
      if (result === 'AUTHORIZED') awaitingUser = false
      return result
    },
    async acceptCallback(callback) {
      // The expected state is read back from storage rather than taken from
      // memory: the redirect can arrive after a restart, and the stored value
      // is the one that survived the browser round-trip.
      const stored = asStoredVerifier(await readGrantPayload(credentials, records.verifier))
      awaitingUser = false
      const expected = stored?.state ?? expectedState
      if (expected === undefined || expected === '' || expected !== callback.state) {
        // A redirect whose state does not match the started flow is the CSRF
        // case the state parameter exists to catch; the code is discarded.
        throw new UnauthorizedError('mcp-client: authorization redirect carried an unexpected state')
      }
      return callback.code
    },
    async forget() {
      for (const key of [records.tokens, records.client, records.verifier, records.discovery]) {
        await credentials.deleteRecord(key)
      }
      awaitingUser = false
    },
  }
}

/**
 * Resolve the credentials service an OAuth server needs.
 *
 * A composition without a credential store has nowhere to keep a grant, so an
 * OAuth server refuses to load rather than silently connecting unauthenticated.
 *
 * @param ctx - The plugin context.
 * @param path - Diagnostic prefix naming the config location in the thrown message.
 * @returns The credentials service.
 * @throws Error when no credentials provider is loaded.
 */
export function requireCredentials(ctx: Context, path: string): CredentialProvider {
  const credentials = ctx.get('credentials')
  if (credentials === undefined) {
    throw new Error(`${path}: oauth requires a credentials provider; load @deepseek-ai/dsh-credentials-local in this composition`)
  }
  return credentials
}
