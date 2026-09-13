/** Authenticated MCP operations shared with companion plugins, without exposing credentials. */
import { Context, Service } from '@deepseek-ai/cordis'
import { scopeOf } from '@deepseek-ai/dsh-scope'

/** Read operations available to a companion of an MCP server. */
export type McpReadMethod = 'resources/read' | 'resources/list' | 'prompts/get' | 'prompts/list'

/** One supervised server's authenticated read interface. */
export interface McpConnection {
  /** Read a resource or prompt through the host connection. */
  request(method: McpReadMethod, params: Record<string, unknown>, signal?: AbortSignal): Promise<unknown>
  /** Return the initialized server's advertised metadata. */
  metadata(): Promise<unknown>
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    mcpConnections: McpConnections
  }
}

/** Scoped connection directory owned by the host; unloading removes its entries. */
export class McpConnections extends Service {
  private readonly entries = new WeakMap<object, Map<string, McpConnection>>()

  constructor(ctx: Context) {
    super(ctx, 'mcpConnections')
  }

  /** Register a server in its existing tool scope; returns its removal effect.
   * @param owner - The MCP plugin context.
   * @param name - Configured server namespace.
   * @param connection - Authenticated operations for the supervised connection.
   * @returns A disposer that removes this registration.
   */
  register(owner: Context, name: string, connection: McpConnection): () => void {
    const scope = scopeOf(owner) ?? owner.root
    let entries = this.entries.get(scope)
    if (!entries) { entries = new Map(); this.entries.set(scope, entries) }
    if (entries.has(name)) throw new Error(`MCP connection ${name} is already registered`)
    entries.set(name, connection)
    return () => { if (entries.get(name) === connection) entries.delete(name) }
  }

  /** Resolve a server visible to the calling plugin without crossing Agent scopes.
   * @param owner - The companion plugin context.
   * @param name - Configured server namespace.
   * @returns Its authenticated read interface.
   * @throws Error if no server is registered in this scope or globally.
   */
  resolve(owner: Context, name: string): McpConnection {
    const scope = scopeOf(owner) ?? owner.root
    const connection = this.entries.get(scope)?.get(name) ?? this.entries.get(owner.root)?.get(name)
    if (!connection) throw new Error(`MCP connection ${name} is not configured in this scope`)
    return connection
  }
}
