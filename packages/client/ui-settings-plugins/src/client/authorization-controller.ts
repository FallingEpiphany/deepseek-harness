/** Pollable, redacted MCP connection state for the plugin settings page. */
import { createSnapshotStore, type SnapshotStore } from '@deepseek-ai/dsh-client-store'

/** Public connection fields returned by the Host. */
export interface AuthorizationView {
  name: string
  label: string
  state: string
  oauth: boolean
  authorizationUrl: string | null
  message: string | null
  code: string | null
  owned: boolean
  methods: Array<{ id: string; label: string }>
  prompt: { kind: string; message: string; options: Array<{ id: string; label: string }> } | null
}
/** Current settings-page view, including real read/action failures. */
export interface AuthorizationState { servers: AuthorizationView[]; loaded: boolean; failed: boolean; busy: string | null }
/** Controller face bound to the configuration tab. */
export interface AuthorizationFace {
  hooks: { authorizations: SnapshotStore<AuthorizationState> }
  refreshAuthorizations(): void
  beginAuthorization(name: string, method: string): void
  respondAuthorization(name: string, answer: string | null): void
}

/** Keeps requests serialized and ignores results after disposal. */
export class AuthorizationController {
  private readonly store = createSnapshotStore<AuthorizationState>({ servers: [], loaded: false, failed: false, busy: null })
  private disposed = false
  private reading = false
  private isDisposed(): boolean { return this.disposed }
  constructor(private readonly remote: {
    authorizations(): Promise<AuthorizationView[]>
    beginAuthorization(name: string, method: string): Promise<void>
    respondAuthorization(name: string, answer: string | null): Promise<void>
  }) {}
  /** Refresh without exposing previous state as a successful current response. */
  async refresh(): Promise<void> {
    if (this.disposed || this.reading) return
    this.reading = true
    try {
      const servers = await this.remote.authorizations()
      if (!this.isDisposed()) this.store.set({ ...this.store.getSnapshot(), servers, loaded: true, failed: false })
    } catch {
      if (!this.isDisposed()) this.store.set({ ...this.store.getSnapshot(), failed: true })
    } finally { this.reading = false }
  }
  /** Begin a server's OAuth flow; the ready link arrives from the host snapshot.
   * @param name - Registered credential key.
   * @param method - Registered authorization method.
   */
  async authorize(name: string, method: string): Promise<void> {
    if (this.disposed || this.store.getSnapshot().busy !== null) return
    this.store.set({ ...this.store.getSnapshot(), busy: name, failed: false })
    try { await this.remote.beginAuthorization(name, method); await this.refresh() }
    catch { if (!this.isDisposed()) this.store.set({ ...this.store.getSnapshot(), failed: true }) }
    finally { if (!this.isDisposed()) this.store.set({ ...this.store.getSnapshot(), busy: null }) }
  }
  /** Forward a prompt response without retaining its value.
   * @param name - Registered credential key.
   * @param answer - Prompt response, or null to cancel.
   */
  async respond(name: string, answer: string | null): Promise<void> {
    try { await this.remote.respondAuthorization(name, answer); await this.refresh() }
    catch { if (!this.isDisposed()) this.store.set({ ...this.store.getSnapshot(), failed: true }) }
  }
  /** Stop publishing when the plugin unloads. */
  dispose(): void { this.disposed = true }
  /** Bind the snapshot and actions.
   * @returns The configuration tab's controller face.
   */
  inject(): AuthorizationFace {
    return {
      hooks: { authorizations: this.store },
      refreshAuthorizations: () => { void this.refresh() },
      beginAuthorization: (name, method) => { void this.authorize(name, method) },
      respondAuthorization: (name, answer) => { void this.respond(name, answer) },
    }
  }
}
