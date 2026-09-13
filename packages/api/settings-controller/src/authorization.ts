/** Browser interaction adapter; the shared authorization service owns every attempt. */
import type { Context } from '@deepseek-ai/cordis'
import { AuthorizationDeclinedError } from '@deepseek-ai/dsh-authorization'
import type { AuthorizationPrompt } from '@deepseek-ai/dsh-authorization'
import type { AuthorizationNotice } from '@deepseek-ai/dsh-authorization/types'
import type { CredentialKey } from '@deepseek-ai/dsh-credentials'

import type { AuthorizationView } from './types.ts'

interface Attempt {
  owner: string
  state: string
  notice?: AuthorizationNotice
  prompt?: AuthorizationPrompt | undefined
  answer?: ((value: string) => void) | undefined
  decline?: (() => void) | undefined
}

/** Relays browser notices and answers without duplicating authorization or credential writes. */
export class AuthorizationSurface {
  private readonly attempts = new Map<CredentialKey, Attempt>()
  constructor(private readonly ctx: Context) {}

  /** Read registered flows, projecting interaction details only to the initiating page.
   * @param owner - Opaque identifier held by the initiating browser page.
   * @returns Redacted registered flows visible to this page.
   */
  async list(owner: string): Promise<AuthorizationView[]> {
    const service = this.ctx.get('authorization')
    return Promise.all((service?.list() ?? []).map(async (entry) => {
      const attempt = this.attempts.get(entry.key)
      const own = attempt?.owner === owner ? attempt : undefined
      const credentials = this.ctx.get('credentials')
      if (credentials === undefined) throw new Error('Authorization credentials are unavailable')
      const saved = await credentials.describeRecord(entry.key)
      return {
        name: entry.key, label: entry.label,
        state: entry.inFlight ? 'authorizing' : (own?.state === 'failed' || own?.state === 'cancelled' ? own.state : saved.configured ? 'credential-saved' : 'not-authorized'),
        oauth: true, owned: own !== undefined,
        authorizationUrl: entry.inFlight ? own?.notice?.url ?? null : null,
        message: own?.notice?.message ?? null, code: entry.inFlight ? own?.notice?.code ?? null : null,
        methods: entry.methods.map(method => ({ id: method.id, label: method.label })),
        prompt: own?.prompt === undefined ? null : {
          kind: own.prompt.kind, message: own.prompt.message,
          options: own.prompt.kind === 'select' ? own.prompt.options.map(option => ({ id: option.id, label: option.label })) : [],
        },
      }
    }))
  }

  /** Start the shared service flow; its commit confirmation supplies the terminal result.
   * @param owner - Initiating page identifier.
   * @param name - Registered credential key.
   * @param method - Registered method identifier.
   */
  begin(owner: string, name: string, method: string): void {
    const service = this.ctx.get('authorization')
    const entry = service?.list().find(item => item.key === name)
    if (service === undefined || entry === undefined) throw new Error('Authorization flow is not configured')
    if (entry.inFlight) throw new Error('Authorization is already in progress')
    if (!entry.methods.some(item => item.id === method)) throw new Error('Unknown authorization method')
    const attempt: Attempt = { owner, state: 'authorizing' }
    this.attempts.set(entry.key, attempt)
    void service.begin({
      key: entry.key, method,
      interaction: {
        notify(notice) { attempt.notice = notice },
        prompt(prompt) {
          if (prompt.signal?.aborted === true) return Promise.reject(new Error('Prompt withdrawn'))
          return new Promise<string>((resolve, reject) => {
            const cleanup = (): void => {
              prompt.signal?.removeEventListener('abort', withdraw)
              attempt.prompt = undefined; attempt.answer = undefined; attempt.decline = undefined
            }
            const withdraw = (): void => { cleanup(); reject(new Error('Prompt withdrawn')) }
            attempt.prompt = prompt
            attempt.answer = (value) => { cleanup(); resolve(value) }
            attempt.decline = () => { cleanup(); reject(new AuthorizationDeclinedError()) }
            prompt.signal?.addEventListener('abort', withdraw, { once: true })
          })
        },
      },
    }).then((outcome) => { attempt.state = outcome.status }, () => {
      attempt.state = 'failed'
      attempt.notice = { message: 'Authorization failed. Retry sign-in.' }
    }).finally(() => {
      attempt.decline?.()
      attempt.prompt = undefined
    })
  }

  /** Answer or cancel only the attempt owned by this page.
   * @param owner - Initiating page identifier.
   * @param name - Registered credential key.
   * @param answer - Prompt response, or null to cancel.
   */
  respond(owner: string, name: string, answer: string | null): void {
    const entry = this.ctx.get('authorization')?.list().find(item => item.key === name)
    const attempt = entry === undefined ? undefined : this.attempts.get(entry.key)
    if (entry === undefined || attempt?.owner !== owner || !entry.inFlight) throw new Error('No authorization attempt belongs to this page')
    if (answer === null) { attempt.decline?.(); this.ctx.get('authorization')?.cancel(entry.key); return }
    if (attempt.answer === undefined) throw new Error('No authorization question is pending')
    if (attempt.prompt?.kind === 'select' && !attempt.prompt.options.some(option => option.id === answer)) {
      throw new Error('Unknown authorization option')
    }
    attempt.answer(answer)
  }

  /** Unloading the browser adapter withdraws its active interactions. */
  dispose(): void {
    for (const [key, attempt] of this.attempts) {
      attempt.decline?.()
      this.ctx.get('authorization')?.cancel(key)
    }
    this.attempts.clear()
  }
}
