/**
 * Loopback redirect listener for one in-flight MCP OAuth authorization.
 *
 * An authorization server sends the user agent back to an absolute redirect
 * URI, so this plugin has to be listening on it before the user finishes
 * authorizing. RFC 8252 permits a loopback interface for a public client, which
 * is why the listener binds `127.0.0.1` and nothing else.
 *
 * The listener owns exactly one flow: it stops on the first redirect it
 * accepts, on the first redirect it rejects, or when the flow's deadline
 * passes, and it never leaves the port bound behind it.
 *
 * @module
 */

import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'

/** Why the listener stopped. */
export type RedirectOutcome =
  | {
    /** The authorization server returned a code for the started flow. */
    readonly kind: 'code'
    /** The authorization code to exchange. */
    readonly code: string
    /** The state the server echoed, already known to match the started flow. */
    readonly state: string
  }
  | {
    /** The user or the authorization server refused the request. */
    readonly kind: 'denied'
    /** The OAuth error code, or a description when the server sent only one. */
    readonly reason: string
  }
  | {
    /** No redirect arrived before the flow's deadline. */
    readonly kind: 'timeout'
  }

/** One running listener, and the flow outcome it will report. */
export interface RedirectListener {
  /**
   * The port actually bound. It equals the requested port when one was named,
   * and is the only way to learn the redirect URI when port 0 asked the
   * operating system to choose one.
   */
  readonly port: number
  /** Stop listening and release the port; safe to call more than once. */
  dispose(): Promise<void>
  /** Settles when the listener stops, with what the redirect carried. */
  readonly settled: Promise<RedirectOutcome>
}

/** Body of the page shown once a redirect has been consumed. */
const page = (title: string, detail: string): string => [
  '<!doctype html><html><head><meta charset="utf-8">',
  `<title>${title}</title>`,
  '<style>body{font-family:system-ui,sans-serif;margin:4rem auto;max-width:32rem;line-height:1.5}</style>',
  `</head><body><h1>${title}</h1><p>${detail}</p></body></html>`,
].join('')

/**
 * Start listening for the redirect that completes one authorization flow.
 *
 * @param options - The bind port, redirect path, the state this flow issued, and the flow deadline.
 * @returns The listener handle; `settled` reports the flow outcome.
 */
export function startRedirectListener(options: {
  port: number
  path: string
  expectedState: string
  timeoutMs: number
}): Promise<RedirectListener> {
  const settle = Promise.withResolvers<RedirectOutcome>()
  let timer: NodeJS.Timeout | undefined
  let closed = false

  const stop = async (): Promise<void> => {
    if (closed) return
    closed = true
    if (timer !== undefined) {
      clearTimeout(timer)
      timer = undefined
    }
    // `server` is assigned before this can run: listening happens first, and
    // every caller of stop() is downstream of it.
    const closedPromise = Promise.withResolvers<void>()
    server.close(() => { closedPromise.resolve() })
    // A keep-alive agent holding the socket open must not delay teardown.
    server.closeAllConnections()
    await closedPromise.promise
  }

  const finish = (outcome: RedirectOutcome): void => {
    void stop().then(() => { settle.resolve(outcome) })
  }

  const respond = (response: ServerResponse, status: number, title: string, detail: string): void => {
    response.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
    response.end(page(title, detail))
  }

  const server = createServer((request: IncomingMessage, response: ServerResponse) => {
    // Parsed once: the path decides whether this request is ours at all, and
    // the query carries the outcome when it is.
    /* v8 ignore next -- an HTTP/1.1 request always carries a target; the fallback only keeps the parse total */
    const target = new URL(request.url ?? '/', 'http://127.0.0.1')
    // Anything but this flow's redirect path is not ours to answer; the port
    // is predictable, so an unrelated request must not consume the flow.
    if (request.method !== 'GET' || target.pathname !== options.path) {
      response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' })
      response.end('not found')
      return
    }
    const query = target.searchParams
    const failure = query.get('error')
    if (failure !== null) {
      const description = query.get('error_description')
      respond(response, 200, 'Authorization not completed', 'You can close this window and return to the harness.')
      finish({ kind: 'denied', reason: description === null || description === '' ? failure : `${failure}: ${description}` })
      return
    }
    const state = query.get('state')
    const code = query.get('code')
    // The state is compared before the code is used: a redirect that does not
    // match the started flow may be a cross-site request, and its code must not
    // reach the token endpoint.
    if (state === null || state !== options.expectedState) {
      respond(response, 400, 'Authorization rejected', 'The response did not match the authorization request that was started.')
      finish({ kind: 'denied', reason: 'redirect state did not match the started authorization flow' })
      return
    }
    if (code === null || code === '') {
      respond(response, 400, 'Authorization rejected', 'The response carried no authorization code.')
      finish({ kind: 'denied', reason: 'redirect carried no authorization code' })
      return
    }
    respond(response, 200, 'Authorization complete', 'You can close this window and return to the harness.')
    finish({ kind: 'code', code, state })
  })

  const listening = Promise.withResolvers<void>()
  server.once('error', (error) => { listening.reject(error) })
  server.listen(options.port, '127.0.0.1', () => { listening.resolve() })

  return listening.promise.then(() => {
    timer = setTimeout(() => { finish({ kind: 'timeout' }) }, options.timeoutMs)
    // An abandoned flow must never hold the process open on its own.
    timer.unref()
    return {
      // The listener is up, so the address is an AddressInfo rather than a
      // pipe name.
      port: (server.address() as AddressInfo).port,
      dispose: stop,
      settled: settle.promise,
    }
  }, async (error: unknown) => {
    await stop()
    throw error
  })
}
