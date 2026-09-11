# Agent Note: OAuth for MCP servers

Status: implemented

English | [中文](2026-09-11-mcp-client-oauth.zh.md)

## Problem

`dsh-mcp-client` could only authenticate with whatever the configuration put in a static header. A Streamable HTTP server that answers the MCP authorization flow — discovery, dynamic registration, an authorization code, a rotating refresh token — could not be reached at all, and the failure had no shape the harness could act on.

The MCP SDK already implements that protocol client-side and hands the host one object, `OAuthClientProvider`, to describe where its state lives and how a user is told to authorize. The harness never supplied one: `createTransport` built `new StreamableHTTPClientTransport(url, { requestInit: { headers } })` and nothing else, so a 401 surfaced as the SDK's `UnauthorizedError` and landed in the supervisor's generic catch. That catch logs `connection attempt failed` and schedules a retry on the exponential backoff, which is the right response to an unreachable server and the wrong one to a server that is waiting for a human: ten attempts later the budget is spent and the tools are gone.

Two things made the gap closable rather than a new plane to design. The credential seam grew a second key space for `{ kind: 'grant' }` records precisely so an obtained credential has somewhere to live, and the authorization seam describes how a plugin talks to a human about obtaining one. Neither had an MCP consumer.

## Decision

The plugin owns the flow, the credential records hold the grant, and the supervisor learns one new distinction.

**OAuth is a configuration choice on one transport.** `oauth` joins the Streamable HTTP server's config, and omission keeps the existing static-header behavior byte for byte — the two are independent, so a server may carry both. Every field is judged again by an explicit `resolveOAuthConfig` step, because a programmatic construction bypasses the config schema; `serverName` is rejected there unless it is a valid credential-key segment, which is what stops two servers from aliasing onto one stored grant.

**The SDK drives the protocol and the harness owns the state.** `createOAuthSession` implements `OAuthClientProvider` over `ctx.credentials` records addressed `mcp-client/<serverName>`, so registration, tokens, the PKCE verifier, and discovery state are four records per server. A composition with no credential provider refuses to load such a server by name rather than connecting unauthenticated, because a login whose grant evaporated would report success and then fail every request. Stored tokens are read back through the SDK's own `OAuthTokensSchema`, so a document written by an incompatible version reads as "no tokens" instead of reaching the transport malformed, and no field of the token document is copied by hand.

**The harness owns the browser round-trip.** `startRedirectListener` binds a configured loopback port for exactly one flow, compares the redirect's `state` against the flow that started it before its code is used, and releases the port on every exit path: an accepted redirect, a refused one, or the flow's deadline. The expected state is read back from the stored verifier record rather than from memory, so a redirect that arrives after a restart is still judged against the flow that started it.

**The supervisor names the one failure a human must clear.** Only the SDK's typed `UnauthorizedError` sets an authorization-pending state that stops the reconnect loop and reports the URL; every other failure, a generic 500 included, stays an ordinary outage and keeps retrying on the same bounded schedule it always used. `ConnectionHandle.reconnect()` is the way back: an authorization that completes after the supervisor stopped reconnects immediately instead of requiring a host restart.

## Alternatives considered

**Static headers only, with documentation telling users to mint a long-lived token.** Cheapest by far and already worked, but it is the practice the MCP authorization flow exists to replace: no rotation, no revocation, and a credential in configuration that the credential seam was built to keep out of it.

**A `ctx.authorization` flow instead of a listener this plugin owns.** The sanctioned surface for asking a human, with `llm-pi-ai` as a working precedent, and it would have given every configuration UI a login button for free. Rejected because the redirect URI is the part an authorization server validates exactly: a dynamically registered client must name the URI it will use before a flow starts, so the listener has to exist and be bound to a configured port regardless of who drives the conversation, and a flow registered per server would still need that listener behind it. Registering a flow on top of this is additive and remains open; the seam's own contract — one attempt per key, a commit confirmed through `ctx.credentials` — is already satisfied by how the records are written.

**Tokens in a settings namespace.** Settings hold literal values in a plain document that is synced and rendered; the credential store is the half built for secrets, and `llm-pi-ai` had already established that a grant belongs there.

**Reusing the transport that threw, calling `finishAuth` on it.** The SDK exposes `finishAuth` on the transport, which suggests keeping the failed instance alive until the user returns. The SDK's own worked example does the opposite — it retries on a fresh transport — and the module-level `auth()` accepts an authorization code directly, so the callback completes the exchange and stores tokens without any reference to the generation that threw. That removed a whole lifetime problem: nothing has to survive the failed attempt.

**Treating a 401 as an ordinary outage.** It would have needed no new supervisor state, and it is exactly the failure the retry budget cannot fix. The budget exists to ride out a server that is down, not to wait for a person.

## Consequences

A server that authenticates through the MCP authorization flow is reachable, and its grant is stored where every other obtained credential lives: rotating it takes effect on the next request, and one server's records are unreachable from another's.

The cost is a fixed port and a human. An authorization-code flow cannot complete without a reachable redirect URI and someone to finish the browser step, so a headless deployment without a pre-registered client cannot use this path — the SDK's non-interactive providers are the answer there and are not wired up yet. Both facts are recorded in the package's limitations rather than left for a user to discover.

The plugin now depends on the credential seam. It is read with `ctx.get`, so a composition that has no store simply refuses an OAuth server instead of failing to load, and the static-header path keeps working with no credential provider at all.

Four records per OAuth server accumulate under `mcp-client/`: the grant, the registration, the verifier, and the discovery cache. Nothing enumerates them for a user yet, and an uninstalled plugin leaves them behind — the credential seam reports such a record as an orphan and leaves recognizing it to a join the caller performs, which no caller performs here.
