/** Shared authorization flows beside plugin configuration. */
import { useEffect } from 'react'
import type { InjectFace, PropsLocale } from '@deepseek-ai/dsh-client-ui-slots'
import type { AuthorizationFace } from './authorization-controller.ts'
import css from './AuthorizationCard.module.css'

/** The host authorization surface and localized copy. */
export type AuthorizationCardProps = PropsLocale<'settings.plugins'> & InjectFace<AuthorizationFace>

/** Render the registered flow methods and the initiating page's notices and questions. */
export function AuthorizationCard(props: AuthorizationCardProps) {
  const state = props.useAuthorizations(value => value)
  useEffect(() => {
    props.refreshAuthorizations()
    const timer = setInterval(props.refreshAuthorizations, 3000)
    return () => { clearInterval(timer) }
  }, [props.refreshAuthorizations])
  const { t } = props
  return <section className={css.card} aria-label={t('mcpTitle')}>
    <h3>{t('mcpTitle')}</h3><p>{t('mcpDescription')}</p>
    {state.failed && <p role="alert">{t('mcpFailed')}</p>}
    {state.loaded && state.servers.length === 0 && !state.failed && <p>{t('mcpEmpty')}</p>}
    {(!state.failed ? state.servers : []).map(server => <div className={css.row} key={server.name}>
      <strong>{server.label}</strong>
      {server.message && <p>{server.message}</p>}
      <span>{server.state === 'credential-saved' || server.state === 'authorized' ? t('mcpConnected')
        : server.state === 'authorizing' ? t('mcpConnecting')
          : server.state === 'failed' ? t('authFailed') : server.state === 'cancelled' ? t('authCancelled') : t('mcpDisconnected')}</span>
      {server.authorizationUrl && /^https?:\/\//.test(server.authorizationUrl)
        && <a href={server.authorizationUrl} target="_blank" rel="noopener noreferrer">{t('mcpOpenAuthorization')}</a>}
      {server.code && <code>{server.code}</code>}
      {server.state === 'authorizing'
        ? server.owned && <button type="button" onClick={() => { props.respondAuthorization(server.name, null) }}>{t('authCancel')}</button>
        : server.methods.map(method => <button key={method.id} type="button" disabled={state.busy !== null}
          onClick={() => { props.beginAuthorization(server.name, method.id) }}>{method.label}</button>)}
      {server.prompt && <form onSubmit={(event) => {
        event.preventDefault()
        const form = event.currentTarget
        const answer = new FormData(form).get('answer')
        if (typeof answer === 'string') props.respondAuthorization(server.name, answer)
        form.reset()
      }}>
        <label>{server.prompt.message}
          {server.prompt.kind === 'select'
            ? <select name="answer">{server.prompt.options.map(option => <option key={option.id} value={option.id}>{option.label}</option>)}</select>
            : <input name="answer" type={server.prompt.kind === 'secret' ? 'password' : 'text'} autoComplete="off" required />}
        </label>
        <button type="submit">{t('authSubmit')}</button>
      </form>}
    </div>)}
  </section>
}
