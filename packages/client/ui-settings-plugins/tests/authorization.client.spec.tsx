// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { bindSnapshotSelector } from '@deepseek-ai/dsh-client-test-runtime'
import { AuthorizationController } from '../src/client/authorization-controller.ts'
import { AuthorizationCard, type AuthorizationCardProps } from '../src/client/AuthorizationCard.tsx'
import { en } from '../src/client/locales.ts'

afterEach(cleanup)

it('offers login, presents the ready link, then shows connected without a login action', async () => {
  let state = { name:'example',label:'Example',state:'not-authorized',oauth:true,authorizationUrl:null as string|null, message:null,code:null,owned:true,methods:[{ id:'oauth',label:'OAuth' }],prompt:null }
  const remote = { authorizations:vi.fn(async()=>[state]),beginAuthorization:vi.fn(async()=>{state={ ...state,state:'authorizing',authorizationUrl:'https://auth.example/authorize?state=test' }}) }
  const controller=new AuthorizationController({ ...remote, respondAuthorization: async () => {} })
  const face=controller.inject()
  const props = {
    ...face,
    t: (key: keyof typeof en) => en[key],
    useAuthorizations: bindSnapshotSelector(face.hooks.authorizations),
  } as unknown as AuthorizationCardProps
  try {
    render(<AuthorizationCard {...props}/> )
    fireEvent.click(await screen.findByRole('button',{ name:'OAuth' }))
    const link=await screen.findByRole('link',{ name:'Open authorization page' })
    expect(link.getAttribute('href')).toBe(state.authorizationUrl)
    expect(remote.beginAuthorization).toHaveBeenCalledWith('example', 'oauth')
    state={ ...state,state:'authorized',authorizationUrl:null }
    await act(()=>controller.refresh())
    expect(screen.getByText('Credential saved')).toBeTruthy()
    expect(screen.getByRole('button',{ name:'OAuth' })).toBeTruthy()
    expect(screen.queryByRole('link')).toBeNull()
    remote.authorizations.mockRejectedValueOnce(new Error('offline'))
    await act(()=>controller.refresh())
    expect(screen.getByRole('alert')).toBeTruthy()
    expect(screen.queryByText('Credential saved')).toBeNull()
  } finally { controller.dispose() }
})

it('does not publish late replies after disposal', async()=>{
  const pending: PromiseWithResolvers<[]> = Promise.withResolvers()
  const controller = new AuthorizationController({
    authorizations: () => pending.promise,
    beginAuthorization: async () => {},
    respondAuthorization: async () => {},
  })
  const store=controller.inject().hooks.authorizations
  const request=controller.refresh()
  controller.dispose()
  pending.resolve([])
  await request
  expect(store.getSnapshot().loaded).toBe(false)
})
