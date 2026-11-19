// The demo's refusal of the engine's requests (claude-mod/maisecrets-mod.mjs, http.fetch). The test kit raises no
// engine http.fetch, so this file takes the hook from register() and calls it as the engine would.
import { expect, test } from 'claude-code/testing'
import { register } from '../claude-mod/maisecrets-mod.mjs'

function hooks() {
  const got: Record<string, any> = {}
  const on: any = (name: string, a: any, b?: any) => {
    const fn = typeof a === 'function' ? a : b
    const entry: any = { fn, catch: null }
    if (!got[name]) got[name] = entry
    return { catch: (c: any) => { entry.catch = c; return undefined } }
  }
  register(on)
  return got
}

// the mod keeps what it learned per session id in its module: each case takes its own id
let ids = 0
function world(demo: boolean | null, opts: { damaged?: boolean, asked?: number[], id?: string } = {}) {
  const id = opts.id ?? `sess-fetch-${++ids}`
  return {
    session: { id: async () => id },
    clock: { now: async () => 1_000_000 },
    plugin: { root: '/plugin' },
    process: { run: async () => {
      opts.asked?.push(1)
      if (demo === null) return { exitCode: 1, stdout: '', stderr: '' }
      return { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-' + 'demo', demo,
                                                                 ...(opts.damaged ? { damaged: true } : {}) }) }
    } },
  }
}

function engineNext(counter: { n: number }, fail = false) {
  const next: any = async () => {
    counter.n++
    if (fail) throw new Error('network down')
    return { value: { status: 200, ok: true, headers: {}, text: 'sent' } }
  }
  next.origin = { plugin: 'engine', tier: 'core' }
  return next
}

test('in a demo session every engine request is refused, with a body or without', async () => {
  const h = hooks()['http.fetch']
  for (const init of [{ method: 'POST', body: '{"messages":[]}' }, { method: 'GET' }, undefined]) {
    const c = { n: 0 }
    const r = await h.fn(world(true), { url: 'https://api.example.com/v1/x', init }, engineNext(c))
    expect(r.deny).toContain('maisecrets demo')
    expect(c.n).toBe(0)
  }
})

test('when the plugin gives no answer, the request is refused and never goes out', async () => {
  // README, "The demo": when the Python gives no answer, the hooks refuse, so nothing goes out by mistake. A Python
  // that exits with an error leaves the demo state unknown: unknown is not "not in the demo"
  const h = hooks()['http.fetch']
  const c = { n: 0 }
  const r = await h.fn(world(null), { url: 'https://api.example.com/v1/x', init: { method: 'POST', body: '{}' } },
                       engineNext(c))
  expect(r.deny).toContain('maisecrets demo')
  expect(c.n).toBe(0)
})

test('outside the demo the request goes on; a failure after it went out is not sent again', async () => {
  const h = hooks()['http.fetch']
  const c = { n: 0 }
  const r = await h.fn(world(false), { url: 'https://api.example.com/v1/x', init: { method: 'GET' } }, engineNext(c))
  expect(r.value.text).toBe('sent')
  const d = { n: 0 }
  const next = engineNext(d, true)
  let thrown = null
  try { await h.fn(world(false), { url: 'u' }, next) } catch (err) { thrown = err }
  expect(thrown).not.toBeNull()
  next.called = true
  next.error = thrown
  let rethrown = null
  try { await h.catch(world(false), { url: 'u' }, next) } catch (err) { rethrown = err }
  expect(rethrown).not.toBeNull()
  expect(d.n).toBe(1)
})

test('a true from a damaged demo state is not kept: once demo off reset it, the session sends again', async () => {
  const h = hooks()['http.fetch']
  const asked: number[] = []
  const c = { n: 0 }
  for (let i = 0; i < 2; i++) {
    const r = await h.fn(world(true, { damaged: true, asked, id: 'sess-damaged' }), { url: 'u' }, engineNext(c))
    expect(r.deny).toContain('maisecrets demo')
  }
  expect(asked.length).toBe(2)                     // asked each time, never kept
  const r = await h.fn(world(false, { id: 'sess-damaged' }), { url: 'u' }, engineNext(c))
  expect(r.value.text).toBe('sent')                // reset by demo off in another session: out of the demo
  expect(c.n).toBe(1)
})

test('a session that learned "not in the demo" from an early request asks again once the demo starts in it', async () => {
  const h = hooks()
  const state = { demo: false }
  const $: any = { ...world(null, { id: 'sess-start' }),
    process: { run: async (argv) => {
      // the person's demo command: the mod's question answers it (prompt_commands.mod_command) and writes the state
      if (argv[2] === 'mod-' + 'prompt') {
        state.demo = true
        return { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-' + 'prompt', drop: 'on' }) }
      }
      return { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-' + 'demo', demo: state.demo }) }
    } },
    clock: { now: async () => 1_000_000, after: () => {} },
    prompt: { fill: async () => ({ isFilled: true }) },
    session: { id: async () => 'sess-start', cwd: async () => '/work' },
    ui: { invalidate: () => {}, log: () => {} } }
  const c = { n: 0 }
  // an early request of the client (a title, a warm-up): not in the demo, kept
  expect((await h['http.fetch'].fn($, { url: 'u' }, engineNext(c))).value.text).toBe('sent')
  // the person's first prompt starts the demo: the mod drops it with the answer, and nothing goes on
  const next: any = async () => { throw new Error('the demo command went on') }
  expect((await h['prompt.submit'].fn($, { text: '/maisecrets:demo on', origin: { kind: 'composer' } }, next)).drop)
    .toBe('on')
  // /rename: its request of its own is refused
  const r = await h['http.fetch'].fn($, { url: 'u', init: { method: 'POST', body: '{"messages":[]}' } }, engineNext(c))
  expect(r.deny).toContain('maisecrets demo')
  expect(c.n).toBe(1)
})
