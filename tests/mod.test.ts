// The mod's own logic (claude-mod/maisecrets-mod.mjs), run by `claude plugin test` with no session and no
// Python: $.process.run is stubbed. The rule under test: only a well-formed answer from the
// plugin's launcher changes the prompt; every other outcome passes it on unchanged, so the
// settings hook decides it (harness: prompt_secret_rewrite_off shows that hook blocks it).
import { expect, test } from 'claude-code/testing'

const TYPED = 'check TOKENWORD in CI'
const REWRITTEN = 'check ⟦SECRET_c1⟧ in CI'

const clock = { t: 1_000_000 }

function common(on, run) {
  on('clock.now', () => ({ value: clock.t }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.cwd', () => ({ value: '/work' }))
  // the mod reads no environment variable (the directory review flagged the read next to a program start)
  on('env.get', () => { throw new Error('the mod read an environment variable') })
  on('ui.log', () => ({ value: undefined }))
  on('process.run', run)
  // Claude Code's own answer to a prompt: the text that arrived
  on('prompt.submit', ($, e) => ({ text: e.text }))
}

async function submit($, kind = 'composer') {
  return $.prompt.submit({ text: TYPED, wait: false, origin: { kind } })
}

test('a well-formed answer replaces the prompt', async ($, on) => {
  let seen
  common(on, ($, e) => {
    seen = e
    return { value: { exitCode: 0, stderr: '',
                      stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN, count: 1 }) } }
  })
  const r = await submit($)
  expect(r.text).toBe(REWRITTEN)
  // the plugin's own dispatch.py, by python3 first, fixed text, with the prompt and the session on stdin
  expect(seen.argv).toEqual(['python3', 'hooks/dispatch.py', 'mod-prompt'])
  expect(typeof seen.init.cwd).toBe('string')        // the plugin folder: the command line is fixed text
  expect(seen.init.env).toEqual({ PYTHONUTF8: '1' })  // set over the environment, which stays
  expect(seen.init.timeoutMs > 0 && seen.init.timeoutMs <= 8000).toBe(true)
  expect(JSON.parse(seen.init.stdin)).toEqual({ prompt: TYPED, session_id: 'sess-1', cwd: '/work', origin: 'composer' })
})

test('a drop from the launcher drops the prompt: the demo answers it, and nothing is sent (maisecrets/demo.py)',
  async ($, on) => {
    const DEMO = 'maisecrets demo: nothing was sent to the AI. It masks 1 secret. /maisecrets:demo off to send again'
    common(on, () => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-prompt', drop: DEMO }) } }))
    const r = await submit($)
    expect(r.drop).toBe(DEMO)
    expect(r.text).toBeUndefined()
  })

test('a drop that is no string leaves the prompt to the settings hook', async ($, on) => {
  common(on, () => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-prompt', drop: 1 }) } }))
  expect((await submit($)).text).toBe(TYPED)
})

test('no rewrite from the launcher leaves the prompt unchanged', async ($, on) => {
  common(on, () => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-prompt' }) } }))
  expect((await submit($)).text).toBe(TYPED)
})

test('a failed launcher leaves the prompt unchanged, even with a well-formed answer', async ($, on) => {
  common(on, () => ({ value: { exitCode: 1, stderr: 'boom',
                               stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN, count: 1 }) } }))
  expect((await submit($)).text).toBe(TYPED)
})

test('a launcher that cannot start leaves the prompt unchanged', async ($, on) => {
  common(on, () => ({ deny: 'cannot start' }))
  expect((await submit($)).text).toBe(TYPED)
})

test('output that is no JSON leaves the prompt unchanged', async ($, on) => {
  common(on, () => ({ value: { exitCode: 0, stderr: '', stdout: 'maisecrets needs Python 3.9' } }))
  expect((await submit($)).text).toBe(TYPED)
})

test('an answer from something else leaves the prompt unchanged', async ($, on) => {
  common(on, () => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ text: REWRITTEN }) } }))
  expect((await submit($)).text).toBe(TYPED)
})

test('a text that is no string leaves the prompt unchanged', async ($, on) => {
  common(on, () => ({ value: { exitCode: 0, stderr: '',
                               stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: { a: 1 } }) } }))
  expect((await submit($)).text).toBe(TYPED)
})

test('a person\'s prompt from Remote Control and from claude -p is rewritten too', async ($, on) => {
  common(on, () => ({ value: { exitCode: 0, stderr: '',
                               stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN, count: 1 }) } }))
  expect((await submit($, 'bridge')).text).toBe(REWRITTEN)
  expect((await submit($, 'sdk')).text).toBe(REWRITTEN)
})

test('a prompt that is not a person\'s goes on unchanged and the launcher does not run', async ($, on) => {
  let runs = 0
  common(on, () => {
    runs += 1
    return { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN }) } }
  })
  // a message of another session too: the client gives the model its own copy, so a rewrite left the value in it
  // and hid it from the settings hook, which blocks it when it sees it unchanged (0.7.4, measured 2026-10-22)
  for (const kind of ['task-notification', 'channel', 'scheduled-trigger', 'unclassified', 'peer', 'peer-send-message']) {
    expect((await submit($, kind)).text).toBe(TYPED)
  }
  expect(runs).toBe(0)
})

const CHECKS = ['ms:(TOKENWORD)', '  Ms:(TOKENWORD', 'MS:(a)b)', '\nms:(x', 'ms: (TOKENWORD)', 'ms：（TOKENWORD）']

function checkSetup(on, run) {
  let downstream = 0
  on('clock.now', () => ({ value: clock.t }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.cwd', () => ({ value: '/work' }))
  on('env.get', () => { throw new Error('the mod read an environment variable') })
  on('ui.log', () => ({ value: undefined }))
  on('process.run', run)
  on('prompt.submit', ($, e) => { downstream += 1; return { text: e.text } })
  return () => downstream
}

test('a check ms:(…) is dropped with the verdict and never passed on', async ($, on) => {
  const sent = checkSetup(on, () => ({ value: { exitCode: 0, stderr: '',
    stdout: JSON.stringify({ maisecrets: 'mod-prompt', drop: 'VERDICT' }) } }))
  for (const text of CHECKS) {
    const r = await $.prompt.submit({ text, wait: false, origin: { kind: 'composer' } })
    expect(r.drop).toBe('VERDICT')
  }
  expect(sent()).toBe(0)
})

test('a check without a verdict is dropped all the same: no launcher, a failed one, or a rewrite', async ($, on) => {
  let n = 0
  const answers = [
    () => ({ deny: 'cannot start' }),
    () => ({ value: { exitCode: 1, stderr: 'boom', stdout: '' } }),
    () => ({ value: { exitCode: 0, stderr: '', stdout: 'not json' } }),
    () => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN }) } }),
  ]
  const sent = checkSetup(on, () => answers[Math.min(Math.floor(n++ / 3), answers.length - 1)]())
  for (let i = 0; i < 4; i++) {
    const r = await $.prompt.submit({ text: 'ms:(TOKENWORD)', wait: false, origin: { kind: 'composer' } })
    expect(typeof r.drop).toBe('string')
    expect(r.text).toBe(undefined)
  }
  expect(sent()).toBe(0)
})

test('a check that is no person\'s goes on to the settings hook, and plain "ms:" is an ordinary prompt', async ($, on) => {
  let runs = 0
  common(on, () => {
    runs += 1
    return { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN }) } }
  })
  expect((await $.prompt.submit({ text: 'ms:(TOKENWORD)', wait: false, origin: { kind: 'peer' } })).text)
    .toBe('ms:(TOKENWORD)')
  expect(runs).toBe(0)
  expect((await $.prompt.submit({ text: 'ms: see (TOKENWORD)', wait: false, origin: { kind: 'composer' } })).text)
    .toBe(REWRITTEN)
})

test('a check whose session cannot be read is dropped too', async ($, on) => {
  on('clock.now', () => ({ value: clock.t }))
  on('session.id', () => { throw new Error('no session') })
  on('session.cwd', () => ({ value: '/work' }))
  on('env.get', () => { throw new Error('the mod read an environment variable') })
  on('ui.log', () => ({ value: undefined }))
  on('process.run', () => { throw new Error('the launcher broke the handler') })
  on('prompt.submit', ($, e) => ({ text: e.text }))
  const r = await $.prompt.submit({ text: 'ms:(TOKENWORD)', wait: false, origin: { kind: 'composer' } })
  expect(typeof r.drop).toBe('string')
})

test('the tip of the answer is shown once next to the line of the rewrite', async ($, on) => {
  const logs = []
  on('clock.now', () => ({ value: clock.t }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.cwd', () => ({ value: '/work' }))
  on('env.get', () => { throw new Error('the mod read an environment variable') })
  on('ui.log', ($, e) => { logs.push(JSON.stringify(e)); return { value: undefined } })
  on('process.run', () => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify(
    { maisecrets: 'mod-prompt', text: REWRITTEN, count: 1, tip: 'Tip: check a value first with ms:(…)' }) } }))
  on('prompt.submit', ($, e) => ({ text: e.text }))
  expect((await submit($)).text).toBe(REWRITTEN)
  expect(logs.length).toBe(2)
  expect(logs[1]).toContain('ms:(')
})

test('an answer with count 0 passes the prompt on as typed and shows only its note', async ($, on) => {
  // the name service did not check the prompt (hooks.UNCHECKED_NOTE): no "masked 0 value(s)" line
  const logs = []
  let downstream = 0
  on('clock.now', () => ({ value: clock.t }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.cwd', () => ({ value: '/work' }))
  on('env.get', () => { throw new Error('the mod read an environment variable') })
  on('ui.log', ($, e) => { logs.push(JSON.stringify(e)); return { value: undefined } })
  on('process.run', () => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify(
    { maisecrets: 'mod-prompt', text: TYPED, count: 0, tip: 'maisecrets: the names in this prompt were not checked' }) } }))
  on('prompt.submit', ($, e) => { downstream += 1; return { text: e.text } })
  expect((await submit($)).text).toBe(TYPED)
  expect(downstream).toBe(1)
  expect(logs.length).toBe(1)
  expect(logs[0]).toContain('not checked')
})

test('a failure after the prompt was passed on drops it and sends nothing a second time', async ($, on) => {
  let downstream = 0
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.cwd', () => ({ value: '/work' }))
  // the mod reads no environment variable (the directory review flagged the read next to a program start)
  on('env.get', () => { throw new Error('the mod read an environment variable') })
  on('ui.log', () => ({ value: undefined }))
  on('process.run', () => ({ value: { exitCode: 0, stderr: '',
                                      stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN, count: 1 }) } }))
  on('prompt.submit', () => {
    downstream += 1
    throw new Error('the client failed after the rewrite')
  })
  const r = await submit($)
  expect(downstream).toBe(1)
  expect(typeof r.drop).toBe('string')
})

test('a Python that starts and fails hands on to the next one, in a fixed order', async ($, on) => {
  // Windows: python3 is often a store stub that starts and exits 9009; py -3 is the launcher that works
  const argvs = []
  common(on, ($, e) => {
    argvs.push(e.argv.join(' '))
    if (e.argv[0] === 'python3') return { value: { exitCode: 9009, stderr: '', stdout: '' } }
    return { value: { exitCode: 0, stderr: '',
                      stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN, count: 1 }) } }
  })
  expect((await submit($)).text).toBe(REWRITTEN)
  expect(argvs).toEqual(['python3 hooks/dispatch.py mod-prompt', 'py -3 hooks/dispatch.py mod-prompt'])
})

test('a Python that cannot start hands on to the next one', async ($, on) => {
  const argvs = []
  common(on, ($, e) => {
    argvs.push(e.argv[0])
    if (e.argv[0] !== 'python') return { deny: 'cannot start' }
    return { value: { exitCode: 0, stderr: '',
                      stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN, count: 1 }) } }
  })
  expect((await submit($)).text).toBe(REWRITTEN)
  expect(argvs).toEqual(['python3', 'py', 'python'])
})

test('when no Python answers, all three are tried once and the prompt goes on unchanged', async ($, on) => {
  let runs = 0
  common(on, () => {
    runs += 1
    return { value: { exitCode: 3, stderr: '', stdout: '' } }     // 3: dispatch.py on a Python older than 3.9
  })
  expect((await submit($)).text).toBe(TYPED)
  expect(runs).toBe(3)
})

test('all tries share one budget of 8 s: each gets what is left', async ($, on) => {
  const timeouts = []
  common(on, ($, e) => {
    timeouts.push(e.init.timeoutMs)
    clock.t += 3000                                  // each failed try takes 3 s
    return { value: { exitCode: 9009, stderr: '', stdout: '' } }
  })
  expect((await submit($)).text).toBe(TYPED)
  expect(timeouts).toEqual([8000, 5000, 2000])
})

test('no try starts after the budget is spent', async ($, on) => {
  const timeouts = []
  common(on, ($, e) => {
    timeouts.push(e.init.timeoutMs)
    clock.t += 5000                                  // two tries spend the budget: the third does not start
    return { value: { exitCode: 9009, stderr: '', stdout: '' } }
  })
  expect((await submit($)).text).toBe(TYPED)
  expect(timeouts).toEqual([8000, 3000])
})

test('a timeout ends the search: no second Python runs the rewrite again', async ($, on) => {
  let runs = 0
  common(on, () => {
    runs += 1
    clock.t += 8000                                  // the whole budget, then the call rejects
    return { deny: 'timed out' }
  })
  expect((await submit($)).text).toBe(TYPED)
  expect(runs).toBe(1)
})


test("a slash command's line goes on unchanged, without a launcher call: the settings hook decides it (#44)", async ($, on) => {
  let calls = 0
  common(on, () => {
    calls += 1
    return { value: { exitCode: 0, stderr: '',
                      stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN, count: 1 }) } }
  })
  // Claude Code throws away a prompt.submit change of a slash command's line and sends the line as typed: a rewrite
  // here made the hook see a placeholder while the value went to the model
  for (const text of ['/plugin:skill TOKENWORD', '/review TOKENWORD', '  /x', '/a.b-c:d-e TOKENWORD',
                      '/plugin:dir:cmd TOKENWORD', '/übersetzen TOKENWORD', '\n/x TOKENWORD']) {
    expect((await $.prompt.submit({ text, wait: false, origin: { kind: 'composer' } })).text).toBe(text)
  }
  expect(calls).toBe(0)
  // a slash inside the text is no command
  expect((await $.prompt.submit({ text: 'see a/b TOKENWORD', wait: false, origin: { kind: 'composer' } })).text)
    .toBe(REWRITTEN)
})

// ---- the demo (maisecrets/demo.py): the masked prompt enters, and the mod answers each model step without a request
const DEMO_LINE = 'Demo mode: nothing was sent to the AI. /clear to switch it off.'

function demoWorld(on, opts: { demo?: boolean | null, sent?: number[], asked?: string[], idThrows?: boolean,
  logged?: string[] } = {}) {
  on('clock.now', () => ({ value: clock.t }))
  on('session.id', () => {
    if (opts.idThrows) throw new Error('no session')
    return { value: 'sess-demo' }
  })
  on('session.cwd', () => ({ value: '/work' }))
  on('ui.log', ($, e) => { opts.logged?.push(e.text); return { value: undefined } })
  on('env.set', ($, e) => { (opts as any).env?.push([e.name, e.value]); return { value: {} } })
  // the mod reads no environment variable (the directory review flagged the read next to a program start): each
  // read is counted, also one that a try/catch of the mod would hide
  on('env.get', ($, e) => { (opts as any).envReads?.push(e.name); return { value: undefined } })
  on('process.run', ($, e) => {
    opts.asked?.push(e.argv[2])
    if (e.argv[2] === 'mod-demo') {
      if (opts.demo === null || opts.demo === undefined) return { value: { exitCode: 1, stdout: '', stderr: '' } }
      return { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-demo', demo: opts.demo,
                                                                           ...(opts as any).demoExtra }) } }
    }
    const on = (opts as any).inDemo ?? true
    return { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN,
                                                                         count: 1, demo: on, inDemo: on,
                                                                         ...(opts as any).promptExtra }) } }
  })
  on('prompt.submit', ($, e) => ({ text: e.text }))
  // the engine's request: the bottom of the chain, counted
  on('turn.step', async function * ($, e) {
    opts.sent?.push(e.index)
    yield { kind: 'text', index: 0, text: 'FROM-THE-MODEL' }
    return { turnId: e.turnId, index: e.index, answer: 'FROM-THE-MODEL', toolUses: [], stopReason: 'end_turn',
             usage: null }
  })
}

async function step($, index = 0, agentId?: string) {
  const s = $.turn.step({ turnId: 'turn-1', index, model: 'm', messageCount: 1, ...(agentId ? { agentId } : {}) })
  const chunks: any[] = []
  let result: any
  for (;;) {
    const n = await s.next()
    if (n.done) { result = n.value; break }
    chunks.push(n.value)
  }
  return { chunks, result }
}

test('a demo prompt enters with its masked text, and no model step sends a request', async ($, on) => {
  const sent: number[] = []
  const asked: string[] = []
  const logged: string[] = []
  demoWorld(on, { sent, asked, logged })
  const r = await $.prompt.submit({ text: TYPED, wait: false, origin: { kind: 'composer' } })
  expect(r.text).toBe(REWRITTEN)
  expect(logged).toEqual([])                  // no "masked … before the prompt was sent": nothing is sent
  for (const [i, agent] of [[0, undefined], [1, 'agent-7']] as const) {
    const { chunks, result } = await step($, i, agent)
    expect(result.answer).toBe(DEMO_LINE)
    expect(result.stopReason).toBe('end_turn')
    expect(result.toolUses).toEqual([])
    expect(chunks.some(c => c.kind === 'text' && c.text === DEMO_LINE)).toBe(true)
  }
  expect(sent).toEqual([])
  expect(asked).toEqual(['mod-prompt'])        // the prompt's answer said inDemo: no second question
})

test('in Cowork the first demo step answers with the text Python gave for the prompt, once, and sends nothing', async ($, on) => {
  const sent: number[] = []
  const SHOW = 'What the AI would have got:\n\nmasked\n\nDemo mode: nothing was sent to the AI. Start a new task to switch it off.'
  demoWorld(on, { sent, promptExtra: { show: SHOW } } as any)
  await $.prompt.submit({ text: TYPED, wait: false, origin: { kind: 'composer' } })
  const first = await step($)
  expect(first.result.answer).toBe(SHOW)
  expect(first.chunks.some(c => c.kind === 'text' && c.text === SHOW)).toBe(true)
  expect((await step($, 1)).result.answer).toBe(DEMO_LINE)     // used once
  expect(sent).toEqual([])
})

test('in Cowork a demo answer Python gave for an earlier prompt is never shown for a later one', async ($, on) => {
  // the prompt hook may block a prompt the mod passed on: then no step takes its answer, and the next prompt's step
  // must not show it
  const sent: number[] = []
  const OLD = 'What the AI would have got:\n\nold\n\nDemo mode: nothing was sent to the AI. Start a new task to switch it off.'
  const opts: any = { sent, promptExtra: { show: OLD } }
  demoWorld(on, opts)
  await $.prompt.submit({ text: TYPED, wait: false, origin: { kind: 'composer' } })
  opts.promptExtra = {}
  await $.prompt.submit({ text: TYPED, wait: false, origin: { kind: 'composer' } })
  expect((await step($)).result.answer).toBe(DEMO_LINE)
  expect(sent).toEqual([])
})

test('a session the mod has not seen asks at the step: in the demo no request goes out', async ($, on) => {
  const sent: number[] = []
  demoWorld(on, { demo: true, sent })
  expect((await step($)).result.answer).toBe(DEMO_LINE)
  expect(sent).toEqual([])
})

test('a session that is not in the demo sends as before', async ($, on) => {
  const sent: number[] = []
  demoWorld(on, { demo: false, sent })
  expect((await step($)).result.answer).toBe('FROM-THE-MODEL')
  expect(sent).toEqual([0])
})

test('a hook that fails answers the step itself unless the session is known not to be in the demo', async ($, on) => {
  const sent: number[] = []
  demoWorld(on, { demo: true, sent, idThrows: true })
  expect((await step($)).result.answer).toBe(DEMO_LINE)
  expect(sent).toEqual([])
})

test('only the demo command makes the next step ask again; an ordinary slash prompt keeps what is known', async ($, on) => {
  const sent: number[] = []
  const asked: string[] = []
  const opts = { demo: false as boolean | null, sent, asked }
  demoWorld(on, opts)
  expect((await step($)).result.answer).toBe('FROM-THE-MODEL')       // asked once: not in the demo, kept
  await $.prompt.submit({ text: '/maisecrets:status', wait: false, origin: { kind: 'composer' } })
  expect((await step($, 1)).result.answer).toBe('FROM-THE-MODEL')
  expect(asked.filter(a => a === 'mod-demo').length).toBe(1)          // the slash prompt kept the known false
  opts.demo = true
  await $.prompt.submit({ text: '/maisecrets:demo on', wait: false, origin: { kind: 'composer' } })
  expect((await step($, 2)).result.answer).toBe(DEMO_LINE)           // the demo command: asked again
  expect(sent).toEqual([0, 1])
})

test('no answer from Python after a slash prompt answers the step itself (fail closed)', async ($, on) => {
  const sent: number[] = []
  demoWorld(on, { demo: null, sent })
  await $.prompt.submit({ text: '/maisecrets:demo on', wait: false, origin: { kind: 'composer' } })
  expect((await step($)).result.answer).toBe(DEMO_LINE)
  expect(sent).toEqual([])
})

test('a compaction of a session in the demo is skipped: it would be a model request of its own', async ($, on) => {
  const opts = { demo: true as boolean | null }
  demoWorld(on, opts)
  let compacted = 0
  on('session.compact', () => { compacted++; return { messages: [{ role: 'user', text: 'summary', toolUses: [] }] } })
  const r = await $.session.compact({ trigger: 'manual', messages: [{ role: 'user', text: 'hi', toolUses: [] }] } as any)
  expect((r as any).skip).toContain('maisecrets demo')
  expect(compacted).toBe(0)
})

test('a compaction outside the demo runs as before', async ($, on) => {
  demoWorld(on, { demo: false })
  let compacted = 0
  on('session.compact', () => { compacted++; return { messages: [{ role: 'user', text: 'summary', toolUses: [] }] } })
  await $.session.compact({ trigger: 'manual', messages: [{ role: 'user', text: 'hi', toolUses: [] }] } as any)
  expect(compacted).toBe(1)
})

test('a demo prompt switches the next-prompt guess of the client off, once per process', async ($, on) => {
  const env: any[] = []
  const opts: any = { env }
  demoWorld(on, opts)
  await $.prompt.submit({ text: TYPED, wait: false, origin: { kind: 'composer' } })
  expect(env).toEqual([['CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION', 'false']])
  await $.prompt.submit({ text: TYPED, wait: false, origin: { kind: 'composer' } })
  expect(env.length).toBe(1)                  // once per process
})

test('a prompt out of the demo switches the next-prompt guess back on, only after the demo switched it off', async ($, on) => {
  const env: any[] = []
  const envReads: string[] = []
  const opts: any = { env, envReads, inDemo: false }
  demoWorld(on, opts)
  await $.prompt.submit({ text: TYPED, wait: false, origin: { kind: 'composer' } })
  expect(env).toEqual([])                     // never switched: nothing to switch back
  opts.inDemo = true
  await $.prompt.submit({ text: TYPED, wait: false, origin: { kind: 'composer' } })
  opts.inDemo = false
  await $.prompt.submit({ text: TYPED, wait: false, origin: { kind: 'composer' } })
  // '' brings the client's default back (its env parser reads '' as not set), with no undefined argument
  expect(env).toEqual([['CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION', 'false'], ['CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION', '']])
  expect(env.flat()).not.toContain(undefined)
  expect(envReads).toEqual([])
})

// ---- the UX test of 2026-11-17
test('an own command typed in a demo session runs without the model: the drop carries its output', async ($, on) => {
  const asked: string[] = []
  demoWorld(on, { demo: true, asked, demoExtra: { drop: 'Stored values (1)' } } as any)
  const r = await $.prompt.submit({ text: '/maisecrets:list', wait: false, origin: { kind: 'composer' } })
  expect((r as any).drop).toBe('Stored values (1)')
  expect(asked).toEqual(['mod-' + 'demo'])
})

test('a longer output of an own command goes above the drop, a row per line', async ($, on) => {
  const logged: string[] = []
  demoWorld(on, { demo: true, logged, demoExtra: { drop: '1 value(s) stored\n\nSECRET_c1  SECRET' } } as any)
  const r = await $.prompt.submit({ text: '/maisecrets:list', wait: false, origin: { kind: 'composer' } })
  expect(logged).toEqual(['1 value(s) stored', 'SECRET_c1  SECRET'])
  expect((r as any).drop).toContain('output is above')
})

test('an own command of a session known not to be in the demo asks nothing and goes on', async ($, on) => {
  const asked: string[] = []
  demoWorld(on, { demo: false, asked })
  await step($)                                                     // the step learned: not in the demo
  const r = await $.prompt.submit({ text: '/maisecrets:list', wait: false, origin: { kind: 'composer' } })
  expect(r.text).toBe('/maisecrets:list')
  // no second demo question; the prompt check asks once, and with no run in its answer the command file runs
  expect(asked).toEqual(['mod-' + 'demo', 'mod-' + 'prompt'])
})

test('the demo answer adds one line: what was masked, and once that names were not checked', async ($, on) => {
  const logged: string[] = []
  demoWorld(on, { logged, promptExtra: { masked: 'masked: 1 secret', namesUnchecked: true } } as any)
  await $.prompt.submit({ text: TYPED, wait: false, origin: { kind: 'composer' } })
  await $.prompt.submit({ text: TYPED, wait: false, origin: { kind: 'composer' } })
  expect(logged).toEqual(['demo · masked: 1 secret · names: not checked', 'demo · masked: 1 secret'])
})

test('a prompt answered in a damaged demo state keeps no true: the next step asks again', async ($, on) => {
  const sent: number[] = []
  const opts: any = { demo: false, sent, promptExtra: { damaged: true } }
  demoWorld(on, opts)
  await $.prompt.submit({ text: TYPED, wait: false, origin: { kind: 'composer' } })   // inDemo true, damaged
  expect((await step($)).result.answer).toBe('FROM-THE-MODEL')     // demo off reset it: the step asked again
  expect(sent).toEqual([0])
})

// ---- the person's own commands (prompt_commands.mod_command, night UX test findings C and F): the mod answers them with
// Python's text and empties the box; a Codex form that needs the model puts its slash form into the box; no answer
// from Python drops the prompt all the same
const settleFill = () => new Promise(resolve => setTimeout(resolve, 150))

function ownSetup(on, answer, logs: string[] = []) {
  const seen = { runs: 0, downstream: 0, filled: [] as string[], answer }
  on('clock.now', () => ({ value: clock.t }))
  on('clock.after', () => ({ value: undefined }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.cwd', () => ({ value: '/work' }))
  on('env.get', () => { throw new Error('the mod read an environment variable') })
  on('ui.log', ($, e) => { logs.push(e.text ?? JSON.stringify(e)); return { value: undefined } })
  on('prompt.fill', ($, e) => { seen.filled.push(e.text); return { isFilled: true } })
  on('process.run', ($, e) => {
    if (e.argv[2] === 'mod-values') return NOTE_ANSWER      // the mod notes the session (noteSession), not counted
    seen.runs += 1
    return seen.answer(JSON.parse(e.init.stdin))
  })
  on('prompt.submit', ($, e) => { seen.downstream += 1; return { text: e.text } })
  return seen
}
// the answer of the launcher to the mod's ask with no keys (noteSession): nothing to draw
const NOTE_ANSWER = { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-values', mode: 'off', values: {} }) } }
const own = (o) => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-prompt', ...o }) } })

test('a command the prompt hook answers is dropped with its answer, and the box is emptied', async ($, on) => {
  const LINE = 'maisecrets: the term is on your list now as NAME_1. This prompt was not sent to the AI.'
  const seen = ownSetup(on, () => own({ drop: LINE }))
  for (const text of ['/maisecrets:term add Bertolt Q', 'maisecrets: term add Bertolt Q', '/maisecrets:demo on',
    '/maisecrets:not-a-secret SECRET_c1', '/maisecrets:report incident',
    'maisecrets: set ssh_consent on', 'maisecrets: status']) {
    seen.filled.length = 0
    seen.downstream = 0
    const r = await $.prompt.submit({ text, wait: false, origin: { kind: 'composer' } })
    expect(r.drop).toBe(LINE)
    expect(r.text).toBeUndefined()
    await settleFill()
    expect(seen.filled).toEqual([''])
    expect(seen.downstream).toBe(0)
  }
})

test('a Codex form that needs the model puts its slash form into the box', async ($, on) => {
  const seen = ownSetup(on, () => own({ drop: 'maisecrets: in Claude Code this is /maisecrets:status test.',
    fill: '/maisecrets:status test' }))
  const r = await $.prompt.submit({ text: 'maisecrets: status test', wait: false, origin: { kind: 'composer' } })
  expect(typeof r.drop).toBe('string')
  await settleFill()
  expect(seen.filled).toEqual(['/maisecrets:status test'])
})

test('an answer of several lines goes above, a row per line, and the drop is one line', async ($, on) => {
  const logs: string[] = []
  ownSetup(on, () => own({ drop: 'first line\nsecond line' }), logs)
  const r = await $.prompt.submit({ text: 'maisecrets: list', wait: false, origin: { kind: 'composer' } })
  expect(r.drop).toBe('maisecrets: answered without the AI, the output is above.')
  expect(logs).toEqual(['first line', 'second line'])
})

test('a command with no answer from Python is dropped all the same and never passed on', async ($, on) => {
  const failures = [() => ({ deny: 'cannot start' }), () => ({ value: { exitCode: 1, stderr: 'boom', stdout: '' } }),
    () => ({ value: { exitCode: 0, stderr: '', stdout: 'not json' } }),
    () => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ drop: 'from another program' }) } })]
  const seen = ownSetup(on, failures[0])
  for (const fail of failures) {
    seen.answer = fail
    for (const text of ['/maisecrets:term add Bertolt Q', 'maisecrets: demo on']) {
      const r = await $.prompt.submit({ text, wait: false, origin: { kind: 'composer' } })
      expect(r.drop).toBe('maisecrets could not answer this command. Nothing was sent; send it again.')
      expect(seen.downstream).toBe(0)
    }
  }
})

test('a Codex-like prompt that is no command takes the normal way with the one answer Python gave', async ($, on) => {
  const seen = ownSetup(on, () => own({ text: REWRITTEN, count: 1 }))
  const r = await $.prompt.submit({ text: 'maisecrets: why was TOKENWORD blocked', wait: false,
    origin: { kind: 'composer' } })
  expect(r.text).toBe(REWRITTEN)
  expect(seen.runs).toBe(1)
})

test('a slash command the mod does not answer goes on as typed', async ($, on) => {
  const seen = ownSetup(on, () => own({}))
  const r = await $.prompt.submit({ text: '/maisecrets:demo', wait: false, origin: { kind: 'composer' } })
  expect(r.text).toBe('/maisecrets:demo')
  expect(seen.downstream).toBe(1)
})

test('the self-test value is no own command: with no answer from Python it goes on to the real prompt hook',
  async ($, on) => {
    // the hook must stop it, so its pass proves that hook ran (Gate A); the mod's fail-closed drop is not for it
    const seen = ownSetup(on, () => ({ value: { exitCode: 1, stderr: 'boom', stdout: '' } }))
    const r = await $.prompt.submit({ text: 'ms-selftest-abcdefghij12', wait: false, origin: { kind: 'composer' } })
    expect(r.text).toBe('ms-selftest-abcdefghij12')
    expect(seen.downstream).toBe(1)
  })

test('a command that is no person\'s takes the hook path: Python is not asked', async ($, on) => {
  const seen = ownSetup(on, () => own({ drop: 'x' }))
  const r = await $.prompt.submit({ text: '/maisecrets:term add Bertolt Q', wait: false, origin: { kind: 'peer' } })
  expect(r.text).toBe('/maisecrets:term add Bertolt Q')
  expect(seen.runs).toBe(0)
})

// ---- `/maisecrets <command> <args>`, typed by the person, is `/maisecrets:<command> <args>` (the Tab completion of
// `/maise` gives `/maisecrets` and a space): the same path and the same checks as the colon form, never more
test('a command after /maisecrets with a space, typed by the person, takes the path of its colon form', async ($, on) => {
  const LINE = 'maisecrets: answered as the colon form.'
  const prompts: any[] = []
  const seen = ownSetup(on, (q) => { prompts.push(q); return own({ drop: LINE }) })
  for (const [spaced, colon] of [['/maisecrets term add Bertolt Q', '/maisecrets:term add Bertolt Q'],
    ['/maisecrets demo on', '/maisecrets:demo on'], ['/maisecrets demo off', '/maisecrets:demo off'],
    ['/maisecrets not-a-secret SECRET_c1', '/maisecrets:not-a-secret SECRET_c1'],
    ['/maisecrets not-a-secret undo SECRET_c1', '/maisecrets:not-a-secret undo SECRET_c1'],
    ['/maisecrets term remove Bertolt Q', '/maisecrets:term remove Bertolt Q'],
    ['/maisecrets forget import:abc123', '/maisecrets:forget import:abc123'],
    ['/maisecrets report incident', '/maisecrets:report incident'], ['  /maisecrets Demo on', '/maisecrets:demo on']]) {
    for (const kind of ['composer', 'bridge']) {
      prompts.length = 0
      seen.downstream = 0
      const r = await $.prompt.submit({ text: spaced, wait: false, origin: { kind } })
      expect(r.drop).toBe(LINE)
      expect(seen.downstream).toBe(0)
      // each question Python gets is the colon form's: its text, the person's origin as it came, nothing added (the
      // demo's question for an own command, then the prompt hook's question)
      expect(prompts.map(q => q.prompt)).toEqual(prompts.map(() => colon))
      expect(prompts.map(q => q.origin)).toEqual(prompts.map(() => kind))
      const hook = prompts.filter(q => q.cwd !== undefined)
      expect(hook.length).toBe(1)
      expect(Object.keys(hook[0]).sort()).toEqual(['cwd', 'origin', 'prompt', 'session_id'])
    }
  }
})

test('an entry form that the mod does not answer goes on as typed to its command file, with no fill', async ($, on) => {
  // Cowork: the command file shows the output there, and the prompt hook reads the line as its colon form
  const seen = ownSetup(on, (q) => own(q.fill_check === true ? { masked: q.prompt, count: 0 } : {}))
  for (const text of ['/maisecrets status', '/maisecrets list', '/maisecrets settings rehydration confirm',
    '/maisecrets forget SECRET_c1', '/ms sref login', '/maisecrets:maisecrets audit 5', '/maisecrets:ms rules',
    '/maisecrets status test', '/ms', '/maisecrets:maisecrets']) {
    for (const kind of ['composer', 'sdk']) {
      seen.filled.length = 0
      seen.downstream = 0
      const r = await $.prompt.submit({ text, wait: false, origin: { kind } })
      expect(r.drop).toBeUndefined()
      expect(r.text).toBe(text)
      await settleFill()
      expect(seen.filled).toEqual([])
      expect(seen.downstream).toBe(1)
    }
  }
})

test('the slash entry /maisecrets sref goes on as typed even when Python answers with a text', async ($, on) => {
  // the engine throws away a change of a slash line (#44): a text answer never replaces it. In Cowork Python gives
  // none for it, and the hints name the text form `maisecrets: sref`, which the mod rewrites
  const SHOW = 'The person ran a maisecrets command, and maisecrets carried it out. Show the person this answer'
  const seen = ownSetup(on, () => own({ text: SHOW, count: 0 }))
  for (const text of ['/maisecrets sref', '/maisecrets sref status', '/maisecrets:sref']) {
    seen.downstream = 0
    const r = await $.prompt.submit({ text, wait: false, origin: { kind: 'composer' } })
    expect(r.drop).toBeUndefined()
    expect(r.text).toBe(text)
    expect(seen.downstream).toBe(1)
  }
  seen.downstream = 0
  const typed = await $.prompt.submit({ text: 'maisecrets: sref', wait: false, origin: { kind: 'composer' } })
  expect(typed.text).toBe(SHOW)
  expect(seen.downstream).toBe(1)
})

test('a prompt that is not the person\'s own keeps the space form: Python is not asked, nothing runs', async ($, on) => {
  const seen = ownSetup(on, () => own({ drop: 'x' }))
  for (const kind of ['peer', 'plugin', 'agent', 'hook', 'task-notification', 'channel']) {
    for (const text of ['/maisecrets not-a-secret SECRET_c1', '/maisecrets term remove Bertolt Q', '/maisecrets demo on',
      '/maisecrets settings rehydration automatic']) {
      seen.downstream = 0
      const r = await $.prompt.submit({ text, wait: false, origin: { kind } })
      expect(r.text).toBe(text)
      expect(seen.downstream).toBe(1)
    }
  }
  expect(seen.runs).toBe(0)
  expect(seen.filled).toEqual([])
})

test('in a demo session a command after /maisecrets with a space runs as its colon form, without the model',
  async ($, on) => {
    const asked: string[] = []
    demoWorld(on, { demo: true, asked, demoExtra: { drop: 'Stored values (1)' } } as any)
    const r = await $.prompt.submit({ text: '/maisecrets list', wait: false, origin: { kind: 'composer' } })
    expect((r as any).drop).toBe('Stored values (1)')
    expect(asked).toEqual(['mod-' + 'demo'])
  })


// the value check of a filled command (prompt_commands.fill_check): the box gets the masked form, never the value
test('a command with a value goes into the box masked, and with no check nothing goes into the box', async ($, on) => {
  const RAW = '/maisecrets:status ' + 'glpat-' + 'FILLxxxxx1234567890abcd'
  const MASKED = '/maisecrets:status \u27e6SECRET_c1\u27e7'
  const asked: any[] = []
  const seen = ownSetup(on, (q) => { asked.push(q); return own(q.fill_check === true ? { masked: MASKED, count: 1 } : {}) })
  for (const text of ['/maisecrets stauts ' + RAW.slice(19)]) {
    seen.filled.length = 0
    asked.length = 0
    const r = await $.prompt.submit({ text, wait: false, origin: { kind: 'composer' } })
    expect(r.drop).toBe(`maisecrets: I put ${MASKED} into the input box. Press Enter to run it, or clear the box. `
      + 'maisecrets masked 1 value(s) in it.')
    expect(r.drop).not.toContain(RAW.slice(19))
    await settleFill()
    expect(seen.filled).toEqual([MASKED])
    expect(asked.filter(q => q.fill_check === true).map(q => q.prompt)).toEqual([RAW])
  }
  // claude -p: the line names the masked form
  const p = await $.prompt.submit({ text: '/maisecrets stauts ' + RAW.slice(19), wait: false, origin: { kind: 'sdk' } })
  expect(p.drop).toBe(`maisecrets: send ${MASKED} with the colon to run it. Nothing was sent.`)
  // no answer (a failed start, a refused one, an exit code), an answer that is no command or one with a line break:
  // nothing is sent, and the box is emptied, because the engine puts the dropped text (maybe with a value) back
  for (const fail of [() => ({ value: { exitCode: 1, stderr: 'boom', stdout: '' } }), () => ({ deny: 'cannot start' }),
    () => own({ masked: 'echo hi', count: 0 }), () => own({ masked: '/maisecrets:status\nx', count: 0 }),
    () => own({}), () => ({ value: { exitCode: 0, stderr: '', stdout: 'not json' } })]) {
    seen.answer = (q) => (q.fill_check === true ? fail() : own({}))
    for (const kind of ['composer', 'bridge']) {
      seen.filled.length = 0
      seen.downstream = 0
      const r = await $.prompt.submit({ text: '/maisecrets stauts ' + RAW.slice(19), wait: false, origin: { kind } })
      expect(r.drop).toBe('maisecrets could not check the text, so it removed it from the input box. Type it again.')
      await settleFill()
      expect(seen.filled).toEqual([''])
      expect(seen.downstream).toBe(0)
    }
    // claude -p has no box: nothing to empty, and the line says that nothing was sent
    seen.filled.length = 0
    const s = await $.prompt.submit({ text: '/maisecrets stauts ' + RAW.slice(19), wait: false, origin: { kind: 'sdk' } })
    expect(s.drop).toBe('maisecrets could not check this command. Nothing was sent; type it again with the colon.')
    await settleFill()
    expect(seen.filled).toEqual([])
  }
})

// ---- the person's own commands, run by the mod without the AI (0.9.19): prompt_commands.run_plan in Python decides,
// with the prompt hook's own check; the mod drops the prompt and starts the CLI entry in the background

const until = async (cond: () => boolean, ms = 2000) => {
  const end = Date.now() + ms
  while (Date.now() < end) {
    if (cond()) return true
    await new Promise(resolve => setTimeout(resolve, 5))
  }
  return cond()
}

const KEY1 = 'SECRET_' + 'c1'
const KEY3 = 'SECRET_' + 'c3'

// opts.answer: what mod-prompt answers; opts.gate: a promise the spawned entry waits for (a login in the browser);
// opts.chunks: what it prints; opts.code: its exit code; opts.placed: whether a pane is placed; opts.spawnFails
function runSetup(on, opts: any = {}) {
  const st: any = { checks: [], spawns: [], statuses: [], toasts: [], logs: [], fills: [], opens: [], downstream: 0,
    ended: 0, afters: [] as number[] }
  on('clock.now', () => ({ value: clock.t }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.cwd', () => ({ value: '/work' }))
  on('env.get', () => { throw new Error('the mod read an environment variable') })
  on('ui.log', ($, e) => { st.logs.push(String(e.text)); return { value: undefined } })
  on('ui.status', ($, e) => { st.statuses.push(e.text); return { value: undefined } })
  on('ui.toast', ($, e) => { st.toasts.push(String(e.text)); return { value: undefined } })
  on('ui.open', ($, e) => { st.opens.push(e); return { value: { isPlaced: opts.placed ?? true } } })
  on('ui.close', () => ({ value: undefined }))
  on('ui.invalidate', () => ({ value: undefined }))
  // a wait of $.clock.after never ends here: the run's own timeout is not part of these tests
  on('clock.after', ($, e) => { st.afters.push(e.ms); return new Promise(() => {}) })
  on('prompt.fill', ($, e) => { st.fills.push(e.text); return { isFilled: true } })
  on('process.run', async ($, e) => {
    if (e.argv[2] === 'mod-values') return NOTE_ANSWER      // the mod notes the session (noteSession), not counted
    st.checks.push(e)
    if (opts.before) await opts.before(st.checks.filter(c => c.argv[2] === 'mod-prompt').length, e)
    const answer = typeof opts.answer === 'function' ? opts.answer(JSON.parse(e.init.stdin), e) : opts.answer
    if (answer === null) return { value: { exitCode: 1, stderr: 'boom', stdout: '' } }
    return { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: e.argv[2], ...answer }) } }
  })
  on('process.spawn', async function * ($, e) {
    st.spawns.push(e)
    if (opts.spawnFails) return { deny: 'cannot start' }
    const pick = (v, d) => (typeof v === 'function' ? v(e) : v) ?? d
    for (const text of pick(opts.early, [])) yield { stream: 'stdout', text }
    if (opts.ticking) {
      // a child that writes until it is released: a stop (return() on the stream) ends it at its next piece, as the
      // engine's kill ends a real child; a wait on one promise would hold the stop until the promise settles
      while (!opts.ticking.released) {
        yield { stream: 'stdout', text: ' ' }
        await new Promise(resolve => setTimeout(resolve, 5))
      }
    } else if (opts.gate) await opts.gate
    for (const text of pick(opts.chunks, ['Stored values: 0\n'])) yield { stream: 'stdout', text }
    st.ended += 1
    return { value: { code: opts.code ?? 0, signal: null } }
  })
  on('prompt.submit', ($, e) => { st.downstream += 1; return { text: e.text } })
  return st
}

const LIST = { run: { argv: ['list', '--args-stdin'], stdin: '' } }
const LOGIN = { run: { argv: ['sref', '--args-stdin'], stdin: 'login team-gw', long: true, server: 'team-gw' } }
const paneOf = (flight: string) => 'maisecrets-out-' + flight.replace(/[^a-z0-9-]/g, '-')
const OUTPUT = { plugin: 'maisecrets', component: 'Pane', requestId: paneOf('cmd:list'), surface: 'terminal',
  props: { title: 'maisecrets', isFocused: true, bodyColumns: 100, placement: 'dock', scroll: { offset: 0, bodyRows: 30 },
    view: {} } }
const BUSY = 'maisecrets: a login runs already; the status line shows it. Nothing else was started.'

test('a command the person typed runs without a model turn: the prompt is dropped and the output opens in a pane',
  async ($, on) => {
    const st = runSetup(on, { answer: LIST })
    const r = await $.prompt.submit({ text: '/maisecrets:list', wait: false, origin: { kind: 'composer' } })
    expect(r.drop).toBe('maisecrets: /maisecrets list runs without the AI; its output opens in a panel.')
    expect(r.text).toBeUndefined()
    expect(st.downstream).toBe(0)                  // nothing reaches the model
    // the prompt hook's own check first, with the person's origin: the same call as for the command file
    const check = st.checks.find(c => c.argv[2] === 'mod-prompt')
    expect(JSON.parse(check.init.stdin)).toEqual({ prompt: '/maisecrets:list', session_id: 'sess-1', cwd: '/work',
      origin: 'composer' })
    expect(await until(() => st.opens.some(o => o.id.startsWith('maisecrets-out-')))).toBe(true)
    // the entry of the command file, by the Python that answered, the arguments on stdin, the session in the env
    expect(st.spawns[0].argv).toEqual(['python3', 'hooks/dispatch.py', 'list', '--args-stdin'])
    expect(st.spawns[0].input).toBe('')
    expect(st.spawns[0].env).toEqual({ PYTHONUTF8: '1', CLAUDE_CODE_SESSION_ID: 'sess-1' })
    const ui = await $.ui.mount(OUTPUT as any)
    expect(await ui.find({ type: 'Text', text: 'Stored values: 0' })).toBeDefined()
    await ui.unmount()
  })

// live probe 2026-11-22: a forget opened a panel only to say that it deleted the key
test('the confirmation of a forget stands above the prompt and opens no pane', async ($, on) => {
  const FORGET = { run: { argv: ['forget', '--args-stdin'], stdin: 'SECRET_c9', view: 'lines' } }
  const st = runSetup(on, { answer: FORGET, chunks: ['Deleted SECRET_c9. A placeholder for it no longer works anywhere.\n'] })
  const r = await $.prompt.submit({ text: '/maisecrets:forget SECRET_c9', wait: false, origin: { kind: 'composer' } })
  expect(r.drop).toBe('maisecrets: /maisecrets forget runs without the AI; its answer shows above the prompt.')
  expect(await until(() => st.ended === 1)).toBe(true)
  expect(await until(() => st.logs.some(l => l.startsWith('Deleted SECRET_c9.')))).toBe(true)
  expect(st.opens.filter(o => String(o.id).startsWith('maisecrets-out-'))).toEqual([])
})

test('the output of /maisecrets:sref has a login button per server; a press starts that login', async ($, on) => {
  const STATUS = { run: { argv: ['sref', '--args-stdin'], stdin: '' } }
  const st = runSetup(on, {
    answer: (q) => q.prompt === '/maisecrets:sref login team-gw' ? LOGIN : STATUS,
    chunks: (e) => e.input === '' ? [
      'team-gw (gw.example): not logged in (/maisecrets:sref login team-gw)\n',
      'other (o.example): logged in; values go into files (log in again to allow commands: ' +
        '/maisecrets:sref login other)\n',
      'odd: /maisecrets:sref login bad;name\n'] : ['logged in\n'] })
  await $.prompt.submit({ text: '/maisecrets:sref', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.ended === 1)).toBe(true)
  await new Promise(resolve => setTimeout(resolve, 20))
  const ui = await $.ui.mount({ ...OUTPUT, requestId: paneOf('cmd:sref') } as any)
  expect(await ui.find({ type: 'Button', key: 'login:team-gw' })).toBeDefined()
  expect(await ui.find({ type: 'Button', key: 'login:other' })).toBeDefined()
  expect(await ui.find({ type: 'Button', key: 'login:bad' })).toBeUndefined()   // only a name the box takes
  expect(await ui.find({ type: 'Button', key: 'login:bad;name' })).toBeUndefined()
  const before = st.fills.length
  const waits = st.afters.filter(ms => ms === 60).length
  await ui.press({ key: 'login:team-gw' })
  await ui.unmount()
  // the press runs the login as the typed command would: Python checks it, the CLI gets the arguments on stdin
  expect(await until(() => st.spawns.length === 2)).toBe(true)
  const ask = st.checks.filter(c => c.argv[2] === 'mod-prompt').map(c => JSON.parse(c.init.stdin))
  expect(ask[ask.length - 1]).toEqual({ prompt: '/maisecrets:sref login team-gw', session_id: 'sess-1', cwd: '/work',
    origin: 'composer' })
  expect(st.spawns[1].input).toBe('login team-gw')
  expect(st.fills.length).toBe(before)                // the box keeps what the person typed
  // one wait of 60 ms: the login's pane takes the keys; a fill of the box would plan a second one
  expect(st.afters.filter(ms => ms === 60).length).toBe(waits + 1)
  expect(await until(() => st.toasts.some(t => t.includes('opens your browser')))).toBe(true)
  expect(st.downstream).toBe(0)
})

test('a prompt that is not the person\'s own keeps the command file: nothing runs', async ($, on) => {
  const st = runSetup(on, { answer: LOGIN })
  for (const kind of ['sdk', 'task-notification', 'channel', 'peer', 'scheduled-trigger']) {
    const r = await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind } })
    expect(r.text).toBe('/maisecrets:sref login team-gw')
  }
  await new Promise(resolve => setTimeout(resolve, 20))
  expect(st.spawns.length).toBe(0)
  expect(st.downstream).toBe(5)
})

test('claude -p (origin sdk) keeps the command file even when Python would plan a run', async ($, on) => {
  const st = runSetup(on, { answer: LIST })
  const r = await $.prompt.submit({ text: '/maisecrets:list', wait: false, origin: { kind: 'sdk' } })
  expect(r.text).toBe('/maisecrets:list')
  await new Promise(resolve => setTimeout(resolve, 20))
  expect(st.spawns.length).toBe(0)
})

test('the login: the status line waits for the consent and clears; the end is a toast', async ($, on) => {
  let release: () => void = () => {}
  const gate = new Promise<void>(resolve => { release = resolve })
  const st = runSetup(on, { answer: LOGIN, gate,
    chunks: ['maisecrets: log in to gw.example in your browser and give the consent.\n',
      'maisecrets: logged in to gw.example. A reference that this gateway shows in a session now gets its value.\n'] })
  const t0 = Date.now()
  const r = await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
  // the hook returns while the login still waits: the box is free at once
  expect(Date.now() - t0).toBeLessThan(1000)
  expect(r.drop).toBe('maisecrets: /maisecrets sref login opens your browser; the status line shows the wait.')
  expect(await until(() => st.spawns.length === 1)).toBe(true)
  expect(st.spawns[0].argv).toEqual(['python3', 'hooks/dispatch.py', 'sref', '--args-stdin'])
  expect(st.spawns[0].input).toBe('login team-gw')
  expect(st.statuses).toContain('maisecrets: waiting for your consent in the browser (team-gw)')
  expect(st.ended).toBe(0)
  release()
  expect(await until(() => st.toasts.length > 0)).toBe(true)
  expect(st.toasts).toEqual(['maisecrets: logged in at team-gw'])
  expect(st.statuses[st.statuses.length - 1]).toBeUndefined()      // the status line is cleared
  expect(st.downstream).toBe(0)
})

test('a failed login says why in the CLI\'s own words', async ($, on) => {
  const st = runSetup(on, { answer: LOGIN, code: 1,
    chunks: ['maisecrets: the login to gw.example did not complete: the consent was refused\n'] })
  await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.toasts.length > 0)).toBe(true)
  expect(st.toasts).toEqual(['maisecrets: the login to gw.example did not complete: the consent was refused'])
})

// #91: a login of a proposed claude.ai connector (the plan names it in `pair`): after the login succeeded, the mod
// asks the connector for its proof of a fresh nonce and hands the answer to Python, which binds only on a match
const LOGIN_PAIR = { run: { ...LOGIN.run, pair: 'team-gw' } }
const BOUND = 'maisecrets: the claude.ai connector team-gw is bound to gw.example: it proved that it reaches that ' +
  'gateway with your account.'
function pairSetup(on, opts: any = {}) {
  const asked: any[] = []
  const st = runSetup(on, { answer: (q) => q.action === 'pair_due' ? (opts.dueFails ? null : { due: opts.due ?? true })
    : q.action === 'pair_cancel' ? { cancelled: true }
    : q.action === 'pair' ? { bound: true, note: BOUND } : (opts.plan ?? LOGIN_PAIR), code: opts.code,
  chunks: ['maisecrets: logged in to gw.example. The claude.ai connector team-gw is bound only when it proves it.\n'] })
  const relayed: any[] = []
  on('tool.call', ($, e) => {
    relayed.push(e)
    // a tool whose result echoes the nonce (opts.echo)
    return { result: opts.echo ? 'seen ' + opts.echo.nonce : 'done' }
  })
  on('mcp.call', async ($, e) => {
    asked.push(e)
    if (opts.connectorFails) return { value: null }
    const nonce = e.args?.nonce
    // the AI carries the nonce into another tool call while the connector's call runs (the relay of #91)
    if (opts.relay) opts.answers.push(await opts.outer.tool.call({ tool: opts.relay, input: { note: 'use ' + nonce },
      tool_use_id: opts.id ?? 'toolu_01abc' } as any))
    if (opts.echo) {
      opts.echo.nonce = nonce
      opts.answers.push(await opts.outer.tool.call({ tool: 'Bash', input: { command: 'ls' } } as any))
    }
    if (opts.prompt) await opts.outer.prompt.submit({ text: 'look: ' + nonce, wait: false, origin: { kind: 'hook' } })
    return { value: { content: [{ type: 'text', text: JSON.stringify({ resource: 'https://gw.example/mcp',
      proof: 'p'.repeat(43), nonce }) }] } }
  })
  return { st, asked, relayed }
}
const questions = (st, action) => st.checks.filter(c => c.argv[2] === 'mod-settings')
  .map(c => JSON.parse(c.init.stdin)).filter(q => q.action === action)

test('after a login of a proposed connector succeeded, the mod asks the connector to prove it with a fresh nonce',
  async ($, on) => {
    const { st, asked } = pairSetup(on)
    await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
    expect(await until(() => st.toasts.includes(BOUND))).toBe(true)
    expect(questions(st, 'pair_due')).toEqual([{ action: 'pair_due', key: 'team-gw' }])
    expect(asked.length).toBe(1)
    expect([asked[0].server, asked[0].tool]).toEqual(['claude_ai_team-gw', 'sensitive_references_resource'])
    expect(Object.keys(asked[0].args)).toEqual(['nonce'])              // the nonce alone goes to the connector
    const nonce = asked[0].args.nonce
    expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/)
    const pair = questions(st, 'pair')
    expect(pair.length).toBe(1)
    expect(pair[0].key).toBe('team-gw')
    expect(pair[0].nonce).toBe(nonce)
    expect(JSON.parse(pair[0].answer).nonce).toBe(nonce)               // the connector's own answer, as it came
    // the pairing waits up to 20 s for Python (a discovery and one request to the gateway)
    const run = st.checks.find(c => c.argv[2] === 'mod-settings' && JSON.parse(c.init.stdin).action === 'pair')
    expect(run.init.timeoutMs).toBe(20000)
    expect(st.logs).toContain(BOUND)
    expect(st.toasts.indexOf('maisecrets: logged in at team-gw')).toBeLessThan(st.toasts.indexOf(BOUND))
    // a second login makes a new nonce
    await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
    expect(await until(() => asked.length === 2)).toBe(true)
    expect(asked[1].args.nonce).not.toBe(nonce)
    expect(st.downstream).toBe(0)
  })

async function asksNothing($, on, opts) {
  const { st, asked } = pairSetup(on, opts)
  await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.toasts.length > 0)).toBe(true)
  await new Promise(resolve => setTimeout(resolve, 50))
  expect(asked.length).toBe(0)
  expect(questions(st, 'pair').length).toBe(0)
  expect(st.toasts.includes(BOUND)).toBe(false)
  expect(questions(st, 'pair_due').length).toBe(opts.due === false ? 1 : 0)
}

test('a failed login asks the connector nothing', async ($, on) => asksNothing($, on, { code: 1 }))

test('a plan without a connector asks the connector nothing', async ($, on) => asksNothing($, on, { plan: LOGIN }))

test('no proposal that waits for a proof asks the connector nothing', async ($, on) =>
  asksNothing($, on, { due: false }))

test('a connector that gives no answer binds nothing, and the unused login mark goes', async ($, on) => {
  const { st, asked } = pairSetup(on, { connectorFails: true })
  await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.toasts.some(t => t.includes('was not bound')))).toBe(true)
  expect(asked.length).toBe(1)
  expect(questions(st, 'pair').length).toBe(0)
  expect(questions(st, 'pair_cancel')).toEqual([{ action: 'pair_cancel', key: 'team-gw' }])
  expect(st.toasts).toContain('maisecrets: the claude.ai connector team-gw was not bound: the connector did not ' +
    'answer. To try again, send /maisecrets:sref login team-gw.')
})

const TAINTED = 'maisecrets: the claude.ai connector team-gw was not bound: another tool call, a tool result or a ' +
  'prompt carried the nonce of this pairing, which only the connector may get. To try again, send ' +
  '/maisecrets:sref login team-gw.'

async function relayTaints($, on, opts) {
  const answers: any[] = []
  const { st, asked, relayed } = pairSetup(on, { ...opts, outer: $, answers })
  await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.toasts.some(t => t.includes('was not bound')))).toBe(true)
  expect(asked.length).toBe(1)
  expect(questions(st, 'pair').length).toBe(0)                    // the answer never reaches Python
  expect(questions(st, 'pair_cancel')).toEqual([{ action: 'pair_cancel', key: 'team-gw' }])
  expect(st.toasts).toContain(TAINTED)
  return { answers, relayed }
}

test('the nonce in a call of another connector while the pairing runs binds nothing, and the login mark goes',
  async ($, on) => {
    const { answers, relayed } = await relayTaints($, on,
      { relay: 'mcp__claude_ai_Real_GW__sensitive_references_resource' })
    // the call that carries the nonce never runs
    expect(answers[0].deny).toMatch(/carried the nonce of a running pairing/)
    expect(relayed.length).toBe(0)
  })

test('the nonce in a command while the pairing runs binds nothing, and the command never runs', async ($, on) => {
  const { answers, relayed } = await relayTaints($, on, { relay: 'Bash' })
  expect(answers[0].deny).toMatch(/carried the nonce of a running pairing/)
  expect(relayed.length).toBe(0)
})

test('a call of the pairing tool under the name of the connector that the AI made is no own call', async ($, on) => {
  const { answers } = await relayTaints($, on, { relay: 'mcp__claude_ai_team-gw__sensitive_references_resource' })
  expect(answers[0].deny).toMatch(/carried the nonce of a running pairing/)
})

test('the mod\'s own pairing call passes its tool hook and binds', async ($, on) => {
  const answers: any[] = []
  const { st, relayed } = pairSetup(on, { relay: 'mcp__claude_ai_team-gw__sensitive_references_resource',
    id: 'toolu_plugin_0123', outer: $, answers })
  await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.toasts.includes(BOUND))).toBe(true)
  expect(answers[0].deny).toBeUndefined()
  expect(relayed.length).toBe(1)
})

test('the nonce in a tool result while the pairing runs binds nothing, and the login mark goes', async ($, on) => {
  const { answers, relayed } = await relayTaints($, on, { echo: {} })
  expect(relayed.length).toBe(1)                // the call ran; its result carried the nonce
  expect(answers[0].deny).toBeUndefined()
})

test('the nonce in a prompt while the pairing runs binds nothing, and the login mark goes', async ($, on) => {
  await relayTaints($, on, { prompt: true })
})

test('no answer from Python about the proof asks the connector nothing, and the unused login mark goes',
  async ($, on) => {
    const { st, asked } = pairSetup(on, { dueFails: true })
    await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
    expect(await until(() => st.toasts.some(t => t.includes('was not bound')))).toBe(true)
    expect(asked.length).toBe(0)
    expect(questions(st, 'pair_cancel').length).toBe(1)
  })

test('a plan whose connector is not the server of the login asks nothing', async ($, on) => {
  const { st, asked } = pairSetup(on, { plan: { run: { ...LOGIN.run, pair: 'other' } } })
  await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.toasts.length > 0)).toBe(true)
  await new Promise(resolve => setTimeout(resolve, 50))
  expect(asked.length).toBe(0)
  expect(questions(st, 'pair_due').length).toBe(0)
})

test('a start that fails reports it, clears the status line and frees the next login', async ($, on) => {
  const st = runSetup(on, { answer: LOGIN, spawnFails: true })
  await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.toasts.length > 0)).toBe(true)
  expect(st.toasts).toEqual(['maisecrets could not run /maisecrets sref login. Send it again.'])
  expect(st.statuses[st.statuses.length - 1]).toBeUndefined()
  await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.spawns.length === 2)).toBe(true)
})

test('a login again while one waits in the browser stops it and starts a new one (another browser profile)',
  async ($, on) => {
    const ticking = { released: false }
    const release = () => { ticking.released = true }
    const st = runSetup(on, { answer: LOGIN, ticking, early: ['Open this URL: http://127.0.0.1:1/x\n'] })
    await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
    expect(await until(() => st.spawns.length === 1)).toBe(true)
    await new Promise(resolve => setTimeout(resolve, 20))
    // a logout while the login waits still starts nothing
    const c = await $.prompt.submit({ text: '/maisecrets:sref logout team-gw', wait: false, origin: { kind: 'composer' } })
    expect(c.drop).toBe(BUSY)
    const r = await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
    expect(r.drop).toBe('maisecrets: the earlier login was stopped, and a new one opens your browser. For another ' +
      'browser or profile, copy the login URL from the panel into it.')
    expect(await until(() => st.spawns.length === 2)).toBe(true)
    await new Promise(resolve => setTimeout(resolve, 20))
    // the stopped run leaves the status line of the new one as it is
    expect(st.statuses[st.statuses.length - 1]).toBe('maisecrets: waiting for your consent in the browser (team-gw)')
    release()
    // the first one was stopped (its loop never ended), the second ends: one toast, and the status line is cleared
    expect(await until(() => st.toasts.length > 0)).toBe(true)
    await new Promise(resolve => setTimeout(resolve, 20))
    expect(st.ended).toBe(1)
    expect(st.toasts).toEqual(['maisecrets: logged in at team-gw'])
    // the end stays in the transcript: the person was in the browser when it came
    expect(st.logs).toContain('maisecrets: logged in at team-gw')
    expect(st.statuses[st.statuses.length - 1]).toBeUndefined()
    expect(st.downstream).toBe(0)
  })

test('a login that ends while a second one is checked frees the flight when the second gets no run', async ($, on) => {
  let release: () => void = () => {}
  const gate = new Promise<void>(resolve => { release = resolve })
  let n = 0
  const st = runSetup(on, { gate, answer: (q, e) => {
      if (e.argv[2] !== 'mod-prompt') return LOGIN
      n += 1
      return n === 1 ? LOGIN : { drop: 'usage' }
    },
    // the first login ends while Python checks the second prompt
    before: async (k, e) => {
      if (k === 2 && e.argv[2] === 'mod-prompt') { release(); await new Promise(r => setTimeout(r, 100)) }
    } })
  await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.spawns.length === 1)).toBe(true)
  await new Promise(resolve => setTimeout(resolve, 20))
  await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
  await new Promise(resolve => setTimeout(resolve, 50))
  const c = await $.prompt.submit({ text: '/maisecrets:sref logout team-gw', wait: false, origin: { kind: 'composer' } })
  expect(c.drop).not.toBe(BUSY)
  expect(st.statuses[st.statuses.length - 1]).toBeUndefined()
})

test('a second login while one waits starts no second flow, also when both prompts come at once', async ($, on) => {
  let release: () => void = () => {}
  const gate = new Promise<void>(resolve => { release = resolve })
  const st = runSetup(on, { answer: LOGIN, gate })
  const [a, b] = await Promise.all([
    $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } }),
    $.prompt.submit({ text: '/maisecrets sref login team-gw', wait: false, origin: { kind: 'composer' } })])
  const c = await $.prompt.submit({ text: '/maisecrets:sref logout team-gw', wait: false, origin: { kind: 'composer' } })
  expect([a.drop, b.drop, c.drop].filter(d => d === BUSY).length).toBe(2)
  await new Promise(resolve => setTimeout(resolve, 20))
  expect(st.spawns.length).toBe(1)
  expect(st.downstream).toBe(0)
  release()
  expect(await until(() => st.toasts.length > 0)).toBe(true)
  // after the end the next login can start
  await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.spawns.length === 2)).toBe(true)
})

test('each entry form runs as the colon form', async ($, on) => {
  const st = runSetup(on, { answer: LIST })
  for (const text of ['/maisecrets list', '/ms list', '/maisecrets:maisecrets list', '/maisecrets:ms list',
    '  /MS List  ']) {
    const n = st.spawns.length
    st.checks.length = 0
    const r = await $.prompt.submit({ text, wait: false, origin: { kind: 'composer' } })
    expect(r.drop).toBe('maisecrets: /maisecrets list runs without the AI; its output opens in a panel.')
    expect(JSON.parse(st.checks.find(c => c.argv[2] === 'mod-prompt').init.stdin).prompt).toBe('/maisecrets:list')
    expect(await until(() => st.spawns.length === n + 1 && st.ended === n + 1)).toBe(true)
    await new Promise(resolve => setTimeout(resolve, 20))
  }
  expect(st.downstream).toBe(0)
})

// a /ms of the person's own is theirs: Python answers nothing when it is not the shortcut (prompt_commands.foreign_ms)
test('the question for /ms NAME says that the person typed /ms, and its empty answer passes the prompt on', async ($, on) => {
  const st = runSetup(on, { answer: (q) => (q.via_ms === true ? {} : LIST) })
  const r = await $.prompt.submit({ text: '/ms list', wait: false, origin: { kind: 'composer' } })
  expect(r.drop).toBeUndefined()
  expect(st.downstream).toBe(1)
  expect(st.spawns.length).toBe(0)
  expect(JSON.parse(st.checks.find(c => c.argv[2] === 'mod-prompt').init.stdin).via_ms).toBe(true)
  for (const text of ['/maisecrets:ms list', '/maisecrets list', '/msx list']) {
    st.checks.length = 0
    await $.prompt.submit({ text, wait: false, origin: { kind: 'composer' } })
    const q = st.checks.find(c => c.argv[2] === 'mod-prompt')
    if (q) expect(JSON.parse(q.init.stdin).via_ms).toBeUndefined()
  }
})

test('the entry alone opens the panel as /maisecrets does; where none is placed the overview runs', async ($, on) => {
  const PANEL = { run: { argv: ['entry'], view: 'panel' } }
  // the panel's own questions (mod-settings) get rows; the prompt's question gets the plan
  const st = runSetup(on, { answer: (q, e) => (e.argv[2] === 'mod-' + 'settings' ? { groups: [] } : PANEL),
    placed: true })
  for (const text of ['/ms', '/maisecrets:ms', '/maisecrets:maisecrets', '  /MS  ']) {
    st.checks.length = 0
    st.opens.length = 0
    const r = await $.prompt.submit({ text, wait: false, origin: { kind: 'composer' } })
    expect(r.drop).toBe('maisecrets: the panel opens. Esc closes it.')
    expect(JSON.parse(st.checks.find(c => c.argv[2] === 'mod-prompt').init.stdin).prompt).toBe('/maisecrets:maisecrets')
    expect(await until(() => st.opens.some(o => o.id === 'maisecrets-settings'))).toBe(true)
  }
  await new Promise(resolve => setTimeout(resolve, 20))
  expect(st.spawns.length).toBe(0)
  expect(st.fills.filter(f => f)).toEqual([])
})

test('where no panel is placed the entry alone runs the overview, and nothing goes into the box', async ($, on) => {
  const st = runSetup(on, { answer: { run: { argv: ['entry'], view: 'panel' } }, placed: false,
    chunks: ['maisecrets protects this session\nA blocked prompt waits: /maisecrets send sends it.\n'] })
  await $.prompt.submit({ text: '/ms', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.spawns.length === 1)).toBe(true)
  expect(st.spawns[0].argv).toEqual(['python3', 'hooks/dispatch.py', 'entry'])
  expect(await until(() => st.logs.some(l => l.includes('A blocked prompt waits')))).toBe(true)
  expect(st.fills.filter(f => f)).toEqual([])
})

test('a command that needs the model is dropped, and the entry command file runs it after the hook', async ($, on) => {
  const answer = { now: { entry: 'status test' } as any }
  const st = runSetup(on, { answer: () => answer.now })
  const r = await $.prompt.submit({ text: '/maisecrets status test', wait: false, origin: { kind: 'composer' } })
  expect(r.drop).toBe('maisecrets: /maisecrets status needs the AI; it runs now.')
  expect(st.spawns.length).toBe(0)
  expect(st.downstream).toBe(0)
  // the entry starts after a wait, so it does not wait on the turn that this hook holds (the other wait empties the box)
  expect(st.afters.filter(ms => ms !== 1000)).toEqual([60, 60])     // 1000: the note of the session (noteSession)
  // words that name no command, a second line or no text start nothing: the prompt goes on as typed
  for (const entry of ['bogus words', 'status\ntest', 12]) {
    answer.now = { entry }
    st.afters.length = 0
    const p = await $.prompt.submit({ text: '/maisecrets status test', wait: false, origin: { kind: 'composer' } })
    expect(p.drop).toBeUndefined()
    expect(st.afters).toEqual([])
  }
})

test('the space form with no answer from Python goes on as typed, and the hook decides it', async ($, on) => {
  const st = runSetup(on, { answer: null })
  const r = await $.prompt.submit({ text: '/maisecrets sref login', wait: false, origin: { kind: 'composer' } })
  expect(r.drop).toBeUndefined()
  expect(st.spawns.length).toBe(0)
  expect(st.downstream).toBe(1)
})

test('a person types /maisecrets NAME or a hidden /maisecrets:NAME: the command runs at once, no fill', async ($, on) => {
  const st = runSetup(on, { answer: LIST })
  on('command.run', () => ({ text: 'engine' }))
  for (const [command, args] of [['maisecrets', 'list'], ['maisecrets:list', ''], ['maisecrets:list', '  ']]) {
    const n = st.spawns.length
    st.checks.length = 0
    const r = await $.command.run({ command, args, origin: { kind: 'composer' } } as any)
    expect(r.text).toBe('/maisecrets list runs without the AI; its output opens in a panel.')
    expect((r as any).isTextDisplayOnly).toBe(true)
    expect(JSON.parse(st.checks.find(c => c.argv[2] === 'mod-prompt').init.stdin))
      .toEqual({ prompt: '/maisecrets:list', session_id: 'sess-1', cwd: '/work', origin: 'command' })
    expect(await until(() => st.spawns.length === n + 1 && st.ended === n + 1)).toBe(true)
    await new Promise(resolve => setTimeout(resolve, 20))
  }
  expect(st.fills).toEqual([])
})

// the engine stamps every local command run `composer`: the route tells Python so, and Python makes no change there
// that only the person's own prompt may make (prompt_commands.COMMAND_ROUTE, C22)
test('a command from the command.run route reaches Python as the command route, never as the person', async ($, on) => {
  const HINT = 'maisecrets: this command changes what maisecrets does, so it counts only as your own prompt. Nothing ' +
    'was changed. Send it as a prompt: maisecrets: set ssh_consent on'
  const st = runSetup(on, { answer: { drop: HINT } })
  on('command.run', () => ({ text: 'engine' }))
  for (const [command, args] of [['maisecrets', 'settings ssh_consent on'], ['maisecrets:settings', 'ssh_consent on'],
    ['maisecrets:term', 'add Bertolt Q'], ['maisecrets:not-a-secret', 'SECRET_c1']]) {
    st.checks.length = 0
    const r = await $.command.run({ command, args, origin: { kind: 'composer' } } as any)
    expect(r.text).toBe(HINT.replace(/^maisecrets: /, ''))
    const asked = st.checks.filter(c => c.argv[2] === 'mod-prompt').map(c => JSON.parse(c.init.stdin))
    expect(asked.length).toBeGreaterThan(0)
    expect(asked.every(q => q.origin === 'command')).toBe(true)
  }
  expect(st.spawns.length).toBe(0)
})

// the engine stamps every local command run `composer`, also one the AI started: a refused change fills no input box,
// even when an answer carries a text form, so no loosening change waits there for the person's Enter
test('a refused change from the command.run route never fills the input box', async ($, on) => {
  const FORM = 'maisecrets: ner https://ner.example.com/ner'
  const HINT = 'maisecrets: this command changes what maisecrets does, so it counts only as your own prompt. ' +
    'Nothing was changed. Send it as a prompt: ' + FORM
  const st = runSetup(on, { answer: { drop: HINT, offer: FORM } })
  on('prompt.read', () => ({ value: { text: '', cursor: 0 } }))
  on('command.run', () => ({ text: 'engine' }))
  for (const [command, args] of [['maisecrets', 'ner https://ner.example.com/ner'],
    ['maisecrets:ner', 'https://ner.example.com/ner']]) {
    const r = await $.command.run({ command, args, origin: { kind: 'composer' } } as any)
    expect(r.text).toBe(HINT.replace(/^maisecrets: /, ''))
  }
  expect(st.fills).toEqual([])
  expect(st.spawns.length).toBe(0)
})

// live probe 2026-11-22: `/maisecrets sref login` and `logout` typed were refused. Python names a login or a logout as
// a form for the box (prompt_commands._BOX_SREF_RE): it waits in an empty box for the person's Enter, as the login offer
test('a refused sref login or logout from the command.run route waits in an empty input box', async ($, on) => {
  const HINT = 'maisecrets: this command changes what maisecrets does, so it counts only as your own prompt. ' +
    'Nothing was changed. Send it as a prompt: '
  let box = ''
  let form = '/maisecrets:sref login gw'
  const st = runSetup(on, { answer: () => ({ drop: HINT + form, box: form }) })
  on('prompt.read', () => ({ value: { text: box, cursor: 0 } }))
  on('command.run', () => ({ text: 'engine' }))
  let r = await $.command.run({ command: 'maisecrets', args: 'sref login gw', origin: { kind: 'composer' } } as any)
  expect(st.fills).toEqual([form])
  expect(r.text).toBe('I put /maisecrets:sref login gw into the input box. Press Enter to run it, or clear the box.')
  form = '/maisecrets:sref logout'
  r = await $.command.run({ command: 'maisecrets', args: 'sref logout', origin: { kind: 'composer' } } as any)
  expect(st.fills).toEqual(['/maisecrets:sref login gw', form])
  // the person's own text stays: the command is only named
  box = 'my draft'
  r = await $.command.run({ command: 'maisecrets', args: 'sref logout', origin: { kind: 'composer' } } as any)
  expect(r.text).toBe((HINT + form).replace(/^maisecrets: /, ''))
  // any other form that an answer names for the box never goes there
  box = ''
  for (const other of ['maisecrets: ner https://ner.example.com/ner', '/maisecrets:maisecrets forget SECRET_c1',
    '/maisecrets:sref login gw; status']) {
    form = other
    r = await $.command.run({ command: 'maisecrets', args: 'sref login gw', origin: { kind: 'composer' } } as any)
    expect(r.text).toBe((HINT + other).replace(/^maisecrets: /, ''))
  }
  expect(st.fills.length).toBe(2)
  expect(st.spawns.length).toBe(0)
})

test('a hidden command that no person typed goes on to the engine, and the mod asks nothing', async ($, on) => {
  const st = runSetup(on, { answer: LIST })
  on('command.run', () => ({ text: 'engine' }))
  for (const kind of ['plugin', 'sdk', 'peer']) {
    const r = await $.command.run({ command: 'maisecrets:list', args: '', origin: { kind } } as any)
    expect(r.text).toBe('engine')
  }
  // a visible command (report, sref, the entry) goes on too: prompt.submit answers it
  for (const command of ['maisecrets:report', 'maisecrets:sref', 'maisecrets:maisecrets', 'compact']) {
    const r = await $.command.run({ command, args: '', origin: { kind: 'composer' } } as any)
    expect(r.text).toBe('engine')
  }
  expect(st.checks.length).toBe(0)
})

test('the prompt hook\'s block (a value in the arguments) drops the command and nothing runs', async ($, on) => {
  const BLOCK = 'maisecrets kept a secret from the AI.'
  const st = runSetup(on, { answer: { drop: BLOCK } })
  const r = await $.prompt.submit({ text: '/maisecrets:sref login TOKENWORD', wait: false, origin: { kind: 'composer' } })
  expect(r.drop).toBe(BLOCK)
  await new Promise(resolve => setTimeout(resolve, 20))
  expect(st.spawns.length).toBe(0)
  expect(st.statuses.length).toBe(0)
})

test('no plan from Python (status test, an older Python) keeps the command file', async ($, on) => {
  const st = runSetup(on, { answer: {} })
  const r = await $.prompt.submit({ text: '/maisecrets:status test', wait: false, origin: { kind: 'composer' } })
  expect(r.text).toBe('/maisecrets:status test')
  expect(st.downstream).toBe(1)
  expect(st.spawns.length).toBe(0)
})

for (const run of [{ argv: ['list', 'x; rm'] }, { argv: ['wipe', '--yes'] }, { argv: [] }, { argv: 'list' }]) {
  test(`a plan ${JSON.stringify(run)} with a word that is no fixed word or an entry not listed runs nothing`,
    async ($, on) => {
      const st = runSetup(on, { answer: { run } })
      const r = await $.prompt.submit({ text: '/maisecrets:list', wait: false, origin: { kind: 'composer' } })
      expect(r.text).toBe('/maisecrets:list')
      expect(st.spawns.length).toBe(0)
    })
}

test('/maisecrets:send puts the cleaned prompt into the box; nothing goes to the model', async ($, on) => {
  const st = runSetup(on, { answer: { run: { argv: ['pending'], fill: true } },
    chunks: ['deploy with \u27e6' + KEY1 + '\u27e7\n'] })
  const r = await $.prompt.submit({ text: '/maisecrets:send', wait: false, origin: { kind: 'composer' } })
  expect(typeof r.drop).toBe('string')
  expect(await until(() => st.toasts.length > 0)).toBe(true)
  expect(st.toasts).toEqual(['maisecrets: the cleaned prompt is in your input box. Press Enter to send it.'])
  expect(st.spawns[0].argv).toEqual(['python3', 'hooks/dispatch.py', 'pending'])
  expect(st.spawns[0].input).toBeUndefined()
  expect(st.downstream).toBe(0)
})

for (const [typed, argv, input] of [
  ['/maisecrets:status', ['status'], undefined],
  ['/maisecrets:status all', ['status', 'all'], undefined],
  ['/maisecrets:audit 5', ['audit', '--args-stdin'], '5'],
  ['/maisecrets:rules', ['rules'], undefined],
  ['/maisecrets:term', ['terms'], undefined],
  ['/maisecrets:forget ' + KEY3, ['forget', '--args-stdin'], KEY3],
  ['/maisecrets:put', ['put', '--clipboard', '--args-stdin'], ''],
  ['/maisecrets:shortcut status', ['shortcut', '--args-stdin'], 'status'],
  ['/maisecrets:guard status', ['guard', '--args-stdin'], 'status'],
  ['/maisecrets:report bug the pane is slow', ['report', '--args-stdin'], 'bug the pane is slow'],
  ['/maisecrets:sref', ['sref', '--args-stdin'], ''],
  ['/maisecrets:sref status', ['sref', '--args-stdin'], 'status'],
  ['/maisecrets:ner all', ['ner', 'all'], undefined],
  ['/maisecrets:settings ssh_consent on', ['settings', '--args-stdin'], 'ssh_consent on'],
] as const) {
  test(`${typed}: the person's prompt runs its entry with no model turn; another origin keeps the command file`,
    async ($, on) => {
      const run: any = { argv }
      if (input !== undefined) run.stdin = input
      const st = runSetup(on, { answer: { run } })
      const r = await $.prompt.submit({ text: typed, wait: false, origin: { kind: 'composer' } })
      expect(typeof r.drop).toBe('string')
      expect(st.downstream).toBe(0)
      expect(await until(() => st.opens.some(o => o.id.startsWith('maisecrets-out-')))).toBe(true)
      expect(st.spawns[0].argv).toEqual(['python3', 'hooks/dispatch.py', ...argv])
      expect(st.spawns[0].input).toBe(input)
      const other = await $.prompt.submit({ text: typed, wait: false, origin: { kind: 'peer' } })
      expect(other.text).toBe(typed)
      expect(st.spawns.length).toBe(1)
    })
}

test('without a placed pane the output goes above the prompt, never to the model', async ($, on) => {
  const st = runSetup(on, { answer: LIST, placed: false, chunks: [KEY1 + '  password  2h\n', 'the second row\n'] })
  await $.prompt.submit({ text: '/maisecrets:list', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.logs.includes('the second row'))).toBe(true)
  expect(st.downstream).toBe(0)
})

test('ner: the change of the prompt hook shows in the panel\'s name-service view, and a start shows its status line',
  async ($, on) => {
    const st = runSetup(on, { answer: (q, e) => e.argv[2] === 'mod-prompt'
      ? { run: { argv: ['ner'], view: 'ner', starting: true, note: 'maisecrets: names from a service' } }
      : { groups: [], source: 'local', lines: [], servers: [], starting: true } })
    const r = await $.prompt.submit({ text: '/maisecrets:ner local', wait: false, origin: { kind: 'composer' } })
    expect(typeof r.drop).toBe('string')
    expect(await until(() => st.statuses.includes('maisecrets: loading the name service (starting)'))).toBe(true)
    expect(await until(() => st.opens.some(o => o.id === 'maisecrets-settings'))).toBe(true)
    expect(st.spawns.length).toBe(0)
    expect(st.downstream).toBe(0)
  })

test('without a pane the login writes each line above the prompt as it comes: the URL before the consent',
  async ($, on) => {
    let release: () => void = () => {}
    const gate = new Promise<void>(resolve => { release = resolve })
    const URL_LINE = 'https://gw.example/auth/authorize?client_id=c1&state=s1'
    const st = runSetup(on, { answer: LOGIN, gate, placed: false,
      early: ['maisecrets: log in to gw.example in your browser and give the consent. If no browser opened, open:\n',
        URL_LINE + '\n'],
      chunks: ['maisecrets: logged in to gw.example.\n'] })
    await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
    expect(await until(() => st.logs.includes(URL_LINE))).toBe(true)
    expect(st.ended).toBe(0)                       // the consent is not given yet
    release()
    expect(await until(() => st.toasts.length > 0)).toBe(true)
    expect(st.logs.filter(l => l === URL_LINE).length).toBe(1)
    expect(st.logs).toContain('maisecrets: logged in to gw.example.')
  })

test('a login that waits and a list keep their own panes, titles and lines', async ($, on) => {
  let release: () => void = () => {}
  const gate = new Promise<void>(resolve => { release = resolve })
  const st = runSetup(on, { answer: (q, e) => (q.prompt ?? '').includes('sref') ? LOGIN : LIST, gate,
    early: (e) => e.argv.includes('sref') ? ['LOGIN-LINE\n'] : [],
    chunks: (e) => e.argv.includes('sref') ? ['LOGIN-END\n'] : ['LIST-LINE\n'] })
  await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.opens.some(o => o.id === paneOf('sref-login')))).toBe(true)
  expect(await until(() => st.spawns.length === 1)).toBe(true)
  // the list's run waits for the same gate, so both run at once
  await $.prompt.submit({ text: '/maisecrets:list', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.spawns.length === 2)).toBe(true)
  release()
  expect(await until(() => st.opens.some(o => o.id === paneOf('cmd:list')))).toBe(true)
  const login = st.opens.filter(o => o.id === paneOf('sref-login')).pop()
  const list = st.opens.filter(o => o.id === paneOf('cmd:list')).pop()
  expect(login.title).toBe('maisecrets: /maisecrets sref login')
  expect(list.title).toBe('maisecrets: /maisecrets list')
  const props = { title: 'maisecrets', isFocused: true, bodyColumns: 100, placement: 'dock',
    scroll: { offset: 0, bodyRows: 30 }, view: {} }
  const a = await $.ui.mount({ plugin: 'maisecrets', component: 'Pane', requestId: paneOf('sref-login'),
    surface: 'terminal', props } as any)
  expect(await a.find({ type: 'Text', text: 'LOGIN-LINE' })).toBeDefined()
  await a.unmount()
  const b = await $.ui.mount({ plugin: 'maisecrets', component: 'Pane', requestId: paneOf('cmd:list'),
    surface: 'terminal', props } as any)
  expect(await b.find({ type: 'Text', text: 'LOGIN-LINE' })).toBeUndefined()
  expect(await b.find({ type: 'Text', text: 'LIST-LINE' })).toBeDefined()
  const c = await $.ui.mount({ plugin: 'maisecrets', component: 'Pane', requestId: paneOf('sref-login'),
    surface: 'terminal', props } as any)
  expect(await c.find({ type: 'Text', text: 'LIST-LINE' })).toBeUndefined()
  expect(await c.find({ type: 'Text', text: 'LOGIN-END' })).toBeDefined()
  await c.unmount()
  await b.unmount()
})

// the status knows that the mod runs in a session from the row of an ask with no keys (status_verdict.note_mod).
// /clear and a resume give a new session id without session.start, and a slash line or a prompt that is no person's
// asks nothing else: each new session id is noted once, after the prompt's own check
test('each new session id is noted once, also for a slash line and a prompt not from the person', async ($, on) => {
  const runs: any[] = []
  const afters: number[] = []
  let id = 'sess-note-1'
  on('clock.now', () => ({ value: clock.t }))
  on('clock.after', ($, e) => { afters.push(e.ms); return { value: undefined } })
  on('session.id', () => ({ value: id }))
  on('session.cwd', () => ({ value: '/work' }))
  on('env.get', () => { throw new Error('the mod read an environment variable') })
  on('ui.log', () => ({ value: undefined }))
  on('ui.invalidate', () => ({ value: undefined }))
  on('process.run', ($, e) => {
    runs.push(e)
    return e.argv[2] === 'mod-values' ? NOTE_ANSWER : { value: { exitCode: 1, stderr: '', stdout: '' } }
  })
  on('prompt.submit', ($, e) => ({ text: e.text }))
  const notes = () => runs.filter(r => r.argv[2] === 'mod-values').map(r => JSON.parse(r.init.stdin))
  const r = await $.prompt.submit({ text: '/compact', wait: false, origin: { kind: 'composer' } })
  expect(r.text).toBe('/compact')
  expect(await until(() => notes().length === 1)).toBe(true)
  expect(notes()[0]).toEqual({ keys: [], refs: [], session_id: 'sess-note-1' })
  expect(afters).toContain(1000)
  await $.prompt.submit({ text: 'a report of a subagent', wait: false, origin: { kind: 'task-notification' } })
  await new Promise(resolve => setTimeout(resolve, 50))
  expect(notes().length).toBe(1)                 // the same session: once
  id = 'sess-note-2'                             // after /clear: a new id, no session.start
  await $.prompt.submit({ text: 'a report of a subagent', wait: false, origin: { kind: 'task-notification' } })
  expect(await until(() => notes().length === 2)).toBe(true)
  expect(notes()[1].session_id).toBe('sess-note-2')
})

// ---- the second net for tool results (session.append on the door tool-result) and the hooks watch

// a placeholder built at run time: the session that writes this file resolves a placeholder in its own text
const ph = (key: string) => String.fromCodePoint(0x27e6) + key + String.fromCodePoint(0x27e7)
const RAW = 'out TOKENWORD end'
const MASKED_TEXT = `out ${ph('SECRET' + '_c9')} end`
// the marker lines of the tool-result hook (maisecrets/second_net.py): the nonce is the one the mod gave the hooks
const CHECKED = (n) => `[maisecrets: result checked ${n}]`
const MASKED_MARK = (n, hash) => `[maisecrets: result masked ${n} ${hash}]`
// maisecrets/second_net.py output_hash: the strings of an output (keys sorted, each before its value), NUL between them
const textsOf = (v, out: string[] = []) => {
  if (typeof v === 'string') out.push(v)
  else if (Array.isArray(v)) v.forEach(x => textsOf(x, out))
  else if (v && typeof v === 'object') for (const k of Object.keys(v).sort()) { out.push(k); textsOf(v[k], out) }
  return out
}
const hashOf = async (v) => [...new Uint8Array(await crypto.subtle.digest('SHA-256',
  new TextEncoder().encode(textsOf(v).join('\0'))))].slice(0, 8).map(n => n.toString(16).padStart(2, '0')).join('')
const resultAnswer = (o) => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-result', ...o }) } })
const watchAnswer = (o) => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-settings', ...o }) } })
const WITHHELD_TEXT = '[maisecrets: the tool ran and finished, but maisecrets could not check its output, so the output ' +
  'is withheld. Do not run the tool again to see it; /maisecrets status shows why.]'
const HOOKS_TEXT = 'maisecrets hooks did not run in this session: values are not protected; run /maisecrets status'

function netWorld(on, session, run, opts: any = {}) {
  on('clock.now', () => ({ value: clock.t }))
  on('clock.after', () => ({ value: undefined }))
  on('session.id', () => ({ value: session }))
  on('session.cwd', () => ({ value: '/work' }))
  on('env.get', () => { throw new Error('the mod read an environment variable') })
  // the nonce the mod gives the hooks while they run: a settings hook of the test reads it as a hook process would
  const st = { nonce: undefined as string | undefined }
  on('env.set', ($, e) => {
    opts.env?.push([e.name, e.value])
    if (e.name === 'MAISECRETS_MOD_NET') st.nonce = e.value
    return { value: {} }
  })
  on('ui.log', ($, e) => { opts.logs?.push(String(e.text)); return { value: undefined } })
  on('ui.toast', ($, e) => { opts.toasts?.push(String(e.text)); return { value: undefined } })
  on('ui.invalidate', () => ({ value: undefined }))
  on('process.run', run)
  // the settings hooks beneath: what PostToolUse and UserPromptSubmit answered
  on('classic.PostToolUse', async () => (typeof opts.post === 'function' ? await opts.post(st.nonce) : opts.post) ?? {})
  on('classic.PostToolUseFailure', async () => (typeof opts.failure === 'function' ? await opts.failure(st.nonce)
    : opts.failure) ?? {})
  on('classic.UserPromptSubmit', () => opts.prompt ?? {})
}

const resultRow = (id, content: any = RAW, tool = 'Bash', isError = false) => ({
  message: { type: 'user', role: 'user',
             content: [{ type: 'tool_result', tool_use_id: id, content, ...(isError ? { is_error: true } : {}) }] },
  door: 'tool-result', origin: { kind: 'tool', tool }, uuid: 'row-' + id,
})

const stored = (r) => r.message.content[0].content
const post = ($, id, tool = 'Bash') => $.classic.PostToolUse({ tool_name: tool, tool_use_id: id, tool_input: {},
                                                              tool_response: RAW })
const asks = (runs) => runs.filter(x => x.argv.includes('mod-result'))

test('a result the maisecrets hook masked goes on as it is, its marker is taken out, and Python is not asked',
  async ($, on) => {
    const runs: any[] = []
    const env: any[] = []
    netWorld(on, 'net-1', ($, e) => { runs.push(e); return resultAnswer({ texts: ['x'], changed: true }) },
      { post: async (n) => ({ updatedToolOutput: MASKED_TEXT,
                              additionalContext: [`maisecrets masked 1 value(s).\n\n${MASKED_MARK(n, await hashOf(MASKED_TEXT))}`] }),
        env })
    const answer = await post($, 'tu-net-1')
    expect(answer.additionalContext).toEqual(['maisecrets masked 1 value(s).'])     // the model never reads the marker
    // the nonce goes to the hooks only while they run: set before, taken back after
    expect(env.map(([k]) => k)).toEqual(['MAISECRETS_MOD_NET', 'MAISECRETS_MOD_NET'])
    expect(env[0][1]).toMatch(/^[0-9a-f]{32}$/)
    expect(env[1][1]).toBe('')
    const r = await $.session.append(resultRow('tu-net-1', MASKED_TEXT))
    expect(stored(r)).toBe(MASKED_TEXT)
    expect(asks(runs).length).toBe(0)
  })

test('a clean result the maisecrets hook checked goes on as it is, and the marker leaves no context', async ($, on) => {
  const runs: any[] = []
  netWorld(on, 'net-1b', ($, e) => { runs.push(e); return resultAnswer({ texts: ['x'], changed: true }) },
    { post: (n) => ({ additionalContext: [CHECKED(n)] }) })
  const answer = await post($, 'tu-net-1b')
  expect(answer.additionalContext).toBeUndefined()
  expect(stored(await $.session.append(resultRow('tu-net-1b')))).toBe(RAW)
  expect(asks(runs).length).toBe(0)
})

test('a result whose PostToolUse failed (onFailure block) is masked by the second net', async ($, on) => {
  const runs: any[] = []
  const toasts: string[] = []
  netWorld(on, 'net-2', ($, e) => { runs.push(e); return resultAnswer({ texts: [MASKED_TEXT], changed: true }) },
    { post: { block: 'hook error' }, toasts })
  await post($, 'tu-net-2')
  const r = await $.session.append(resultRow('tu-net-2'))
  expect(stored(r)).toContain(MASKED_TEXT)
  expect(stored(r)).not.toContain('TOKENWORD')
  expect(stored(r)).toContain('maisecrets masked values in this tool result')
  expect(asks(runs).length).toBe(1)
  expect(asks(runs)[0].argv).toEqual(['python3', 'hooks/dispatch.py', 'mod-result'])
  expect(JSON.parse(asks(runs)[0].init.stdin)).toEqual({ session_id: 'net-2', cwd: '/work', tool_name: 'Bash',
                                                         agent_id: null, texts: [RAW] })
  // the person's toast names no value
  expect(toasts.length).toBe(1)
  expect(toasts[0]).not.toContain('TOKENWORD')
})

test('a result with no marker of maisecrets is masked: no maisecrets hook ran for that call', async ($, on) => {
  const runs: any[] = []
  netWorld(on, 'net-2b', ($, e) => { runs.push(e); return resultAnswer({ texts: [MASKED_TEXT], changed: true }) })
  await post($, 'tu-net-2b')
  expect(stored(await $.session.append(resultRow('tu-net-2b')))).toContain(MASKED_TEXT)
  expect(asks(runs).length).toBe(1)
})

test("another plugin's updated output without the masked marker of maisecrets is masked (L1)", async ($, on) => {
  netWorld(on, 'net-2c', () => resultAnswer({ texts: [MASKED_TEXT], changed: true }),
    { post: (n) => ({ updatedToolOutput: RAW, additionalContext: [CHECKED(n)] }) })
  await post($, 'tu-net-2c')
  expect(stored(await $.session.append(resultRow('tu-net-2c')))).toContain(MASKED_TEXT)
})

test('hooks that stop in the middle of a session: the next result without the marker is masked', async ($, on) => {
  const runs: any[] = []
  let answer: any = (n) => ({ additionalContext: [CHECKED(n)] })
  netWorld(on, 'net-2d', ($, e) => { runs.push(e); return resultAnswer({ texts: [MASKED_TEXT], changed: true }) },
    { post: (n) => (typeof answer === 'function' ? answer(n) : answer) })
  await post($, 'tu-net-2d-1')
  expect(stored(await $.session.append(resultRow('tu-net-2d-1')))).toBe(RAW)
  answer = {}                                       // the hooks of maisecrets no longer run
  await post($, 'tu-net-2d-2')
  expect(stored(await $.session.append(resultRow('tu-net-2d-2')))).toContain(MASKED_TEXT)
  expect(asks(runs).length).toBe(1)
})

test('a failed command (PostToolUseFailure, anthropics/claude-code#97278) is masked by the second net', async ($, on) => {
  netWorld(on, 'net-3', () => resultAnswer({ texts: [MASKED_TEXT], changed: true }), { failure: (n) => ({ additionalContext: [CHECKED(n)] }) })
  await $.tool.call({ tool: 'Bash', tool_use_id: 'tu-net-3', input: { command: 'cat .env; false' } }).catch(() => {})
  await $.classic.PostToolUseFailure({ tool_name: 'Bash', tool_use_id: 'tu-net-3', tool_input: {}, error: RAW })
  const r = await $.session.append(resultRow('tu-net-3', RAW, 'Bash', true))
  expect(stored(r)).toContain(MASKED_TEXT)
  expect(stored(r)).not.toContain('TOKENWORD')
})

test('an error with no state at all (a mod reload, a hook of its own that threw) is masked, not taken for a refusal',
  async ($, on) => {
    const runs: any[] = []
    netWorld(on, 'net-3b', ($, e) => { runs.push(e); return resultAnswer({ texts: [MASKED_TEXT], changed: true }) })
    const r = await $.session.append(resultRow('tu-net-3b', RAW, 'Bash', true))
    expect(stored(r)).toContain(MASKED_TEXT)
    expect(asks(runs).length).toBe(1)
  })

test('no answer from Python withholds the result, and the row is still stored: the session goes on', async ($, on) => {
  netWorld(on, 'net-4', () => ({ value: { exitCode: 1, stderr: 'boom', stdout: '' } }), { post: { block: 'hook error' } })
  await post($, 'tu-net-4')
  const r = await $.session.append(resultRow('tu-net-4', [{ type: 'text', text: RAW }]))
  expect(stored(r)).toBe(WITHHELD_TEXT)
})

test('an answer of the wrong length withholds the result', async ($, on) => {
  netWorld(on, 'net-5', () => resultAnswer({ texts: [MASKED_TEXT, 'more'], changed: true }), { post: { block: 'x' } })
  await post($, 'tu-net-5')
  expect(stored(await $.session.append(resultRow('tu-net-5')))).toBe(WITHHELD_TEXT)
})

test('a withheld answer of Python (names not checked, withhold) withholds the result', async ($, on) => {
  netWorld(on, 'net-5b', () => resultAnswer({ withheld: true }), { post: { block: 'x' } })
  await post($, 'tu-net-5b')
  expect(stored(await $.session.append(resultRow('tu-net-5b')))).toBe(WITHHELD_TEXT)
})

test('one Python start per row: a failed start of a Python that exists ends the search', async ($, on) => {
  const runs: any[] = []
  netWorld(on, 'net-6', ($, e) => { runs.push(e); return { value: { exitCode: 1, stderr: '', stdout: '' } } },
    { post: { block: 'x' } })
  await post($, 'tu-net-6a')
  await post($, 'tu-net-6b')
  const row = resultRow('tu-net-6a')
  row.message.content.push({ type: 'tool_result', tool_use_id: 'tu-net-6b', content: RAW })
  const r = await $.session.append(row)
  expect(r.message.content.map(b => b.content)).toEqual([WITHHELD_TEXT, WITHHELD_TEXT])
  expect(asks(runs).length).toBe(1)
})

test('a Python that is not there hands on to the next one; exit 3 too; the note of Python goes with the result',
  async ($, on) => {
    const runs: any[] = []
    netWorld(on, 'net-6c', ($, e) => {
      runs.push(e)
      // the rejection Claude Code 2.1.330 gives for a missing program (measured in the harness)
      if (e.argv[0] === 'python3') return { deny: 'failed to start: ENOENT: Executable not found in $PATH' }
      if (e.argv[0] === 'py') return { value: { exitCode: 3, stderr: '', stdout: '' } }
      return resultAnswer({ texts: [MASKED_TEXT], changed: true, note: 'names: not checked' })
    }, { post: { block: 'x' } })
    await post($, 'tu-net-6c')
    const r = await $.session.append(resultRow('tu-net-6c'))
    expect(asks(runs).map(x => x.argv[0])).toEqual(['python3', 'py', 'python'])
    expect(stored(r)).toContain('names: not checked')
    expect(stored(r)).toContain(MASKED_TEXT)
  })

test('a timeout of the first Python withholds the result and starts no second one', async ($, on) => {
  const runs: any[] = []
  netWorld(on, 'net-6d', ($, e) => { runs.push(e); return { deny: 'the command timed out' } }, { post: { block: 'x' } })
  await post($, 'tu-net-6d')
  expect(stored(await $.session.append(resultRow('tu-net-6d')))).toBe(WITHHELD_TEXT)
  expect(asks(runs).length).toBe(1)
})

test('a refused call (an error of a call that never ran) goes on as it is, and Python is not asked', async ($, on) => {
  const runs: any[] = []
  netWorld(on, 'net-10', ($, e) => { runs.push(e); return resultAnswer({ texts: ['x'], changed: true }) })
  on('tool.check', () => ({ decision: 'deny', reason: 'refused by a hook' }))
  await $.tool.call({ tool: 'Bash', tool_use_id: 'tu-net-10', input: { command: 'cat .env' } }).catch(() => {})
  const r = await $.session.append(resultRow('tu-net-10', 'PreToolUse:Bash hook error: refused', 'Bash', true))
  expect(stored(r)).toBe('PreToolUse:Bash hook error: refused')
  expect(asks(runs).length).toBe(0)
})

test('a placeholder in the result stays: the texts go to Python and back in order, media blocks stay', async ($, on) => {
  const img = { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'AAAA' } }
  const kept = `a ${ph('SECRET' + '_c1')}`
  netWorld(on, 'net-9', () => resultAnswer({ texts: [kept, MASKED_TEXT], changed: true }), { post: { block: 'x' } })
  await post($, 'tu-net-9', 'Read')
  const r = await $.session.append(resultRow('tu-net-9', [{ type: 'text', text: kept }, img, { type: 'text', text: RAW }],
    'Read'))
  const c = stored(r)
  expect(c.map(b => b.type)).toEqual(['text', 'text', 'image', 'text'])
  expect(c[1].text).toBe(kept)
  expect(c[3].text).toBe(MASKED_TEXT)
})

test('the watch: no prompt-hook row after a prompt shows one line, once per session', async ($, on) => {
  const logs: string[] = []
  const asked: any[] = []
  netWorld(on, 'watch-1', ($, e) => {
    if (e.argv[2] === 'mod-settings') asked.push(JSON.parse(e.init.stdin))
    return watchAnswer({ ran: false })
  }, { logs })
  await $.classic.UserPromptSubmit({ prompt: 'hello', session_id: 'watch-1' })
  expect(await until(() => logs.some(l => l.includes('hooks did not run')))).toBe(true)
  expect(logs.filter(l => l.includes('hooks did not run'))).toEqual([HOOKS_TEXT])
  expect(asked[0]).toEqual({ action: 'hooks_ran', session_id: 'watch-1', since: clock.t / 1000 })
  await $.classic.UserPromptSubmit({ prompt: 'again', session_id: 'watch-1' })
  await new Promise(resolve => setTimeout(resolve, 50))
  expect(logs.filter(l => l.includes('hooks did not run')).length).toBe(1)
})

test('the watch says nothing when the hook ran, when Python gives no answer, or in Cowork', async ($, on) => {
  const logs: string[] = []
  let answer: any = { ran: true }
  const asked: any[] = []
  netWorld(on, 'watch-2', ($, e) => {
    // a failed ask tries the next Python too: each session is counted once
    const id = JSON.parse(e.init.stdin).session_id
    if (e.argv[2] === 'mod-settings' && !asked.includes(id)) asked.push(id)
    return answer === null ? { value: { exitCode: 1, stderr: '', stdout: '' } } : watchAnswer(answer)
  }, { logs })
  await $.classic.UserPromptSubmit({ prompt: 'hello', session_id: 'watch-2' })
  expect(await until(() => asked.length === 1)).toBe(true)
  answer = null
  await $.classic.UserPromptSubmit({ prompt: 'hello', session_id: 'watch-3' })
  expect(await until(() => asked.length === 2)).toBe(true)
  answer = { ran: null }                      // Cowork (status_verdict.hooks_watch)
  await $.classic.UserPromptSubmit({ prompt: 'hello', session_id: 'watch-4' })
  expect(await until(() => asked.length === 3)).toBe(true)
  await $.classic.UserPromptSubmit({ prompt: 'again', session_id: 'watch-2' })   // known to run: not asked again
  await new Promise(resolve => setTimeout(resolve, 100))
  expect(asked).toEqual(['watch-2', 'watch-3', 'watch-4'])
  expect(logs.filter(l => l.includes('hooks did not run'))).toEqual([])
})

test('the watch does not look at a prompt the settings hook blocked', async ($, on) => {
  const runs: any[] = []
  netWorld(on, 'watch-5', ($, e) => { runs.push(e); return { value: { exitCode: 1, stderr: '', stdout: '' } } },
    { prompt: { block: 'maisecrets blocked it' } })
  await $.classic.UserPromptSubmit({ prompt: 'hello', session_id: 'watch-5' })
  await new Promise(resolve => setTimeout(resolve, 100))
  expect(runs.filter(x => x.argv[2] === 'mod-settings').length).toBe(0)
})

test('a context row with the marker (the REPL of Code Mode, which the classic chain of the mod does not see) loses it',
  async ($, on) => {
    let nonce = ''
    netWorld(on, 'net-11', () => resultAnswer({ texts: ['x'], changed: false }),
      { post: (n) => { nonce = n; return {} } })
    await post($, 'tu-net-11')            // the mod's nonce, as a hook of this process saw it
    const text = `PostToolUse:REPL hook additional context: ${CHECKED(nonce)}\n\nPostToolUse:Bash hook additional context: a note`
    const r = await $.session.append({ message: { type: 'attachment', name: 'hook_additional_context',
                                                  content: [{ type: 'text', text }] },
                                       door: 'hook-context', origin: { kind: 'engine' }, uuid: 'row-ctx-11' })
    expect(r.message.content[0].text).toBe('PostToolUse:Bash hook additional context: a note')
  })

test('scenario A: a copied marker text in another entry, or one with another nonce, counts as no marker', async ($, on) => {
  const runs: any[] = []
  netWorld(on, 'net-12', ($, e) => { runs.push(e); return resultAnswer({ texts: [MASKED_TEXT], changed: true }) },
    { post: (n) => ({ additionalContext: [
      `another plugin copied: ${CHECKED(n)}\nand more text after it`,
      CHECKED('0'.repeat(32)),
    ] }) })
  const answer = await post($, 'tu-net-12')
  expect(answer.additionalContext.length).toBe(2)          // no marker of this process: both entries stay
  expect(stored(await $.session.append(resultRow('tu-net-12')))).toContain(MASKED_TEXT)
  expect(asks(runs).length).toBe(1)
})

test("scenario B: another hook's output in place of the one maisecrets masked does not count as masked", async ($, on) => {
  const runs: any[] = []
  netWorld(on, 'net-13', ($, e) => { runs.push(e); return resultAnswer({ texts: [MASKED_TEXT], changed: true }) },
    { post: async (n) => ({ updatedToolOutput: RAW, additionalContext: [MASKED_MARK(n, await hashOf(MASKED_TEXT))] }) })
  await post($, 'tu-net-13')
  expect(stored(await $.session.append(resultRow('tu-net-13')))).toContain(MASKED_TEXT)
  expect(asks(runs).length).toBe(1)
})

test('a masked object output with the right hash passes: the hash covers the keys and the strings', async ($, on) => {
  const runs: any[] = []
  const out = { stdout: MASKED_TEXT, stderr: '', interrupted: false }
  netWorld(on, 'net-14', ($, e) => { runs.push(e); return resultAnswer({ texts: ['x'], changed: true }) },
    { post: async (n) => ({ updatedToolOutput: out, additionalContext: [MASKED_MARK(n, await hashOf(out))] }) })
  await post($, 'tu-net-14')
  expect(stored(await $.session.append(resultRow('tu-net-14', MASKED_TEXT)))).toBe(MASKED_TEXT)
  expect(asks(runs).length).toBe(0)
})

test('only a hook_additional_context row loses the marker: another attachment row stays as it is', async ($, on) => {
  let nonce = ''
  netWorld(on, 'net-15', () => resultAnswer({ texts: ['x'], changed: false }), { post: (n) => { nonce = n; return {} } })
  await post($, 'tu-net-15')
  const text = `a note\n\n${CHECKED(nonce)}`
  const r = await $.session.append({ message: { type: 'attachment', name: 'nested_memory',
                                                content: [{ type: 'text', text }] },
                                     door: 'hook-context', origin: { kind: 'engine' }, uuid: 'row-ctx-15' })
  expect(r.message.content[0].text).toBe(text)
})

// ---- the band (#105, B11): the name check of a tool result of this turn left a rest

const BAND = { plugin: 'maisecrets', component: 'AbovePrompt', surface: 'terminal',
  props: { hasSurvey: false, isCollapsed: false, isWorking: false, maxRows: 10, bodyColumns: 160,
           scroll: { offset: 0, bodyRows: 9 }, view: {} } }
const bandText = async ($) => {
  const ui = await $.ui.mount(BAND as any)
  const t = await ui.find({ type: 'Text', text: /^maisecrets: (a result|\d+ results) of this turn/ })
  await ui.unmount()
  return t?.text
}
const withRest = (n, rest) => `[maisecrets: result checked ${n} rest ${rest}]`
const ONE = 'maisecrets: a result of this turn '
// the band lives as long as the mod process: each test starts a new turn with a prompt of the person
function bandWorld(on, session, run, opts: any = {}) {
  netWorld(on, session, run, opts)
  on('prompt.submit', ($, e) => ({ text: e.text }))
}
const newTurn = ($, kind = 'composer') => $.prompt.submit({ text: 'the next question', wait: false, origin: { kind } })

test("a rest shows the share above the prompt; a later result without a rest keeps the line; only the person's next prompt takes it away",
  async ($, on) => {
  let answer = (n) => ({ additionalContext: [`note for the AI\n\n${withRest(n, '70 rules')}`] })
  bandWorld(on, 'band-1', () => resultAnswer({ texts: ['x'], changed: false }), { post: (n) => answer(n) })
  await newTurn($)
  expect(await bandText($)).toBeUndefined()
  const r = await post($, 'tu-band-1')
  expect(r.additionalContext).toEqual(['note for the AI'])     // the marker with its rest never reaches the model
  const line = ONE + 'was checked for names in part (70 %); the rest went to the AI with the rules only'
  expect(await bandText($)).toBe(line)
  answer = (n) => ({ additionalContext: [CHECKED(n)] })
  await post($, 'tu-band-2')
  expect(await bandText($)).toBe(line)
  await newTurn($, 'task-notification')                       // no prompt of the person: the same turn
  expect(await bandText($)).toBe(line)
  await newTurn($)
  expect(await bandText($)).toBeUndefined()
})

test('parallel results on the hook path: the band names the count and the worst rest of the turn', async ($, on) => {
  const rests = { 'tu-band-3': '70 rules', 'tu-band-4': '40 cut', 'tu-band-6': '40 whole' }
  let id = ''
  bandWorld(on, 'band-2', () => resultAnswer({ texts: ['x'], changed: false }),
    { post: (n) => ({ additionalContext: [rests[id] ? withRest(n, rests[id]) : CHECKED(n)] }) })
  await newTurn($)
  for (const next of ['tu-band-3', 'tu-band-4', 'tu-band-5']) { id = next; await post($, next) }
  expect(await bandText($)).toBe('maisecrets: 2 results of this turn were not fully checked for names; the worst ' +
    'was checked for names in part (40 %); the rest was withheld from the AI')
  id = 'tu-band-6'                                              // the same share: a whole withhold is worse than a cut
  await post($, id)
  expect(await bandText($)).toBe('maisecrets: 3 results of this turn were not fully checked for names; the worst ' +
    'was checked for names in part (40 %); the whole result was withheld from the AI')
})

test('the second net: a rest, then a clean result and a subagent\'s clean result in the same turn keep the band',
  async ($, on) => {
    let rest: any = { share: 25, mode: 'cut' }
    bandWorld(on, 'band-3', () => resultAnswer({ texts: [RAW], changed: false, ...(rest ? { rest } : {}) }),
      { post: { block: 'hook error' } })
    await newTurn($)
    await post($, 'tu-band-7')
    await $.session.append(resultRow('tu-band-7'))
    const line = ONE + 'was checked for names in part (25 %); the rest was withheld from the AI'
    expect(await bandText($)).toBe(line)
    rest = undefined
    await post($, 'tu-band-8')
    expect(stored(await $.session.append(resultRow('tu-band-8')))).toBe(RAW)   // Python answered, with no rest
    expect(await bandText($)).toBe(line)
    await post($, 'tu-band-9')
    expect(stored(await $.session.append({ ...resultRow('tu-band-9'), agentId: 'agent-band' }))).toBe(RAW)
    expect(await bandText($)).toBe(line)
  })

test('a result withheld by Python counts as not checked and withheld', async ($, on) => {
  bandWorld(on, 'band-4', () => resultAnswer({ withheld: true, rest: { share: 0, mode: 'whole' } }),
    { post: { block: 'hook error' } })
  await newTurn($)
  await post($, 'tu-band-10')
  expect(stored(await $.session.append(resultRow('tu-band-10')))).toBe(WITHHELD_TEXT)
  expect(await bandText($)).toBe(ONE + 'was not checked for names; it was withheld from the AI')
})

test('a result too long for one request, and one the service did not answer for: rules only, the latter is worse',
  async ($, on) => {
    let rest = '0 long'
    bandWorld(on, 'band-5', () => resultAnswer({ texts: ['x'], changed: false }),
      { post: (n) => ({ additionalContext: [withRest(n, rest)] }) })
    await newTurn($)
    await post($, 'tu-band-11')
    expect(await bandText($)).toBe(ONE + 'was not checked for names (too long for one request to the name service); ' +
      'it went to the AI with the rules only')
    rest = '0 rules'
    await post($, 'tu-band-12')
    expect(await bandText($)).toBe('maisecrets: 2 results of this turn were not fully checked for names; the worst ' +
      'was not checked for names (the name service did not answer); it went to the AI with the rules only')
  })

test('a rest that is no share and mode of its form shows nothing, and a refused result keeps no band of its marker',
  async ($, on) => {
    let answer: any = (n) => ({ block: 'hook error', additionalContext: [withRest(n, '70 rules')] })
    bandWorld(on, 'band-6', () => resultAnswer({ texts: [RAW], changed: false, rest: { share: 100, mode: 'rules' } }),
      { post: (n) => answer(n) })
    await newTurn($)
    // a marker with a rest, but the hook blocked: its rest sets no band; the second net decides, and its rest of the
    // wrong form is none
    await post($, 'tu-band-13')
    expect(await bandText($)).toBeUndefined()
    await $.session.append(resultRow('tu-band-13'))
    expect(await bandText($)).toBeUndefined()
    // a marker whose rest has another form is no marker: the result goes to the second net
    answer = (n) => ({ additionalContext: [`[maisecrets: result checked ${n} rest 70 everything]`] })
    await post($, 'tu-band-14')
    expect(await bandText($)).toBeUndefined()
  })
