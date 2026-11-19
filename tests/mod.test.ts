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
    seen.runs += 1
    return seen.answer(JSON.parse(e.init.stdin))
  })
  on('prompt.submit', ($, e) => { seen.downstream += 1; return { text: e.text } })
  return seen
}
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

test('a command file command after /maisecrets with a space goes into the box with its colon', async ($, on) => {
  const seen = ownSetup(on, (q) => own(q.fill_check === true ? { masked: q.prompt, count: 0 } : {}))
  for (const [spaced, colon] of [['/maisecrets status', '/maisecrets:status'], ['/maisecrets list', '/maisecrets:list'],
    ['/maisecrets settings rehydration confirm', '/maisecrets:settings rehydration confirm'],
    ['/maisecrets forget SECRET_c1', '/maisecrets:forget SECRET_c1'], ['/maisecrets sref login', '/maisecrets:sref login'],
    ['/maisecrets audit 5', '/maisecrets:audit 5'], ['/maisecrets rules', '/maisecrets:rules'],
    ['/maisecrets put', '/maisecrets:put'], ['/maisecrets send', '/maisecrets:send'],
    ['/maisecrets guard status', '/maisecrets:guard status'], ['/maisecrets shortcut', '/maisecrets:shortcut'],
    ['/maisecrets ner local', '/maisecrets:ner local'], ['/maisecrets report last', '/maisecrets:report last']]) {
    seen.filled.length = 0
    seen.downstream = 0
    const r = await $.prompt.submit({ text: spaced, wait: false, origin: { kind: 'composer' } })
    expect(r.drop).toBe(`maisecrets: I put ${colon} into the input box. Press Enter to run it, or clear the box.`)
    await settleFill()
    expect(seen.filled).toEqual([colon])
    expect(seen.downstream).toBe(0)
  }
  // claude -p and an SDK host have no input box: the line names the command
  seen.filled.length = 0
  const r = await $.prompt.submit({ text: '/maisecrets status', wait: false, origin: { kind: 'sdk' } })
  expect(r.drop).toBe('maisecrets: send /maisecrets:status with the colon to run it. Nothing was sent.')
  await settleFill()
  expect(seen.filled).toEqual([])
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
  for (const text of [RAW.replace(':', ' '), '/maisecrets stauts ' + RAW.slice(19)]) {
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
  const p = await $.prompt.submit({ text: RAW.replace(':', ' '), wait: false, origin: { kind: 'sdk' } })
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
      const r = await $.prompt.submit({ text: RAW.replace(':', ' '), wait: false, origin: { kind } })
      expect(r.drop).toBe('maisecrets could not check the text, so it removed it from the input box. Type it again.')
      await settleFill()
      expect(seen.filled).toEqual([''])
      expect(seen.downstream).toBe(0)
    }
    // claude -p has no box: nothing to empty, and the line says that nothing was sent
    seen.filled.length = 0
    const s = await $.prompt.submit({ text: RAW.replace(':', ' '), wait: false, origin: { kind: 'sdk' } })
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
    ended: 0 }
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
  on('clock.after', () => new Promise(() => {}))
  on('prompt.fill', ($, e) => { st.fills.push(e.text); return { isFilled: true } })
  on('process.run', ($, e) => {
    st.checks.push(e)
    const answer = typeof opts.answer === 'function' ? opts.answer(JSON.parse(e.init.stdin), e) : opts.answer
    if (answer === null) return { value: { exitCode: 1, stderr: 'boom', stdout: '' } }
    return { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: e.argv[2], ...answer }) } }
  })
  on('process.spawn', async function * ($, e) {
    st.spawns.push(e)
    if (opts.spawnFails) return { deny: 'cannot start' }
    const pick = (v, d) => (typeof v === 'function' ? v(e) : v) ?? d
    for (const text of pick(opts.early, [])) yield { stream: 'stdout', text }
    if (opts.gate) await opts.gate
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
    expect(r.drop).toBe('maisecrets: /maisecrets:list runs without the AI; its output opens in a panel.')
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
  expect(r.drop).toBe('maisecrets: /maisecrets:sref login opens your browser; the status line shows the wait.')
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

test('a start that fails reports it, clears the status line and frees the next login', async ($, on) => {
  const st = runSetup(on, { answer: LOGIN, spawnFails: true })
  await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.toasts.length > 0)).toBe(true)
  expect(st.toasts).toEqual(['maisecrets could not run /maisecrets:sref login. Send it again.'])
  expect(st.statuses[st.statuses.length - 1]).toBeUndefined()
  await $.prompt.submit({ text: '/maisecrets:sref login team-gw', wait: false, origin: { kind: 'composer' } })
  expect(await until(() => st.spawns.length === 2)).toBe(true)
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

test('the space form runs as the colon form', async ($, on) => {
  const st = runSetup(on, { answer: LIST })
  const r = await $.prompt.submit({ text: '/maisecrets list', wait: false, origin: { kind: 'composer' } })
  expect(r.drop).toBe('maisecrets: /maisecrets:list runs without the AI; its output opens in a panel.')
  expect(JSON.parse(st.checks.find(c => c.argv[2] === 'mod-prompt').init.stdin).prompt).toBe('/maisecrets:list')
  expect(await until(() => st.spawns.length === 1)).toBe(true)
})

test('the space form with no answer from Python runs nothing and empties the box (offer of fix/ux-0918)',
  async ($, on) => {
    const st = runSetup(on, { answer: null })
    const r = await $.prompt.submit({ text: '/maisecrets sref login', wait: false, origin: { kind: 'composer' } })
    expect(r.drop).toBe('maisecrets could not check the text, so it removed it from the input box. Type it again.')
    expect(st.spawns.length).toBe(0)
    expect(st.downstream).toBe(0)
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
  expect(login.title).toBe('maisecrets: /maisecrets:sref login')
  expect(list.title).toBe('maisecrets: /maisecrets:list')
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
