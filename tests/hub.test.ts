// The settings pane of the mod (proto): /maisecrets:settings typed by the person opens the pane and drops the
// command (no model turn); the pane lists the settings; a press sends the change through dispatch.py's pane entry.
import { expect, test } from 'claude-code/testing'

const ENTRY = 'mod-' + 'settings'
const PANE = {
  plugin: 'maisecrets',
  component: 'Pane',
  requestId: 'maisecrets-settings',
  props: {
    title: 'maisecrets settings',
    isFocused: true,
    bodyColumns: 100,
    placement: 'dock',
    scroll: { offset: 0, bodyRows: 30 },
    view: {},
  },
} as const

function rows(rehydration: string, mark = '') {
  return [
    { title: 'Protection', items: [
      { key: 'ssh_consent', label: 'Ask before ssh changes a host', value: 'off', choices: ['on', 'off'], mark: '',
        locked: false, hint: '' }] },
    { title: 'Stored values', items: [
      { key: 'rehydration', label: 'Put values into tool calls', value: rehydration,
        choices: ['automatic', 'confirm', 'block'], mark, locked: false, hint: '' }] },
    { title: 'Prompts and files', items: [
      { key: 'rule_dirs', label: 'Folders with your own rules', value: 'none', choices: [], mark: '', locked: false,
        list: true, count: 0 }] },
    { title: 'Personal data', items: [
      { key: 'regions', label: 'Countries for personal data', value: 'auto', values: ['auto'], multi: true,
        choices: ['auto', 'de', 'fr'], labels: {}, mark: '', locked: false }] },
  ]
}

const filled: string[] = []

// the panel draws at once and its status line follows in the background: draw it again until the query finds it
async function mountWhen($, query) {
  for (let i = 0; i < 100; i++) {
    const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
    if (await ui.find(query)) return ui
    await ui.unmount()
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  return $.ui.mount({ ...PANE, surface: 'terminal' })
}
// opts: a clock the test moves, a status line per ask, the waits of $.clock.after (a recorded wait never ends)
function engine(on, calls: any[], opened: { placed: boolean },
  opts: { clock?: { t: number }, line?: (n: number) => string, waits?: number[], delay?: (n: number) => number,
    offer?: string | null } = {}) {
  let asked = 0
  on('clock.now', () => ({ value: opts.clock ? opts.clock.t : 1_000_000 }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.cwd', () => ({ value: '/work' }))
  on('ui.log', () => ({ value: undefined }))
  on('ui.invalidate', () => ({ value: undefined }))
  on('ui.open', () => ({ value: opened.placed ? { isPlaced: true } : { isPlaced: false, reason: 'no surface' } }))
  on('ui.close', () => ({ value: undefined }))
  on('clock.after', ($, e) => {
    if (!opts.waits) return { value: undefined }
    opts.waits.push(e.ms)
    return new Promise(() => {})
  })
  on('prompt.fill', ($, e) => { filled.push(e.text); return { isFilled: true } })
  on('process.run', async ($, e) => {
    calls.push(e)
    if (e.argv.includes('mod-' + 'prompt') && JSON.parse(e.init.stdin || '{}').fill_check === true) {
      const prompt = JSON.parse(e.init.stdin).prompt
      return { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-' + 'prompt',
        masked: prompt, count: 0 }) } }
    }
    if (e.argv[2] !== ENTRY) return { value: { exitCode: 1, stderr: '', stdout: '' } }
    const q = JSON.parse(e.init.stdin)
    const set = q.action === 'set'
    // the status comes late, as on a busy CI runner: the panel draws first and the line follows
    const n = q.action === 'status' ? ++asked : 0
    if (q.action === 'status') await new Promise(resolve => setTimeout(resolve, opts.delay ? opts.delay(n) : 30))
    if (q.action === 'status') return { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({
      maisecrets: ENTRY, line: opts.line ? opts.line(n) : '🔒 maisecrets 0.9.12 protects this session', ms: 8,
      notes: [{ name: 'store', fact: 'test file, 0 values', next: 'set backend in config.json' }] }) } }
    const answer = (o) => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: ENTRY, ...o }) } })
    const VALUES = { rows: [{ key: 'SECRET_c1', type: 'SECRET', shown: '-', age: '2h', uses: 1, expires: '22h',
      live: true }], total: 1, offset: 0 }
    if (q.action === 'values') return answer(VALUES)
    if (q.action === 'login_offer') return answer({ fill: opts.offer ?? null })
    if (q.action === 'forget') return answer({ note: 'Forgot SECRET_c1.', rows: [], total: 0, offset: 0 })
    const NER = { source: 'off', locked: false, servers: ['team-gw'], lines: ['names: off (the rules alone)'] }
    if (q.action === 'ner') return answer(NER)
    if (q.action === 'ner_set') return answer({ ...NER, source: 'gateway', gateway_name: 'team-gw', note: 'set',
      login: 'team-gw' })
    return { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({
      maisecrets: ENTRY, groups: rows(set ? q.value : 'automatic', set ? '✎' : ''),
      note: set ? 'Saved. Stored values in tool calls is confirm (set by you).' : null, more: 11, config_only: [],
    }) } }
  })
  on('prompt.submit', ($, e) => ({ text: e.text }))
}

test('the typed command opens the pane and never reaches the model', async ($, on) => {
  const calls: any[] = []
  engine(on, calls, { placed: true })
  const r = await $.prompt.submit({ text: '/maisecrets:settings', wait: false, origin: { kind: 'composer' },
    command: { name: 'maisecrets:settings', args: '' } })
  expect(typeof r.drop).toBe('string')
  expect(calls.some(c => c.argv.join(' ') === `python3 hooks/dispatch.py ${ENTRY}`)).toBe(true)
})

test('without a placed pane (claude -p, Codex) the command goes on to the text view', async ($, on) => {
  engine(on, [], { placed: false })
  const r = await $.prompt.submit({ text: '/maisecrets:settings', wait: false, origin: { kind: 'sdk' },
    command: { name: 'maisecrets:settings', args: '' } })
  expect(r.drop).toBeUndefined()
})

test('a change typed with a value goes on to the settings hook, not the pane', async ($, on) => {
  const calls: any[] = []
  engine(on, calls, { placed: true })
  const r = await $.prompt.submit({ text: '/maisecrets:settings rehydration confirm', wait: false,
    origin: { kind: 'composer' }, command: { name: 'maisecrets:settings', args: 'rehydration confirm' } })
  expect(r.drop).toBeUndefined()
  expect(calls.some(c => JSON.parse(c.init.stdin || '{}').action === 'set')).toBe(false)
})

test('the pane lists the settings, and a press changes the value through the entry', async ($, on) => {
  const calls: any[] = []
  engine(on, calls, { placed: true })
  await $.prompt.submit({ text: '/maisecrets:settings', wait: false, origin: { kind: 'composer' },
    command: { name: 'maisecrets:settings', args: '' } })
  for (const surface of ['terminal', 'desktop'] as const) {
    const ui = await $.ui.mount({ ...PANE, surface })
    expect(await ui.find({ type: 'Text', text: /Put values into tool calls/ })).toBeDefined()
    expect((await ui.find({ key: 'set:rehydration:automatic' }))?.text).toMatch(/● automatic/)
    await ui.unmount()
  }
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await ui.press({ key: 'set:rehydration:confirm' })
  const set = calls.map(c => JSON.parse(c.init.stdin || '{}')).find(q => q.action === 'set')
  expect(set).toEqual({ action: 'set', key: 'rehydration', value: 'confirm' })
  await ui.unmount()
  const again = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect((await again.find({ key: 'set:rehydration:confirm' }))?.text).toMatch(/● confirm ✎/)
  expect(await again.find({ type: 'Text', text: /^Saved\./ })).toBeDefined()
  await again.unmount()
})

test('/maisecrets alone opens the same pane: a status line, the views, and the old-leaks button', async ($, on) => {
  const calls: any[] = []
  engine(on, calls, { placed: true })
  on('command.run', () => ({ text: 'engine' }))
  const r = await $.command.run({ command: 'maisecrets' })
  expect(r.text).toBeUndefined()
  const ui = await mountWhen($, { type: 'Text', text: /protects this session/ })
  expect(await ui.find({ type: 'Text', text: /protects this session/ })).toBeDefined()
  await ui.press({ key: 'stored' })
  await ui.unmount()
  const view = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await view.find({ type: 'Text', text: /SECRET_c1/ })).toBeDefined()
  await view.press({ key: 'back' })
  await view.unmount()
  const back = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await back.press({ key: 'leaks' })
  expect(filled).toContain('/maisecrets:secret-hygiene')
  await back.unmount()
})

test('the notes of the status are a button that opens and closes them', async ($, on) => {
  engine(on, [], { placed: true })
  on('command.run', () => ({ text: 'engine' }))
  await $.command.run({ command: 'maisecrets' })
  const ui = await mountWhen($, { key: 'notes' })
  expect((await ui.find({ key: 'notes' }))?.text).toMatch(/1 note/)
  expect(await ui.find({ type: 'Text', text: /store: test file/ })).toBeUndefined()
  expect(await ui.find({ type: 'Text', text: /Opened in/ })).toBeUndefined()
  await ui.press({ key: 'notes' })
  await ui.unmount()
  const open = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect((await open.find({ type: 'Text', text: /store: test file/ }))?.text).toMatch(/set backend/)
  await open.press({ key: 'notes' })
  await open.unmount()
  const closed = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await closed.find({ type: 'Text', text: /store: test file/ })).toBeUndefined()
  await closed.unmount()
})

test('a list setting fills the prompt box; the countries open their own view', async ($, on) => {
  engine(on, [], { placed: true })
  on('command.run', () => ({ text: 'engine' }))
  await $.command.run({ command: 'maisecrets' })
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ key: 'remove:rule_dirs' })).toBeUndefined()        // nothing to remove yet
  await ui.press({ key: 'add:rule_dirs' })
  expect(filled).toContain('/maisecrets:settings rule_dirs add ')
  await ui.unmount()
  await $.command.run({ command: 'maisecrets' })
  const main = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await main.find({ key: 'set:regions:de' })).toBeUndefined()        // not inline
  expect((await main.find({ key: 'regions:choose' }))?.text).toMatch(/choose/)
  await main.press({ key: 'regions:choose' })
  await main.unmount()
  const sub = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await sub.find({ key: 'set:regions:de' })).toBeDefined()
  expect(await sub.find({ key: 'back' })).toBeDefined()
  await sub.unmount()
})

test('stored values: forget asks first, then goes through the entry; no value is drawn', async ($, on) => {
  const calls: any[] = []
  engine(on, calls, { placed: true })
  on('command.run', () => ({ text: 'engine' }))
  await $.command.run({ command: 'maisecrets' })
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await ui.press({ key: 'stored' })
  await ui.unmount()
  const v = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await v.press({ key: 'forget:SECRET_c1' })
  await v.unmount()
  const ask = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect((await ask.find({ type: 'Text', text: /Forget SECRET_c1\?/ }))).toBeDefined()
  expect(calls.some(c => JSON.parse(c.init.stdin || '{}').action === 'forget')).toBe(false)
  await ask.press({ key: 'yes:SECRET_c1' })
  await ask.unmount()
  const forgot = calls.map(c => JSON.parse(c.init.stdin || '{}')).find(q => q.action === 'forget')
  expect(forgot.key).toBe('SECRET_c1')
  const after = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await after.find({ type: 'Text', text: /Forgot SECRET_c1/ })).toBeDefined()
  await after.unmount()
})

test('name service: the source as buttons, a gateway pick goes through the entry and offers the login', async ($, on) => {
  const calls: any[] = []
  engine(on, calls, { placed: true })
  on('command.run', () => ({ text: 'engine' }))
  await $.command.run({ command: 'maisecrets' })
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await ui.press({ key: 'names' })
  await ui.unmount()
  const n = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect((await n.find({ key: 'ner:off' }))?.text).toMatch(/● off/)
  await n.press({ key: 'ner:gateway' })
  await n.unmount()
  const g = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await g.press({ key: 'gw:team-gw' })
  await g.unmount()
  const set = calls.map(c => JSON.parse(c.init.stdin || '{}')).find(q => q.action === 'ner_set')
  expect(set.value).toBe('gateway:team-gw')
  const done = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await done.press({ key: 'login' })
  expect(filled).toContain('/maisecrets:sref login team-gw')
  await done.unmount()
})

test('name service: local starts at once, with no question first (0.9.19)', async ($, on) => {
  const calls: any[] = []
  engine(on, calls, { placed: true })
  on('command.run', () => ({ text: 'engine' }))
  await $.command.run({ command: 'maisecrets' })
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await ui.press({ key: 'names' })
  await ui.unmount()
  const n = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await n.press({ key: 'ner:local' })
  await n.unmount()
  const sent = calls.map(c => JSON.parse(c.init.stdin || '{}')).filter(q => q.action === 'ner_set')
  expect(sent.map(q => q.value)).toEqual(['local'])
  const q = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await q.find({ key: 'start' })).toBeUndefined()
  await q.unmount()
})

test('not a secret sends the first step at the press and the second at the yes; forget all sends its sentence',
  async ($, on) => {
    const calls: any[] = []
    engine(on, calls, { placed: true })
    on('command.run', () => ({ text: 'engine' }))
    await $.command.run({ command: 'maisecrets' })
    const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
    await ui.press({ key: 'stored' })
    await ui.unmount()
    const v = await $.ui.mount({ ...PANE, surface: 'terminal' })
    await v.press({ key: 'allow:SECRET_c1' })
    await v.unmount()
    const asked = () => calls.map(c => JSON.parse(c.init.stdin || '{}').action)
    expect(asked()).toContain('allow_ask')
    expect(asked()).not.toContain('allow')
    const yes = await $.ui.mount({ ...PANE, surface: 'terminal' })
    await yes.press({ key: 'yes:SECRET_c1' })
    await yes.unmount()
    expect(asked().indexOf('allow')).toBeGreaterThan(asked().indexOf('allow_ask'))
    await $.command.run({ command: 'maisecrets' })
    const m = await $.ui.mount({ ...PANE, surface: 'terminal' })
    await m.press({ key: 'stored' })
    await m.unmount()
    const all = await $.ui.mount({ ...PANE, surface: 'terminal' })
    await all.press({ key: 'forget-all' })
    await all.unmount()
    expect(asked()).not.toContain('forget_all')
    const sure = await $.ui.mount({ ...PANE, surface: 'terminal' })
    await sure.press({ key: 'yes:all' })
    await sure.unmount()
    const wipe = calls.map(c => JSON.parse(c.init.stdin || '{}')).find(q => q.action === 'forget_all')
    expect(wipe.confirm).toBe('forget every stored value')
  })

// the status of an open panel follows the session: the first line can come before the session's first tool call
const statusAsks = (calls: any[]) => calls.filter(c => JSON.parse(c.init.stdin || '{}').action === 'status').length
const settle = () => new Promise(resolve => setTimeout(resolve, 60))
const lineOf = (n: number) => n === 1 ? '⚠️ maisecrets 0.9.15 is NOT protecting this session (ask 1)'
  : `🔒 maisecrets 0.9.15 protects this session (ask ${n})`

test('a tool call while the panel is open brings a new status line, at most once in a few seconds', async ($, on) => {
  const calls: any[] = []
  const clock = { t: 1_000_000 }
  const waits: number[] = []
  engine(on, calls, { placed: true }, { clock, line: lineOf, waits })
  on('command.run', () => ({ text: 'engine' }))
  on('tool.call', () => ({ result: 'listed' }))
  await $.command.run({ command: 'maisecrets' })
  ;(await mountWhen($, { type: 'Text', text: /\(ask 1\)/ })).unmount()
  clock.t += 5000
  await $.tool.call({ tool: 'Bash', command: 'ls' } as any)
  const ui = await mountWhen($, { type: 'Text', text: /protects this session \(ask 2\)/ })
  expect(await ui.find({ type: 'Text', text: /protects this session \(ask 2\)/ })).toBeDefined()
  await ui.unmount()
  // a second call a moment later waits for the gap: one wait, no ask now
  clock.t += 500
  await $.tool.call({ tool: 'Bash', command: 'ls' } as any)
  await $.tool.call({ tool: 'Bash', command: 'ls' } as any)
  await settle()
  expect(statusAsks(calls)).toBe(2)
  // (the wait of 60 ms is the panel's own: it asks for the keys once the dropped prompt landed)
  expect(waits.filter(ms => ms !== 60)).toEqual([2500])
})

// a gateway sent a reference and this computer has no login there: at the end of the turn the login command goes into
// the input box, only into an empty one, and only when Python names it
const GW_RESULT = { result: { content: [{ type: 'text', text: 'author: ⟦sref:email:abc123:ma•••@example.org⟧' }] } }
const offers = (calls: any[], action = 'login_offer') =>
  calls.filter(c => JSON.parse(c.init.stdin || '{}').action === action)

test('a gateway reference without a login puts the login command into an empty input box at the end of the turn',
  async ($, on) => {
    const calls: any[] = []
    filled.length = 0
    let box = ''
    engine(on, calls, { placed: true }, { offer: '/maisecrets:sref login team-gw' })
    on('prompt.read', () => ({ value: { text: box, cursor: box.length } }))
    on('tool.call', () => GW_RESULT)
    on('turn.complete', ($, e) => ({ text: e.answer }))
    await $.tool.call({ tool: 'mcp__team-gw__jira_read_actions', action: 'get' } as any)
    expect(offers(calls).length).toBe(0)              // nothing while the turn runs
    await $.turn.complete({ answer: 'done', reason: 'answer' } as any)
    await settle()
    expect(offers(calls).length).toBe(1)
    expect(JSON.parse(offers(calls)[0].init.stdin).session_id).toBe('sess-1')
    expect(filled).toEqual(['/maisecrets:sref login team-gw'])
    // the fill is reported, so Python records the offer only now
    expect(JSON.parse(offers(calls, 'login_offered')[0].init.stdin)).toEqual({ action: 'login_offered',
      session_id: 'sess-1', fill: '/maisecrets:sref login team-gw' })
  })

test('a key typed while Python answers keeps the box as it is and the offer for a later turn', async ($, on) => {
  const calls: any[] = []
  filled.length = 0
  const reads = ['', 'x', '']
  engine(on, calls, { placed: true }, { offer: '/maisecrets:sref login team-gw' })
  on('prompt.read', () => { const text = reads.shift() ?? ''; return { value: { text, cursor: text.length } } })
  on('tool.call', () => GW_RESULT)
  on('turn.complete', ($, e) => ({ text: e.answer }))
  await $.tool.call({ tool: 'mcp__team-gw__jira_read_actions', action: 'get' } as any)
  await $.turn.complete({ answer: 'done', reason: 'answer' } as any)
  await settle()
  expect(offers(calls).length).toBe(1)
  expect(filled).toEqual([])                          // the box held a key by the time of the fill
  expect(offers(calls, 'login_offered').length).toBe(0)
  await $.turn.complete({ answer: 'done', reason: 'answer' } as any)
  await settle()
  expect(filled).toEqual(['/maisecrets:sref login team-gw'])
})

test('a box with the person\'s text keeps the login offer for the end of a later turn; a subagent\'s end never fills',
  async ($, on) => {
    const calls: any[] = []
    filled.length = 0
    let box = 'my own words'
    engine(on, calls, { placed: true }, { offer: '/maisecrets:sref login team-gw' })
    on('prompt.read', () => ({ value: { text: box, cursor: box.length } }))
    on('tool.call', () => GW_RESULT)
    on('turn.complete', ($, e) => ({ text: e.answer }))
    await $.tool.call({ tool: 'mcp__team-gw__jira_read_actions', action: 'get' } as any)
    await $.turn.complete({ answer: 'done', reason: 'answer' } as any)
    await settle()
    expect(offers(calls).length).toBe(0)               // the person's text stays, and Python is not even asked
    expect(filled).toEqual([])
    box = ''
    // a subagent ends while the main turn runs: no fill then
    await $.turn.complete({ answer: 'sub done', reason: 'answer', agentId: 'agent-1' } as any)
    await settle()
    expect(offers(calls).length).toBe(0)
    // the main turn ends with an empty box: the offer kept from before fills it, with no new reference
    await $.turn.complete({ answer: 'done', reason: 'answer' } as any)
    await settle()
    expect(filled).toEqual(['/maisecrets:sref login team-gw'])
    expect(offers(calls, 'login_offered').length).toBe(1)
  })

test('no login offer without a gateway reference, from a tool that is no MCP tool, or for an answer that is no login',
  async ($, on) => {
    const calls: any[] = []
    filled.length = 0
    engine(on, calls, { placed: true }, { offer: '/maisecrets:sref login team-gw; rm -rf ~' })
    on('prompt.read', () => ({ value: { text: '', cursor: 0 } }))
    let mcpRef = false
    on('tool.call', ($, e) => e.tool === 'Bash' || mcpRef ? GW_RESULT : { result: 'no reference' })
    on('turn.complete', ($, e) => ({ text: e.answer }))
    await $.tool.call({ tool: 'mcp__team-gw__jira_read_actions', action: 'get' } as any)
    await $.tool.call({ tool: 'Bash', command: 'cat notes.txt' } as any)
    await $.turn.complete({ answer: 'done', reason: 'answer' } as any)
    await settle()
    expect(offers(calls).length).toBe(0)
    mcpRef = true
    await $.tool.call({ tool: 'mcp__team-gw__jira_read_actions', action: 'get' } as any)
    await $.turn.complete({ answer: 'done', reason: 'answer' } as any)
    await settle()
    expect(offers(calls).length).toBe(1)
    expect(filled).toEqual([])                         // an answer that is not the plain login command fills nothing
  })

test('a closed panel asks nothing after a tool call', async ($, on) => {
  const calls: any[] = []
  const clock = { t: 2_000_000 }
  engine(on, calls, { placed: true }, { clock, line: lineOf })
  on('command.run', () => ({ text: 'engine' }))
  on('tool.call', () => ({ result: 'listed' }))
  await $.command.run({ command: 'maisecrets' })
  const ui = await mountWhen($, { type: 'Text', text: /\(ask 1\)/ })
  await ui.press({ key: 'close' })
  await ui.unmount()
  clock.t += 5000
  await $.tool.call({ tool: 'Bash', command: 'ls' } as any)
  await settle()
  expect(statusAsks(calls)).toBe(1)
})

test('the panel asks for the status again when it takes the keys back', async ($, on) => {
  const calls: any[] = []
  const clock = { t: 3_000_000 }
  engine(on, calls, { placed: true }, { clock, line: lineOf })
  on('command.run', () => ({ text: 'engine' }))
  await $.command.run({ command: 'maisecrets' })
  ;(await mountWhen($, { type: 'Text', text: /\(ask 1\)/ })).unmount()
  const away = await $.ui.mount({ ...PANE, props: { ...PANE.props, isFocused: false }, surface: 'terminal' })
  await away.unmount()
  await settle()
  expect(statusAsks(calls)).toBe(1)
  clock.t += 5000
  const ui = await mountWhen($, { type: 'Text', text: /protects this session \(ask 2\)/ })
  expect(await ui.find({ type: 'Text', text: /protects this session \(ask 2\)/ })).toBeDefined()
  await ui.unmount()
})

// `/maisecrets sref login`, typed with a space: when the prompt check gives no answer, the command with its colon goes
// into the box, and nothing is sent (with an answer it runs as the colon form: tests/mod.test.ts)
test('a maisecrets command typed after /maisecrets with a space goes into the box with its colon', async ($, on) => {
  const calls: any[] = []
  engine(on, calls, { placed: true })
  filled.length = 0
  const r = await $.prompt.submit({ text: '/maisecrets sref login', wait: false, origin: { kind: 'composer' },
    command: { name: 'maisecrets', args: 'sref login' } })
  expect(r.drop).toBe('maisecrets: I put /maisecrets:sref login into the input box. Press Enter to run it, or clear '
    + 'the box.')
  await settle()
  expect(filled).toContain('/maisecrets:sref login')
  // the demo's question for an own command (as for the colon form), then the value check of the filled command; no
  // settings entry (the demo's question tries each Python: this engine answers none of them)
  expect(calls.length).toBeGreaterThan(1)
  expect([...new Set(calls.map(c => c.argv[c.argv.length - 1]))]).toEqual(['mod-' + 'demo', 'mod-' + 'prompt'])
  expect(JSON.parse(calls[calls.length - 1].init.stdin)).toMatchObject({ prompt: '/maisecrets:sref login',
    fill_check: true })
})

test('/maisecrets settings with a space opens the panel as the colon form does; /maisecrets alone goes to the menu',
  async ($, on) => {
    const calls: any[] = []
    engine(on, calls, { placed: true })
    for (const text of ['/maisecrets settings', '/maisecrets settings all']) {
      const r = await $.prompt.submit({ text, wait: false, origin: { kind: 'composer' },
        command: { name: 'maisecrets', args: text.slice(12) } })
      expect(r.drop).toBe('maisecrets: the panel is open. Esc closes it.')
    }
    // a prompt that is no person's: no panel from it
    const before = calls.length
    const p = await $.prompt.submit({ text: '/maisecrets settings', wait: false, origin: { kind: 'plugin' },
      command: { name: 'maisecrets', args: 'settings' } })
    expect(p.drop).toBeUndefined()
    expect(calls.length).toBe(before)
    // /maisecrets alone is the menu command: the prompt goes on, and the command opens the panel
    const r = await $.prompt.submit({ text: '/maisecrets', wait: false, origin: { kind: 'composer' },
      command: { name: 'maisecrets', args: '' } })
    expect(r.drop).toBeUndefined()
  })

test('a command that no person typed gets the same answer from the menu command', async ($, on) => {
  engine(on, [], { placed: true })
  filled.length = 0
  on('command.run', () => ({ text: 'engine' }))
  const r = await $.command.run({ command: 'maisecrets', args: 'not-a-secret SECRET_c1' } as any)
  expect(r.text).toBe('maisecrets: I put /maisecrets:not-a-secret SECRET_c1 into the input box. Press Enter to run it, '
    + 'or clear the box.')
  expect(filled).toContain('/maisecrets:not-a-secret SECRET_c1')
})

// a mistyped command name: the closest command goes into the box, and the note says so; the demo adds where it starts
test('a mistyped command after /maisecrets goes into the box as the closest command, with a note', async ($, on) => {
  const calls: any[] = []
  engine(on, calls, { placed: true })
  filled.length = 0
  const r = await $.prompt.submit({ text: '/maisecrets stauts all', wait: false, origin: { kind: 'composer' },
    command: { name: 'maisecrets', args: 'stauts all' } })
  expect(r.drop).toBe('maisecrets: I put /maisecrets:status all into the input box. Press Enter to run it, or clear '
    + 'the box.')
  await settle()
  expect(filled).toContain('/maisecrets:status all')
  expect(calls.length).toBe(1)
  expect(JSON.parse(calls[0].init.stdin)).toMatchObject({ prompt: '/maisecrets:status all', fill_check: true })
  filled.length = 0
  for (const [word, command] of [['lsit', '/maisecrets:list'], ['adit 5', '/maisecrets:audit 5'],
    ['rulse', '/maisecrets:rules']]) {
    const d = await $.command.run({ command: 'maisecrets', args: word } as any)
    expect(d.text).toBe(`maisecrets: I put ${command} into the input box. Press Enter to run it, or clear the box.`)
    expect(filled).toContain(command)
  }
  // a demo on that no person typed: the box gets it, and the line says where the demo starts
  const d = await $.command.run({ command: 'maisecrets', args: 'demo on' } as any)
  expect(d.text).toBe('maisecrets: I put /maisecrets:demo on into the input box. Press Enter to run it, or clear the '
    + 'box. The demo starts only in a new session (or after /clear).')
})

// a mistyped name never becomes a command that deletes, weakens, changes or sends: a reflex Enter must not run it
test('a mistyped name near a command that changes something is no suggestion', async ($, on) => {
  const calls: any[] = []
  engine(on, calls, { placed: true })
  on('command.run', () => ({ text: 'engine' }))
  filled.length = 0
  for (const args of ['forger SECRET_c1', 'team remove Bertolt Q', 'not-a-secre SECRET_c1', 'settigns rehydration automatic',
    'nre off', 'deom on', 'sfer logout', 'pt', 'snd', 'gaurd remove', 'shotcut --remove', 'reprot incident']) {
    const p = await $.prompt.submit({ text: `/maisecrets ${args}`, wait: false, origin: { kind: 'composer' },
      command: { name: 'maisecrets', args } })
    expect(p.drop).toBeUndefined()
    const r = await $.command.run({ command: 'maisecrets', args } as any)
    expect(r.text).toBeUndefined()
  }
  expect(filled.filter(f => f.startsWith('/maisecrets:'))).toEqual([])
  expect(calls.filter(c => c.argv.includes('mod-' + 'prompt'))).toEqual([])
})

test('a word near no command, or near two, is no suggestion: the panel says it is no command', async ($, on) => {
  engine(on, [], { placed: true })
  on('command.run', () => ({ text: 'engine' }))
  filled.length = 0
  for (const word of ['wibble', 'st', 'zzzzzz']) {
    const r = await $.command.run({ command: 'maisecrets', args: word } as any)
    expect(r.text).toBeUndefined()
  }
  expect(filled.filter(f => f.startsWith('/maisecrets:'))).toEqual([])
})

test('/maisecrets with a word that is no command opens the panel with a line that says so', async ($, on) => {
  engine(on, [], { placed: true })
  on('command.run', () => ({ text: 'engine' }))
  filled.length = 0
  const r = await $.command.run({ command: 'maisecrets', args: 'wibble' } as any)
  expect(r.text).toBeUndefined()
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ type: 'Text', text: /^"wibble" is no maisecrets command\. Try: status, settings, ner, sref login/ }))
    .toBeDefined()
  await ui.unmount()
  expect(filled).not.toContain('/maisecrets:wibble')
  // the plain menu has no such line
  await $.command.run({ command: 'maisecrets', args: '' } as any)
  const again = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await again.find({ type: 'Text', text: /is no maisecrets command/ })).toBeUndefined()
  await again.unmount()
})

test('an older status answer that comes late does not replace a newer one', async ($, on) => {
  const calls: any[] = []
  const clock = { t: 4_000_000 }
  // the first ask answers after the second
  engine(on, calls, { placed: true }, { clock, line: lineOf, delay: n => (n === 1 ? 300 : 10) })
  on('command.run', () => ({ text: 'engine' }))
  on('tool.call', () => ({ result: 'listed' }))
  await $.command.run({ command: 'maisecrets' })
  clock.t += 5000
  await $.tool.call({ tool: 'Bash', command: 'ls' } as any)
  await new Promise(resolve => setTimeout(resolve, 450))
  expect(statusAsks(calls)).toBe(2)
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ type: 'Text', text: /\(ask 2\)/ })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: /\(ask 1\)/ })).toBeUndefined()
  await ui.unmount()
})

test('the status question carries the start of the last tool call of the session that the mod saw', async ($, on) => {
  const calls: any[] = []
  const clock = { t: 5_000_000 }
  engine(on, calls, { placed: true }, { clock, line: lineOf })
  on('command.run', () => ({ text: 'engine' }))
  on('tool.call', () => ({ result: 'listed' }))
  await $.command.run({ command: 'maisecrets' })
  ;(await mountWhen($, { type: 'Text', text: /\(ask 1\)/ })).unmount()
  const asks = () => calls.map(c => JSON.parse(c.init.stdin || '{}')).filter(q => q.action === 'status')
  clock.t += 5000
  const start = clock.t
  await $.tool.call({ tool: 'Bash', command: 'ls' } as any)
  ;(await mountWhen($, { type: 'Text', text: /\(ask 2\)/ })).unmount()
  expect(asks()[1]).toMatchObject({ session_id: 'sess-1', tool_call_at: start / 1000 })
})

test('of two tool calls at once, the newer start stays when the older call ends last', async ($, on) => {
  const calls: any[] = []
  const clock = { t: 6_000_000 }
  engine(on, calls, { placed: true }, { clock, line: lineOf })
  on('command.run', () => ({ text: 'engine' }))
  on('tool.call', async ($, e) => {
    if (e.command === 'slow') await new Promise(resolve => setTimeout(resolve, 150))
    return { result: 'listed' }
  })
  await $.command.run({ command: 'maisecrets' })
  ;(await mountWhen($, { type: 'Text', text: /\(ask 1\)/ })).unmount()
  const asks = () => calls.map(c => JSON.parse(c.init.stdin || '{}')).filter(q => q.action === 'status')
  clock.t += 5000
  const older = $.tool.call({ tool: 'Bash', command: 'slow' } as any)
  await new Promise(resolve => setTimeout(resolve, 20))
  clock.t += 5000
  const newer = clock.t
  await $.tool.call({ tool: 'Bash', command: 'fast' } as any)
  await older
  await new Promise(resolve => setTimeout(resolve, 150))
  const last = asks()[asks().length - 1]
  expect(asks().length).toBeGreaterThan(2)
  expect(last.tool_call_at).toBe(newer / 1000)
})

// the UX test of 2026-11-17: Enter right after /maisecrets changed a setting, and a double Enter on forget deleted
async function focused(ui) {
  const all = await ui.findAll({ type: 'Button' })
  return all.filter(b => b.props?.autoFocus === true).map(b => b.key ?? b.props?.key)
}

test('the panel opens with the focus on Close, and a forget asks with the focus on no', async ($, on) => {
  const calls: any[] = []
  engine(on, calls, { placed: true })
  on('command.run', () => ({ text: 'engine' }))
  await $.command.run({ command: 'maisecrets' })
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await focused(ui)).toEqual(['close'])
  await ui.press({ key: 'stored' })
  await ui.unmount()
  const v = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await focused(v)).toEqual(['back'])
  await v.press({ key: 'forget:SECRET_c1' })
  await v.unmount()
  const ask = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await focused(ask)).toEqual(['no:SECRET_c1'])
  await ask.press({ key: 'no:SECRET_c1' })
  await ask.press({ key: 'forget-all' })
  await ask.unmount()
  const all = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await focused(all)).toEqual(['no:all'])
  await all.unmount()
  expect(calls.some(c => ['forget', 'forget_all'].includes(JSON.parse(c.init.stdin || '{}').action))).toBe(false)
})

test('the gateway question of the name service opens on Back, and a cancel sends nothing', async ($, on) => {
  const calls: any[] = []
  engine(on, calls, { placed: true })
  on('command.run', () => ({ text: 'engine' }))
  await $.command.run({ command: 'maisecrets' })
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await ui.press({ key: 'names' })
  await ui.unmount()
  for (const sub of ['ner:gateway']) {
    const n = await $.ui.mount({ ...PANE, surface: 'terminal' })
    expect(await focused(n)).toEqual(['back'])
    await n.press({ key: sub })
    await n.unmount()
    const q = await $.ui.mount({ ...PANE, surface: 'terminal' })
    expect(await focused(q)).toEqual(['back'])
    await q.press({ key: 'cancel' })
    await q.unmount()
  }
  expect(calls.some(c => JSON.parse(c.init.stdin || '{}').action === 'ner_set')).toBe(false)
})
