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
function engine(on, calls: any[], opened: { placed: boolean }) {
  on('clock.now', () => ({ value: 1_000_000 }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.cwd', () => ({ value: '/work' }))
  on('ui.log', () => ({ value: undefined }))
  on('ui.invalidate', () => ({ value: undefined }))
  on('ui.open', () => ({ value: opened.placed ? { isPlaced: true } : { isPlaced: false, reason: 'no surface' } }))
  on('ui.close', () => ({ value: undefined }))
  on('clock.after', () => ({ value: undefined }))
  on('prompt.fill', ($, e) => { filled.push(e.text); return { isFilled: true } })
  on('process.run', async ($, e) => {
    calls.push(e)
    if (e.argv[2] !== ENTRY) return { value: { exitCode: 1, stderr: '', stdout: '' } }
    const q = JSON.parse(e.init.stdin)
    const set = q.action === 'set'
    // the status comes late, as on a busy CI runner: the panel draws first and the line follows
    if (q.action === 'status') await new Promise(resolve => setTimeout(resolve, 30))
    if (q.action === 'status') return { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({
      maisecrets: ENTRY, line: '🔒 maisecrets 0.9.12 protects this session', ms: 8,
      notes: [{ name: 'store', fact: 'test file, 0 values', next: 'set backend in config.json' }] }) } }
    const answer = (o) => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: ENTRY, ...o }) } })
    const VALUES = { rows: [{ key: 'SECRET_c1', type: 'SECRET', shown: '-', age: '2h', uses: 1, expires: '22h',
      live: true }], total: 1, offset: 0 }
    if (q.action === 'values') return answer(VALUES)
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

test('name service: local asks first and runs nothing before start', async ($, on) => {
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
  const q = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await q.find({ type: 'Text', text: /690 MB/ })).toBeDefined()
  expect(calls.some(c => JSON.parse(c.init.stdin || '{}').action === 'ner_set')).toBe(false)
  await q.press({ key: 'cancel' })
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
