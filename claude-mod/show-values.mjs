// maisecrets as a Claude Code mod: the values behind placeholders on the person's screen (setting show_values).
// The mod draws a reply or a command output again with each value of this computer's store in place of its
// placeholder, with a lock after it. The model, the transcript and /export keep the placeholders: a drawing is no part
// of them (measured on Claude Code 2.1.319, harness scenario show_values_stay_on_screen).
//
// always: each value stands in the text; a click copies it. click: a click on a placeholder shows the values of that
// text for 10 seconds; typing in the prompt hides them. off: nothing is drawn.
//
// Drawn only in the fullscreen terminal and the desktop app. The terminal's main screen keeps a drawing in its
// scrollback, and /export takes it from there (measured): there, in VS Code and on the phone the placeholders stay.
// A value lives only in this module's memory (at most CACHE_MAX, gone with the session): never in $.state, $.store,
// a log or a file. dispatch.py mod-values gives it, for this session's keys only (maisecrets/show_values.py).

const PH = /`[^`\n]*`|⟦([A-Z][A-Z0-9_]{0,40}_c\d{1,9})(?::[^⟧\n]{0,80})?⟧/g
const KEY_RE = /⟦([A-Z][A-Z0-9_]{0,40}_c\d{1,9})(?::[^⟧\n]{0,80})?⟧/g
const LINK = 'https://mcpgate.de/maisecrets/v#'
const CACHE_MAX = 500
const ASK_MS = 4000
const CLICK_MS = 10000
const SHOWN_CHARS = 80
const HINT_SESSIONS = 3

let mode = 'off'          // until the first answer: nothing is drawn
let links = true
let session = null
const cache = new Map()   // key -> value, the oldest first
const absent = new Set()  // keys the store did not give (another session's, expired): not asked again
const wanted = new Set()
let asking = false
const open = new Map()    // click: the text's address -> keys shown until CLICK_MS
let hinted = false

async function runValues($, stdin) {
  // the same Pythons as the prompt path, fixed command lines (claude-mod/maisecrets-mod.mjs)
  const init = { cwd: $.plugin.root, stdin, timeoutMs: ASK_MS, env: { PYTHONUTF8: '1' } }
  for (const argv of [['python3', 'hooks/dispatch.py', 'mod-values'], ['py', '-3', 'hooks/dispatch.py', 'mod-values'],
    ['python', 'hooks/dispatch.py', 'mod-values']]) {
    try {
      const r = await $.process.run(argv, init)
      if (r.exitCode === 0) return r
    } catch {
      // this Python cannot start or timed out: the next one
    }
  }
  return null
}

async function ask($, keys) {
  // the id of each question: /clear and a resume start another session without session.start
  const id = await $.session.id()
  if (id !== session) { session = id; cache.clear(); absent.clear(); open.clear() }
  const r = await runValues($, JSON.stringify({ keys, session_id: session }))
  if (!r) return false
  let a
  try { a = JSON.parse(r.stdout) } catch { return false }
  if (!a || a.maisecrets !== 'mod-values') return false
  const was = mode
  mode = ['always', 'click', 'off'].includes(a.mode) ? a.mode : 'off'
  links = a.links !== false
  if (mode === 'off') { cache.clear(); absent.clear(); open.clear() }
  const values = a.values && typeof a.values === 'object' ? a.values : {}
  for (const k of keys) {
    if (typeof values[k] === 'string') {
      cache.delete(k)
      cache.set(k, values[k])
      if (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value)
    } else absent.add(k)
  }
  return was !== mode || Object.keys(values).length > 0
}

// one question for every key the drawings of this moment miss, outside the drawing (a ui.render hook may not act)
function fetchLater($) {
  if (asking || !wanted.size) return
  asking = true
  $.clock.after(0, async () => {
    const keys = [...wanted].slice(0, 200)
    for (const k of keys) wanted.delete(k)
    let changed = false
    try { changed = await ask($, keys) } catch { /* the placeholders stay */ }
    asking = false
    if (changed) $.ui.invalidate('ui.render')
    if (wanted.size) fetchLater($)
  })
}

const keysIn = (t) => [...new Set([...t.matchAll(KEY_RE)].map(m => m[1]))]
// a value as inline code: a run of backticks one longer than any inside, line breaks as spaces, a long value cut
function code(v) {
  let s = v.replace(/[\r\n\t]+/g, ' ')
  if (s.length > SHOWN_CHARS) s = s.slice(0, SHOWN_CHARS - 1) + '…'
  const ticks = '`'.repeat(Math.max(0, ...[...s.matchAll(/`+/g)].map(m => m[0].length)) + 1)
  const pad = s.startsWith('`') || s.endsWith('`') ? ' ' : ''
  return `${ticks}${pad}${s} 🔒${pad}${ticks}`
}

// a line with a link, a URL or HTML keeps its placeholders: a value there could become part of a link target
// that the model wrote (`[x](https://host/?q=` + placeholder), and a click would send it away (Opus review)
const LINKY = /:\/\/|\]\(|\]\[|^\s*\[[^\]]*\]:|<[a-z!/]|www\./i

function rewrite(text, address) {
  const shown = open.get(address)?.keys
  return text.split('\n').map(line => LINKY.test(line) ? line : rewriteLine(line, shown)).join('\n')
}

function rewriteLine(text, shown) {
  return text.replace(PH, (all, k) => {
    if (!k) return all
    const v = cache.get(k)
    if (mode === 'always' && v !== undefined) return links ? `[${code(v)}](${LINK}${k})` : code(v)
    if (mode === 'click') {
      const link = `[${all}](${LINK}${k})`
      return shown && shown.has(k) && v !== undefined ? `${link} ${code(v)}` : link
    }
    return all
  })
}

// the fullscreen terminal and the desktop app; a surface that does not say so draws as before
const drawsHere = (e) => (e.surface === 'terminal' && e.viewport?.isFullscreen === true) || e.surface === 'desktop'

function hint($) {
  if (hinted) return
  hinted = true
  $.clock.after(0, async () => {
    try {
      const n = Number(await $.store.get('show-values-hints')) || 0
      if (n >= HINT_SESSIONS) return
      await $.store.set('show-values-hints', n + 1)
      $.ui.toast('Values with 🔒 are on your screen only; Claude sees placeholders. A click copies one. ' +
        'Change it: /maisecrets:settings show_values')
    } catch { /* a hint only */ }
  })
}

function draw($, e, text, address, wrap) {
  const keys = keysIn(text)
  // a message drawn outside the viewport (onScreen null) asks for nothing: it asks when a scroll brings it in
  if (e.props?.onScreen !== null) {
    for (const k of keys) if (!cache.has(k) && !absent.has(k)) wanted.add(k)
    fetchLater($)
  }
  if (mode === 'off' || !keys.some(k => cache.has(k))) return null
  if (mode === 'always') hint($)
  const { Markdown, Box, Text } = $.ui.resolve(e)
  const press = async (link, p) => {
    const k = link.href.slice(LINK.length)
    if (!cache.has(k)) return
    if (mode === 'always') {
      try {
        const r = await $.ui.copy({ text: cache.get(k), surface: p?.surface ?? e.surface })
        $.ui.toast(r?.isCopied ? 'Copied. Claude knows only the placeholder.' : 'Not copied.')
      } catch { /* nothing copied */ }
      return
    }
    // a second click starts the 10 seconds again: only the timer of the last click closes the view
    const view = { keys: new Set(keys) }
    open.set(address, view)
    $.ui.invalidate('ui.render')
    $.clock.after(CLICK_MS, () => {
      if (open.get(address) === view) { open.delete(address); $.ui.invalidate('ui.render') }
    })
  }
  const pressable = links || mode === 'click'
  const md = pressable
    ? h(Markdown, { key: `ms-${address}`, text: rewrite(text, address),
      pressableLinks: keys.map(k => LINK + k), onLinkPress: press })
    : h(Markdown, { key: `ms-${address}`, text: rewrite(text, address) })
  return wrap(md, Box, Text)
}

// a prompt that names show_values may change the mode (the settings hook writes it): ask again after it
// (called from the prompt.submit hook of maisecrets-mod.mjs: one hook per event and module)
export function afterPrompt($, text) {
  absent.clear()      // a key the person typed into a prompt is this session's now
  if (typeof text !== 'string' || !text.includes('show_values')) return
  $.clock.after(1500, async () => {
    try { if (await ask($, [])) $.ui.invalidate('ui.render') } catch { /* the mode stays */ }
  })
}

const mdEscape = (s) => s.replace(/([\\`*_|[\]<>#])/g, '\\$1')
// a line of plain text as markdown: escaped, its placeholders kept as they are
const lineAsMarkdown = (l) => l.split(/(⟦[^⟧\n]{1,140}⟧)/).map((part, i) => i % 2 ? part : mdEscape(part)).join('')

export function registerShowValues(on) {
  on('session.start', async ($, e, next) => {
    try {
      if (await ask($, [])) $.ui.invalidate('ui.render')
    } catch { /* off until an answer */ }
    return next(e)
  })

  // a typed /maisecrets:settings show_values … changes the mode; typing hides what click opened
  on('prompt.change', async ($, e, next) => {
    if (open.size) { open.clear(); $.ui.invalidate('ui.render') }
    return next(e)
  })

  on('ui.render', { component: 'AssistantMessage' }, async ($, e, next) => {
    const text = e.props?.text
    if (typeof text !== 'string' || !text.includes('⟦') || !drawsHere(e)) return next(e)
    const tree = draw($, e, text, `a-${e.requestId}`, (md, Box, Text) => h(Box, { flexDirection: 'row' },
      h(Text, null, e.props.isFirstOfReply ? '● ' : '  '),
      h(Box, { flexDirection: 'column', flexGrow: 1, flexShrink: 1 }, md)))
    return tree ?? next(e)
  })

  on('ui.render', { component: 'ToolResult' }, async ($, e, next) => {
    const out = e.props?.output
    const text = typeof out?.stdout === 'string' ? out.stdout : ''
    // an error, an output with stderr and a collapsed row stay the engine's: this drawing has stdout alone
    if (!text.includes('⟦') || !drawsHere(e) || e.props.isErrored || out?.stderr || e.props.isExpanded === false) {
      return next(e)
    }
    // plain text as markdown: escaped, with its line breaks
    const md = text.trimEnd().split('\n').map(lineAsMarkdown).join('  \n')
    const tree = draw($, e, md, `t-${e.requestId}`, (m, Box) => h(Box, { paddingLeft: 4 }, m))
    return tree ?? next(e)
  })
}
