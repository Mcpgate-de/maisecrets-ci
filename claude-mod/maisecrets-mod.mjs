// maisecrets as a Claude Code mod (Claude Code 2.1.287 and later). A prompt with a secret or
// personal data goes through with placeholders in place of the values, instead of being blocked
// and sent again. The detection is the plugin's own (hooks/dispatch.py mod-prompt), not a copy.
//
// The settings hook in hooks/hooks.json stays the gate. It runs after this mod, on the text the
// mod passes on. Whenever the mod gives no rewrite (it does not load, the launcher fails, the
// answer has another shape, the hook times out), the prompt reaches that hook unchanged and the
// hook blocks it as without the mod. So no path here may pass on a value.

// One file: the plugin directory reads $ and on only as a whole argument to a function declared in the same file.

// ---- the values on the person's screen (setting show_values)

// maisecrets as a Claude Code mod: the values behind placeholders on the person's screen (setting show_values).
// The mod draws a reply or a command output again with each value of this computer's store in place of its
// placeholder, with a lock after it. The model, the transcript and /export keep the placeholders: a drawing is no part
// of them (measured on Claude Code 2.1.319, harness scenario show_values_stay_on_screen).
//
// always: each value stands in the text; a click copies it. click: a click on a placeholder shows the values of that
// text for 10 seconds; a sent prompt hides them. off: nothing is drawn.
//
// Drawn only in the fullscreen terminal and the desktop app. The terminal's main screen keeps a drawing in its
// scrollback, and /export takes it from there (measured): there, in VS Code and on the phone the placeholders stay.
// A value lives only in this module's memory (at most CACHE_MAX, gone with the session): never in $.state, $.store,
// a log or a file. dispatch.py mod-values gives it, for this session's keys only (maisecrets/show_values.py).

const PH = /`[^`\n]*`|⟦([A-Z][A-Z0-9_]{0,40}_c\d{1,9})(?::[^⟧\n]{0,80})?⟧|⟦(sref:[A-Za-z0-9_-]{1,32}:[A-Za-z0-9_-]{20,128})(?::[^⟧\n]{1,256})?⟧/g
const SREF_RE = /⟦(sref:[A-Za-z0-9_-]{1,32}:[A-Za-z0-9_-]{20,128})(?::[^⟧\n]{1,256})?⟧/g
const KEY_RE = /⟦([A-Z][A-Z0-9_]{0,40}_c\d{1,9})(?::[^⟧\n]{0,80})?⟧/g
// the link of a value carries a random part of this process, which only the drawing holds: the model cannot write a
// link that the mod answers (a link with the bare prefix and a key in a reply copied that value, Opus review of #30)
const NONCE = (() => {
  const a = new Uint32Array(4)
  if (globalThis.crypto?.getRandomValues) globalThis.crypto.getRandomValues(a)
  else for (let i = 0; i < 4; i++) a[i] = Math.floor(Math.random() * 2 ** 32)
  return [...a].map(n => n.toString(36)).join('')
})()
const LINK = `https://mcpgate.de/maisecrets/v#${NONCE}/`
const CACHE_MAX = 500
const ASK_MS = 4000
const CLICK_MS = 10000
const SHOWN_CHARS = 80
const HINT_SESSIONS = 3
// a gateway's reference: only a click resolves it, once per session, at most REVEAL_MAX per session (#30); a click
// on the value it shows then copies it, as for a value of the store
const REVEAL_MAX = 20
const REVEAL_MS = 8000

let mode = 'off'          // until the first answer: nothing is drawn
let links = true
let session = null
const cache = new Map()   // key -> value, the oldest first
const absent = new Set()  // keys the store did not give (another session's, expired): not asked again
const wanted = new Set()
let asking = false
const open = new Map()    // click: the text's address -> keys shown until CLICK_MS
let hinted = false
let docker = false       // docker or podman is there: the NER tip can start it
let names = true        // NER is on (mod-values answer); off adds the NER tip to the first hint
const revealed = new Map()  // a gateway reference -> its value, for this session
// a gateway reference -> the display the gateway gave with it ('' when none): the label of its link, never the text the
// AI wrote after the id (DS21 of the specification: the AI could label one reference with another person's display)
const labels = new Map()
let revealing = false
let reveals = 0

// The commands of the mod, each written out at its call (the plugin directory reads a process call whose argument list
// is a variable as a program it cannot check, #106): `which` picks the Python (0 python3, 1 py -3, 2 python), `entry`
// the dispatch.py entry. An entry outside this list starts nothing
const PY_NAMES = ['python3', 'py', 'python']
function runEntry($, entry, which, init) {
  switch (entry) {
    case 'mod-values':
      if (which === 0) return $.process.run(['python3', 'hooks/dispatch.py', 'mod-values'], init)
      if (which === 1) return $.process.run(['py', '-3', 'hooks/dispatch.py', 'mod-values'], init)
      return $.process.run(['python', 'hooks/dispatch.py', 'mod-values'], init)
    case 'mod-reveal':
      if (which === 0) return $.process.run(['python3', 'hooks/dispatch.py', 'mod-reveal'], init)
      if (which === 1) return $.process.run(['py', '-3', 'hooks/dispatch.py', 'mod-reveal'], init)
      return $.process.run(['python', 'hooks/dispatch.py', 'mod-reveal'], init)
    case 'mod-demo':
      if (which === 0) return $.process.run(['python3', 'hooks/dispatch.py', 'mod-demo'], init)
      if (which === 1) return $.process.run(['py', '-3', 'hooks/dispatch.py', 'mod-demo'], init)
      return $.process.run(['python', 'hooks/dispatch.py', 'mod-demo'], init)
    case 'mod-settings':
      if (which === 0) return $.process.run(['python3', 'hooks/dispatch.py', 'mod-settings'], init)
      if (which === 1) return $.process.run(['py', '-3', 'hooks/dispatch.py', 'mod-settings'], init)
      return $.process.run(['python', 'hooks/dispatch.py', 'mod-settings'], init)
    case 'mod-result':
      if (which === 0) return $.process.run(['python3', 'hooks/dispatch.py', 'mod-result'], init)
      if (which === 1) return $.process.run(['py', '-3', 'hooks/dispatch.py', 'mod-result'], init)
      return $.process.run(['python', 'hooks/dispatch.py', 'mod-result'], init)
    default:
      return Promise.reject(new Error(`maisecrets: no command for ${entry}`))
  }
}

async function runValues($, stdin) {
  // the same Pythons as the prompt path, fixed command lines (runDispatch below)
  const init = { cwd: $.plugin.root, stdin, timeoutMs: ASK_MS, env: { PYTHONUTF8: '1' } }
  for (const which of [0, 1, 2]) {  // python3, py -3, python (mod-values)
    try {
      const r = await runEntry($, 'mod-values', which, init)
      if (r.exitCode === 0) return r
    } catch {
      // this Python cannot start or timed out: the next one
    }
  }
  return null
}

async function askValues($, asked) {
  let keys = asked
  // the id of each question: /clear and a resume start another session without session.start
  const id = await $.session.id()
  if (id !== session) {
    session = id; cache.clear(); absent.clear(); open.clear(); revealed.clear(); labels.clear(); reveals = 0
  }
  const refs = keys.filter(k => k.startsWith('sref:'))
  keys = keys.filter(k => !k.startsWith('sref:'))
  const r = await runValues($, JSON.stringify({ keys, refs, session_id: session }))
  if (!r) return false
  let a
  try { a = JSON.parse(r.stdout) } catch { return false }
  if (!a || a.maisecrets !== 'mod-values') return false
  const was = mode
  mode = ['always', 'click', 'off'].includes(a.mode) ? a.mode : 'off'
  links = a.links !== false
  names = a.names !== false
  docker = a.docker === true
  if (mode === 'off') { cache.clear(); absent.clear(); open.clear(); revealed.clear() }
  const values = a.values && typeof a.values === 'object' ? a.values : {}
  const shown = a.displays && typeof a.displays === 'object' ? a.displays : {}
  for (const ref of refs) labels.set(ref, typeof shown[ref] === 'string' ? shown[ref] : '')
  for (const k of keys) {
    if (typeof values[k] === 'string') {
      cache.delete(k)
      cache.set(k, values[k])
      if (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value)
    } else absent.add(k)
  }
  return was !== mode || Object.keys(values).length > 0 || refs.length > 0
}

// the status knows that the mod runs in a session from a row the launcher writes for an ask with no keys
// (status_verdict.note_mod). session.start asks once; /clear and a resume give a new session id without it, and a
// slash line or a prompt that is no person's asks nothing else, so each prompt asks once per new session id. It asks
// after NOTE_MS, outside the prompt's own check and its budget
const noted = new Set()
const NOTE_MS = 1000
function noteSession($) {
  void (async () => {
    const id = await $.session.id()
    if (typeof id !== 'string' || noted.has(id)) return
    noted.add(id)
    $.clock.after(NOTE_MS, async () => {
      try { if (await askValues($, [])) $.ui.invalidate('ui.render') } catch { /* the status may say the mod is off */ }
    })
  })().catch(() => {})
}

// one question for every key the drawings of this moment miss, outside the drawing (a ui.render hook may not act)
function fetchLater($) {
  if (asking || !wanted.size) return
  asking = true
  $.clock.after(0, async () => {
    const keys = [...wanted].slice(0, 200)
    for (const k of keys) wanted.delete(k)
    let changed = false
    try { changed = await askValues($, keys) } catch { /* the placeholders stay */ }
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
const LINKY = /:\/\/|\]\(|\]\[|^\s*\[[^\]]*\]:|<[a-z!/]|www\.|\b(?:mailto|data|file|tel|sms|javascript|ftp):|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\/|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\?/i

function rewrite(text, address) {
  const shown = open.get(address)?.keys
  return text.split('\n').map(line => LINKY.test(line) ? line : rewriteLine(line, shown)).join('\n')
}

const isSecretRef = (ref) => ref.startsWith('sref:secret:')
const label = (ref) => labels.get(ref) ? `\u27e6${ref}:${labels.get(ref)}\u27e7` : `\u27e6${ref}\u27e7`
// a secret of this computer's store is never drawn either, as a gateway's (consistent): its click copies it
const isSecretKey = (k) => k.startsWith('SECRET_')
const SECRET_TOAST = 'Copied. The secret stays hidden on the screen.'

function rewriteLine(text, shown) {
  return text.replace(PH, (all, k, ref) => {
    if (ref) {
      // a gateway's reference: a link that a click resolves; then the value in its place, a click copies it. A secret
      // is never drawn (a screenshot, a shared screen; the desktop app put its own masking control on a token, whose
      // click opened the link in the browser): its click copies it at once
      if (isSecretRef(ref)) return `[${label(ref)}](${LINK}${ref})`
      return revealed.has(ref) ? `[${code(revealed.get(ref))}](${LINK}copy/${ref})` : `[${label(ref)}](${LINK}${ref})`
    }
    if (!k) return all
    const v = cache.get(k)
    if (isSecretKey(k)) return links && v !== undefined && mode !== 'off' ? `[${all} \u{1F512}](${LINK}${k})` : all
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
      // the lock says what Claude never saw; plain text next to it Claude knows (UX research 2026-11-09)
      $.ui.toast('🔒 Claude got only a placeholder for this value. Text without 🔒 Claude knows. ' +
        (names ? 'A click copies the value.' : docker ? '💡 To find names too: /maisecrets ner local (a local model).'
          : '💡 A name it missed? /maisecrets term add NAME'), { timeoutMs: 15000 })
    } catch { /* a hint only */ }
  })
}

// one click, one reference: the gateway resolves it for the screen (sink display) through dispatch.py mod-reveal,
// which checks that this session got the reference from a user-scope gateway; never from a drawing (Opus review)
async function reveal($, ref) {
  if (revealed.has(ref) || revealing) return
  if (reveals >= REVEAL_MAX) {
    $.ui.toast(`maisecrets shows at most ${REVEAL_MAX} gateway values per session.`)
    return
  }
  revealing = true
  reveals += 1
  try {
    const id = await $.session.id()
    if (id !== session) { session = id; cache.clear(); absent.clear(); open.clear(); revealed.clear(); reveals = 0 }
    const init = { cwd: $.plugin.root, stdin: JSON.stringify({ ref, session_id: id }), timeoutMs: REVEAL_MS,
      env: { PYTHONUTF8: '1' } }
    let r = null
    for (const which of [0, 1, 2]) {  // python3, py -3, python (mod-reveal)
      try {
        r = await runEntry($, 'mod-reveal', which, init)
        if (r.exitCode === 0) break
      } catch { r = null }
    }
    let a = null
    try { a = r && r.exitCode === 0 ? JSON.parse(r.stdout) : null } catch { a = null }
    if (a?.maisecrets === 'mod-reveal' && typeof a.value === 'string') {
      revealed.set(ref, a.value)
      $.ui.invalidate('ui.render')
    } else {
      $.ui.toast(typeof a?.reason === 'string' ? a.reason.slice(0, 300) : 'maisecrets could not get the value.')
    }
  } finally {
    revealing = false
  }
}

// any other tool's call row and result (an MCP tool, Write, Edit …): the client draws them itself, with the values
// put into its input and output for the drawing (always only; a line with a link, a URL or HTML keeps its
// placeholders). Bash keeps its own drawing above, where a click copies
const DEEP_MAX = 8
function collect(v, out, depth = 0) {
  if (depth > DEEP_MAX) return
  if (typeof v === 'string') { if (v.includes('\u27e6')) for (const k of keysIn(v)) out.add(k); return }
  if (Array.isArray(v)) { for (const x of v) collect(x, out, depth + 1); return }
  if (v && typeof v === 'object') for (const x of Object.values(v)) collect(x, out, depth + 1)
}
function shown(v, depth = 0) {
  if (depth > DEEP_MAX) return v
  if (typeof v === 'string') {
    if (!v.includes('\u27e6')) return v
    return v.split('\n').map(line => LINKY.test(line) ? line : line.replace(KEY_RE, (all, k) =>
      cache.has(k) && !isSecretKey(k) ? `${cache.get(k)} \u{1F512}` : all)).join('\n')
  }
  if (Array.isArray(v)) return v.map(x => shown(x, depth + 1))
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, shown(x, depth + 1)]))
  return v
}
function rewriteProps($, e, fields) {
  const keys = new Set()
  for (const f of fields) collect(e.props?.[f], keys)
  if (!keys.size) return null
  if (e.props?.onScreen !== null) {
    for (const k of keys) if (!cache.has(k) && !absent.has(k)) wanted.add(k)
    fetchLater($)
  }
  if (mode !== 'always' || ![...keys].some(k => cache.has(k))) return null
  const props = { ...e.props }
  for (const f of fields) if (f in props) props[f] = shown(props[f])
  return { ...e, props }
}

// the origins of a person's own prompt (maisecrets-mod.mjs PERSON)
const OWN_PROMPT = new Set(['composer', 'bridge', 'sdk'])

const srefsIn = (t) => [...new Set([...t.matchAll(SREF_RE)].map(m => m[1]))]

function draw($, e, text, address, wrap) {
  const keys = keysIn(text)
  const refs = srefsIn(text)
  // a message drawn outside the viewport (onScreen null) asks for nothing: it asks when a scroll brings it in
  if (e.props?.onScreen !== null) {
    for (const k of keys) if (!cache.has(k) && !absent.has(k)) wanted.add(k)
    for (const r of refs) if (!labels.has(r)) wanted.add(r)
    fetchLater($)
  }
  if (mode === 'off' || (!keys.some(k => cache.has(k)) && !refs.length)) return null
  if (mode !== 'off') hint($)
  const { Markdown, Box, Text } = $.ui.resolve(e)
  const press = async (link, p) => {
    if (typeof link?.href !== 'string' || !link.href.startsWith(LINK)) return
    const k = link.href.slice(LINK.length)
    if (k.startsWith('sref:')) {
      if (!refs.includes(k)) return
      await reveal($, k)
      if (isSecretRef(k) && revealed.has(k)) {
        try {
          const r = await $.ui.copy({ text: revealed.get(k), surface: p?.surface ?? e.surface })
          $.ui.toast(r?.isCopied ? SECRET_TOAST : 'Not copied.')
        } catch { /* nothing copied */ }
      }
      return
    }
    if (k.startsWith('copy/sref:')) {
      const ref = k.slice(5)
      if (!refs.includes(ref) || !revealed.has(ref)) return
      try {
        const r = await $.ui.copy({ text: revealed.get(ref), surface: p?.surface ?? e.surface })
        $.ui.toast(r?.isCopied ? 'Copied.' : 'Not copied.')
      } catch { /* nothing copied */ }
      return
    }
    if (!cache.has(k)) return
    if (mode === 'always' || isSecretKey(k)) {
      try {
        const r = await $.ui.copy({ text: cache.get(k), surface: p?.surface ?? e.surface })
        $.ui.toast(r?.isCopied ? (isSecretKey(k) ? SECRET_TOAST : 'Copied. Claude knows only the placeholder.')
          : 'Not copied.')
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
  const pressable = links || mode === 'click' || refs.length > 0
  const md = pressable
    ? h(Markdown, { key: `ms-${address}`, text: rewrite(text, address),
      pressableLinks: [...keys, ...refs, ...refs.map(r => 'copy/' + r)].map(k => LINK + k), onLinkPress: press })
    : h(Markdown, { key: `ms-${address}`, text: rewrite(text, address) })
  return wrap(md, Box, Text)
}

// a prompt that names show_values may change the mode (the settings hook writes it): ask again after it
// (called from the prompt hook below: one hook per event and module)
// A sent prompt also hides what a click opened. Not on each key stroke: the directory refuses a mod that hooks
// prompt.change, an event its list does not hold (2026-11-12)
function afterPrompt($, text) {
  absent.clear()      // a key the person typed into a prompt is this session's now
  if (open.size) { open.clear(); $.ui.invalidate('ui.render') }
  if (typeof text !== 'string' || !text.includes('show_values')) return
  $.clock.after(1500, async () => {
    try { if (await askValues($, [])) $.ui.invalidate('ui.render') } catch { /* the mode stays */ }
  })
}

const mdEscape = (s) => s.replace(/([\\`*_|[\]<>#])/g, '\\$1')
// a line of plain text as markdown: escaped, its placeholders kept as they are
const lineAsMarkdown = (l) => l.split(/(⟦[^⟧\n]{1,140}⟧)/).map((part, i) => i % 2 ? part : mdEscape(part)).join('')

function registerShowValues(on) {
  on('session.start', async ($, e, next) => {
    try { void renewKey($) } catch { /* the first marker asks for the key */ }
    try {
      try { noted.add(await $.session.id()) } catch { /* the first prompt asks */ }
      if (await askValues($, [])) $.ui.invalidate('ui.render')
    } catch { /* off until an answer */ }
    // the settings pane's rows, so the first /maisecrets:settings draws at once
    void askSettings($, { action: 'list' }).catch(() => {})
    try {
      void $.command.register({ name: 'maisecrets', description: 'The maisecrets menu: status, settings, stored values',
        immediate: true }).catch(() => {})
    } catch { /* no command: /maisecrets:settings opens the same pane */ }
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

  // the person's own prompt, as the mod sent it: the values the person typed come back on the screen (a message of
  // another session, a notification or a channel keeps its row: it is not the person's text)
  on('ui.render', { component: 'UserMessage' }, async ($, e, next) => {
    const text = e.props?.text
    // only the row of the normal view (isExpanded false): ctrl+o, --verbose and an export draw it in full, and those
    // stay the engine's
    if (typeof text !== 'string' || !text.includes('\u27e6') || !drawsHere(e) || e.props.isExpanded !== false
        || !OWN_PROMPT.has(e.props.origin?.kind)) {
      return next(e)
    }
    const md = text.split('\n').map(lineAsMarkdown).join('  \n')
    const tree = draw($, e, md, `u-${e.requestId}`, (m, Box, Text) => h(Box, { flexDirection: 'row' },
      h(Text, null, '\u276f '), h(Box, { flexDirection: 'column', flexGrow: 1, flexShrink: 1 }, m)))
    return tree ?? next(e)
  })

  on('ui.render', { component: 'ToolUse' }, async ($, e, next) => {
    if (e.props?.tool === 'Bash' || !drawsHere(e)) return next(e)
    return next(rewriteProps($, e, ['input', 'output']) ?? e)
  })

  on('ui.render', { component: 'ToolResult' }, async ($, e, next) => {
    if (e.props?.tool !== 'Bash') {
      if (!drawsHere(e) || e.props?.isErrored) return next(e)
      return next(rewriteProps($, e, ['output']) ?? e)
    }
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

// ---- the prompt

const MARK = 'mod-prompt'
// a person's own prompt: typed or queued at the terminal, sent through Remote Control, or the turn of
// claude -p. A subagent's report or a channel's message stays with the settings hook (C19)
const PERSON = new Set(['composer', 'bridge', 'sdk'])
// a message of another Claude session (SendMessage) is never rewritten here: the client gives the model the message
// from its own copy, so a rewritten prompt text left the value in what the model read, and the settings hook, which
// then saw only placeholders, did not block it (0.7.4, measured 2026-10-22 between two sessions). It goes on unchanged
// to the settings hook, which blocks it and names the sending session (maisecrets/settings.py, peer_sender)
// ms:(…): a check of a value. It is never rewritten and never sent: the mod drops it with the verdict of
// dispatch.py mod-prompt (maisecrets/check_value.py), or with its own sentence when no verdict comes. A prompt that is
// not a person's goes on to the settings hook, which blocks it as a check
// (blanks around the colon and the full-width colon and bracket count, as in check_value.py, which takes more)
const CHECK = /^\s*ms\s*[:\uff1a]\s*[(\uff08]/i
// a line that starts with a slash. Claude Code throws away a prompt.submit change of a slash command's line and sends
// it as typed, so a rewrite here would let the settings hook pass a value it never sees: the line goes on unchanged,
// and the hook decides it (#44). Every slash, not only a command name a regex could know: names with two colons
// (/plugin:dir:cmd) and non-ASCII names are commands too (Gate A). A prompt that starts with a path gets the hook's
// block, with /ms to send it
const SLASH = /^\s*\//

// The plugin's own hooks/dispatch.py, started by this computer's Python, in the plugin folder: each call is
// fixed text, no shell and no environment read (the directory review asks for one program by name with fixed
// arguments). macOS and Linux have python3, Windows the py launcher or python; on Windows `python3` is often a
// store stub that starts and exits 9009. A call that cannot start or exits with an error hands on to the next
// (dispatch.py exits 3 on Python 3.6 to 3.8, and an older one cannot parse it); a timeout ends the search. All of them share one budget, so a
// prompt waits at most BUDGET_MS. When none answers, the settings hook blocks the prompt (README, "The mod")
const BUDGET_MS = 8000

async function runPython3($, init) {
  return await $.process.run(['python3', 'hooks/dispatch.py', 'mod-prompt'], init)
}

async function runPyLauncher($, init) {
  return await $.process.run(['py', '-3', 'hooks/dispatch.py', 'mod-prompt'], init)
}

async function runPython($, init) {
  return await $.process.run(['python', 'hooks/dispatch.py', 'mod-prompt'], init)
}

// the Python that answered the last prompt check: a command the mod runs (runOwn below) starts with it
let lastPython = 0

async function runDispatch($, stdin) {
  // $.clock.now: the mods API's clock, which a test can set (wall-clock time; a clock that jumps ahead ends the
  // search early, and the settings hook blocks)
  const end = (await $.clock.now()) + BUDGET_MS
  for (let i = 0; i < 3; i++) {
    const left = end - (await $.clock.now())
    if (left <= 0) return null        // the budget is spent: no other Python starts, nor runs the rewrite again
    // UTF-8 for the pipe: Windows Python would read it in the console code page, and a prompt with umlauts failed
    const init = { cwd: $.plugin.root, stdin, timeoutMs: left, env: { PYTHONUTF8: '1' } }
    let r
    try {
      r = i === 0 ? await runPython3($, init) : i === 1 ? await runPyLauncher($, init) : await runPython($, init)
    } catch {
      continue        // this Python cannot start, or it timed out: then the check above ends the search
    }
    if (r.exitCode === 0) { lastPython = i; return r }
  }
  return null
}

async function ask($, prompt, session, cwd, origin) {
  // origin: the hook takes a {{name}} marker only from a prompt the person typed (composer, bridge)
  const r = await runDispatch($, JSON.stringify({ prompt, session_id: session, cwd, origin }))
  if (!r) return null
  return takeAnswer(JSON.parse(r.stdout), session)
}

// #107: an MCP task's result, sent by the client as a notification, is a tool's output: Python masks it when it proves
// itself (hooks.rewrite_prompt), else the settings hook judges it as before (C19)
async function taskResult($, e, next) {
  let a = null
  try { a = await ask($, e.text, await $.session.id(), await $.session.cwd(), e.origin.kind) } catch { /* the hook */ }
  return next(a && typeof a.text === 'string' ? { ...e, text: a.text } : e)
}

// a parsed answer of mod-prompt for this session: what the steps below read, or null
function takeAnswer(answer, session) {
  if (!answer || answer.maisecrets !== MARK) return null
  // what each model step reads below; a damaged state is not kept (demo off in another session resets it)
  if (typeof answer.inDemo === 'boolean') {
    if (answer.damaged === true) demo.delete(session)
    else demo.set(session, answer.inDemo)
  }
  if (typeof answer.text !== 'string' && typeof answer.drop !== 'string') return null
  return answer
}

// ---- the demo (maisecrets/demo.py): the prompt enters with its values masked, and no model request goes out

// Each model step of a session in the demo is answered here with one line: no request is made. Whether a session is
// in the demo comes from Python (mod-prompt says inDemo for each prompt it sees; mod-demo when it saw none since the
// last prompt), kept in this module's memory per session id. /clear gives a new session id, which asks again
const DEMO_LINE = 'Demo mode: nothing was sent to the AI. /clear to switch it off.'
const demo = new Map()     // session id -> in the demo; the demo command clears its entry
// session id -> the answer of the next demo step in Cowork (maisecrets/demo.py cowork_show, cowork_own): what the AI
// would have got, or a command's output, ending with the Cowork demo line. Cowork draws no row under a prompt
const demoShow = new Map()
const namesTold = new Set()   // session ids told once that the demo did not check names
const DEMO_CMD = /^\s*(?:\/maisecrets:demo|maisecrets:\s*demo)\b/i

async function runDemo($, stdin) {
  // one deadline for all three Pythons: a step waits at most ASK_MS, then answers itself (fail closed)
  const end = (await $.clock.now()) + ASK_MS
  for (const which of [0, 1, 2]) {  // python3, py -3, python (mod-demo)
    const left = end - (await $.clock.now())
    if (left <= 0) return null
    try {
      const r = await runEntry($, 'mod-demo', which, { cwd: $.plugin.root, stdin, timeoutMs: left, env: { PYTHONUTF8: '1' } })
      if (r.exitCode === 0) return r
    } catch {
      // this Python cannot start or timed out: the next one, within the deadline
    }
  }
  return null
}

// the person's own maisecrets command typed in a session in the demo: Python runs it without the model and the mod
// drops the prompt with its output (maisecrets/demo.py own_answer). null: no answer, the prompt goes on as before
const OWN_SLASH = /^\s*\/maisecrets:[a-z]/i
const OWN_MS = 20000
async function ownInDemo($, text, origin) {
  const id = await $.session.id()
  if (demo.get(id) === false) return null
  const end = (await $.clock.now()) + OWN_MS
  const stdin = JSON.stringify({ session_id: id, prompt: text, origin })
  for (const which of [0, 1, 2]) {  // python3, py -3, python (mod-demo)
    const left = end - (await $.clock.now())
    if (left <= 0) return null
    let r
    try {
      r = await runEntry($, 'mod-demo', which, { cwd: $.plugin.root, stdin, timeoutMs: left, env: { PYTHONUTF8: '1' } })
    } catch { continue }
    if (r.exitCode !== 0) continue
    let a = null
    try { a = JSON.parse(r.stdout) } catch { return null }
    // not kept in `demo`: the hook of this prompt runs after it and may switch the session (only the steps keep it)
    if (a?.maisecrets !== 'mod-demo' || typeof a.demo !== 'boolean') return null
    return typeof a.drop === 'string' ? a.drop : null
  }
  return null
}

// a drop draws one line (Claude Code 2.1.326 shows a newline as a box): a longer output goes above it, a row per line
const OWN_LINES = 80
function showOwn($, text, last = 'demo mode: run here without the AI, its output is above.') {
  const lines = text.split(/\r?\n/).filter(l => l.trim())
  if (lines.length <= 1) return lines[0] || text
  try {
    for (const l of lines.slice(0, OWN_LINES)) $.ui.log(l)
    if (lines.length > OWN_LINES) $.ui.log(`… ${lines.length - OWN_LINES} more lines`)
  } catch { return lines.join(' · ') }
  return last
}

// ---- the person's own maisecrets commands (prompt_commands.mod_command): the mod answers them, so none reaches the
// model and none reads as "blocked by hook". The prompt hook's answer to a command (term add, not-a-secret, demo, the
// incident report, a settings change) and each Codex form `maisecrets: NAME` are dropped with Python's text, and the
// box is emptied (the engine puts a dropped prompt back into it: once, a name in it merged into the next prompt and
// went to the AI). A Codex form that needs the model puts its slash form into the box. No answer from Python drops the
// prompt all the same (fail closed); the settings hook blocks these without the mod. The self-test value is not here:
// the real prompt hook must stop it, so its pass proves that hook ran
const OWN_CMD = /^\s*(?:maisecrets\s*:\s*[a-z]|\/maisecrets:(?:term\s+\S|not-a-secret\b|demo\b|forget\s+import:|report\s+incident\b))/i
const OWN_FAILED = 'maisecrets could not answer this command. Nothing was sent; send it again.'
const OWN_ABOVE = 'maisecrets: answered without the AI, the output is above.'

// Python's answer to a prompt, or null when none came (a failed start, a timeout, no JSON, another program's answer)
// viaMs: the person typed `/ms NAME`; Python answers nothing when their /ms is a command of their own (hooks.py)
async function askOwn($, text, origin, viaMs = false) {
  const r = await runDispatch($, JSON.stringify({ prompt: text, session_id: await $.session.id(),
    cwd: await $.session.cwd(), origin, ...(viaMs ? { via_ms: true } : {}) }))
  if (!r) return null
  let a = null
  try { a = JSON.parse(r.stdout) } catch { return null }
  return a && a.maisecrets === MARK ? a : null
}

// once the drop landed: the box gets `text` ('' empties it)
function fillSoon($, text) {
  try {
    $.clock.after(60, () => { void $.prompt.fill({ text }).catch(() => {}) })
  } catch { /* the text stays in the box */ }
}

// true or false as Python said for this session id, null when Python gave no answer
async function inDemo($) {
  const id = await $.session.id()
  if (demo.has(id)) return demo.get(id)
  const r = await runDemo($, JSON.stringify({ session_id: id }))
  let a = null
  try { a = r ? JSON.parse(r.stdout) : null } catch { a = null }
  if (a?.maisecrets !== 'mod-demo' || typeof a.demo !== 'boolean') return null
  if (a.damaged !== true) demo.set(id, a.demo)      // a damaged state is asked again: demo off in any session resets it
  return a.demo
}

// the step's answer without a request: one text block, the end of the turn. In Cowork the text Python gave for this
// prompt (demoShow), once; else the demo line
async function * demoAnswer($, e) {
  let text = DEMO_LINE
  try {
    const id = await $.session.id()
    if (typeof demoShow.get(id) === 'string') { text = demoShow.get(id); demoShow.delete(id) }
  } catch { /* the demo line */ }
  yield { kind: 'text', index: 0, text }
  yield { kind: 'stop', stopReason: 'end_turn', usage: null }
  return { turnId: e.turnId, index: e.index, answer: text, toolUses: [], stopReason: 'end_turn', usage: null }
}

const COMPACT_SKIP = 'maisecrets demo: the conversation stays as it is, nothing goes to the AI'

// the client's guess at the next prompt is a model request of its own (a forked agent, source prompt_suggestion,
// measured on Claude Code 2.1.326), with no hook of the mods API before it: in a session in the demo it is switched off
// for this process. Once a prompt of a session out of the demo comes, it is set to '' (only when this module switched
// it): the client's env parser reads '' as not set, so the Claude Code default applies. A value set before the demo is
// not kept (no env read next to a program start, directory review). If that reset fails, suggestions stay off until
// the next session
let quieted = false
async function quietForTheDemo($) {
  if (quieted) return
  try {
    const r = await $.env.set('CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION', 'false')
    quieted = !r?.deny
  } catch { /* the suggestion request stays: see docs/USING.md */ }
}
async function loudAgain($) {
  if (!quieted) return
  try {
    await $.env.set('CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION', '')
    quieted = false
  } catch { /* suggestions stay off until the next session */ }
}

const DEMO_DENY = 'maisecrets demo: nothing goes to the AI. /clear to switch it off.'

function registerDemo(on) {
  // Where an organization manages Claude Code (2.1.327 and later), the http.fetch{origin=engine} and session.compact
  // hooks of a plugin the person installed do not run: /compact and the side requests then go out, with placeholders
  // only. on() gives no sign of it, so the demo start says it as a condition (maisecrets/demo.py ORG_NOTE, ADMIN.md)
  // every request the engine sends raises http.fetch (origin "engine"): the turns, and each side request a client
  // command makes outside a turn (/btw side_question, /rename, /recap away_summary, the title, the next-prompt guess,
  // measured on Claude Code 2.1.326). In a session in the demo none goes out, with a body or without (a URL can carry
  // text too); no answer from Python refuses it too
  on('http.fetch', async ($, e, next) => {
    if (next.origin?.plugin !== 'engine') return next(e)
    if (await inDemo($) === false) return next(e)
    return { deny: DEMO_DENY }
  }).catch(async ($, e, next) => {
    // the request went out and then failed: its failure stands, it is never sent a second time
    if (next.called) throw next.error ?? new Error('maisecrets: the request failed')
    if (next.origin?.plugin !== 'engine') return next(e)
    let id = null
    try { id = await $.session.id() } catch { id = null }
    if (id !== null && demo.get(id) === false) return next(e)
    return { deny: DEMO_DENY }
  })
  // a compaction is a model request of its own (/compact made 2 in a demo session, Claude Code 2.1.326) and no
  // turn.step: in the demo it is skipped, and the conversation stays as it is
  on('session.compact', async ($, e, next) => {
    if (await inDemo($) === false) return next(e)
    return { skip: COMPACT_SKIP }
  }).catch(async ($, e, next) => {
    if (next.called) return next(e)
    let id = null
    try { id = await $.session.id() } catch { id = null }
    if (id !== null && demo.get(id) === false) return next(e)
    return { skip: COMPACT_SKIP }
  })
  // every loop, main's and a subagent's: a step sends its request only for a session Python said is not in the demo.
  // No answer, a malformed one or a timeout answers the step itself (fail closed, Gate A of the demo turn)
  on('turn.step', async function * ($, e, next) {
    if (await inDemo($) === false) return yield * next(e)
    return yield * demoAnswer($, e)
  }).catch(async function * ($, e, next) {
    // the hook failed: a request goes out only for a session this module knows is not in the demo
    if (next.called) return yield * next(e)
    let id = null
    try { id = await $.session.id() } catch { id = null }
    if (id !== null && demo.get(id) === false) return yield * next(e)
    return yield * demoAnswer($, e)
  })
}

// ---- the /maisecrets panel
// /maisecrets (a command of this mod) and /maisecrets:settings typed by the person open a panel: the settings, the
// stored values, the name service. /maisecrets:settings is dropped before its command file renders and /maisecrets
// answers with no text, so the model gets no turn. Each press is the person's act: the mod hands it to
// `hooks/dispatch.py mod-settings` (maisecrets/hub.py), which changes it through the writer of the typed path. A tool
// call that names that entry is refused (shell_commands.py). Codex and claude -p keep the text view: no panel is placed
// there.
const SETTINGS_PANE = 'maisecrets-settings'
const SETTINGS_CMD = /^\s*\/maisecrets:settings(?:\s+(?:all|--all))?\s*$/i
// the names of commands/*.md (tests/test_hub.py compares them): `/maisecrets sref login`, typed with a space, means
// `/maisecrets:sref login`
const COMMANDS = ['audit', 'demo', 'forget', 'guard', 'list', 'ner', 'not-a-secret', 'put', 'report', 'rules', 'send',
  'settings', 'shortcut', 'sref', 'status', 'term']
const SPACED_CMD = /^\s*\/maisecrets\s+([^\s]+)(.*)$/s
// the one entry (commands/maisecrets.md, commands/ms.md, prompt_commands.canonical): `/maisecrets NAME ARGS`, `/ms NAME
// ARGS`, `/maisecrets:maisecrets NAME ARGS` and `/maisecrets:ms NAME ARGS` mean `/maisecrets:NAME ARGS`. The entry
// alone (`/ms`, `/maisecrets:ms`, `/maisecrets:maisecrets`) is `/maisecrets:maisecrets`: the blocked prompt, else the
// overview. `/maisecrets` alone is the mod's own command, the panel
const ENTRY_CMD = /^\s*\/(?:maisecrets(?::(?:maisecrets|ms))?|ms)(?:[ \t]+([^\s]+)([^\r\n]*))?\s*$/i
const ENTRY_ALONE = '/maisecrets:maisecrets'
const MS_TYPED = /^\s*\/ms(?![\w:-])/i
// the command meant by an entry form: its colon form, or null for no command of maisecrets
function meantCommand(text) {
  const m = ENTRY_CMD.exec(typeof text === 'string' ? text : '')
  if (!m) return null
  if (m[1] === undefined) return /^\s*\/maisecrets\s*$/i.test(text) ? null : ENTRY_ALONE
  if (!COMMANDS.includes(m[1].toLowerCase())) return null
  return `/maisecrets:${m[1].toLowerCase()}${m[2].replace(/\s+$/, '')}`
}
// the commands whose command file the client refuses when the person types it (user-invocable: false): the mod's
// command.run hook sees them first and runs them as their colon form. report and sref stay the person's own
const HIDDEN = COMMANDS.filter(n => n !== 'report' && n !== 'sref')
// the number of single-letter changes (insert, delete, replace, swap of two neighbours) from a to b
function editDistance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)])
  for (let j = 1; j <= b.length; j++) d[0][j] = j
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1))
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1)
      }
    }
  }
  return d[a.length][b.length]
}
// the commands a mistyped name may become: they only show. A command that deletes, weakens, changes a setting, starts
// something or sends a prompt (forget, term, not-a-secret, settings, ner, demo, sref, put, send, guard, shortcut,
// report) needs its exact name: `/maisecrets forger SECRET_c1` must not become a forget for a reflex Enter (Gate A)
const NEAR_ONLY = ['status', 'list', 'audit', 'rules']
// `/maisecrets stauts`: the one command name closest to a mistyped word (at most 2 changes, 1 for a short word), as
// `/maisecrets:status REST`; null for a known name, a word near none or near two, and a word nearest to a command
// outside NEAR_ONLY
function nearCommand(text) {
  const m = SPACED_CMD.exec(typeof text === 'string' ? text : '')
  if (!m) return null
  const word = m[1].toLowerCase()
  if (COMMANDS.includes(word) || word.length < 3 || word.length > 20) return null
  const most = word.length < 5 ? 1 : 2
  const near = COMMANDS.map(c => [c, editDistance(word, c)]).filter(([, n]) => n <= most).sort((x, y) => x[1] - y[1])
  if (!near.length || (near.length > 1 && near[1][1] === near[0][1]) || !NEAR_ONLY.includes(near[0][0])) return null
  return `/maisecrets:${near[0][0]}${m[2].replace(/\s+$/, '')}`
}
// what the person reads when a command went into the input box: what happened, and how to go on
const NEW_SESSION = /^\/maisecrets:demo\s+on\b/i
const filledNote = (command) => `maisecrets: I put ${command} into the input box. Press Enter to run it, or clear ` +
  'the box.' + (NEW_SESSION.test(command) ? ' The demo starts only in a new session (or after /clear).' : '')
// a prompt of claude -p or an SDK host (origin sdk) has no input box: the line names the command to send instead
const typeNote = (command) => `maisecrets: send ${command} with the colon to run it. Nothing was sent.`
// a command goes into the box only with its values masked, as the prompt hook masks a prompt that carries one: the
// box never gets a value back (prompt_commands.fill_check, Gate A of !591). null: Python gave no answer
async function checkFill($, text, origin) {
  let r = null
  try {
    r = await runDispatch($, JSON.stringify({ prompt: text, session_id: await $.session.id(),
      cwd: await $.session.cwd(), origin, fill_check: true }))
  } catch { return null }
  if (!r) return null
  let a = null
  try { a = JSON.parse(r.stdout) } catch { return null }
  return a?.maisecrets === MARK && typeof a.masked === 'string' && a.masked.startsWith('/maisecrets:') &&
    !/[\r\n]/.test(a.masked) ? a : null
}
const CHECK_FAILED = 'maisecrets could not check this command. Nothing was sent; type it again with the colon.'
// the engine puts a dropped prompt back into the box: a text that could not be checked may hold a value, so the box is
// emptied once the drop landed (Gate A round 2 of !591)
const FILL_FAILED = 'maisecrets could not check the text, so it removed it from the input box. Type it again.'
const maskedNote = (a) => (Number(a.count) > 0 ? ` maisecrets masked ${Number(a.count)} value(s) in it.` : '')
// the drop of a person's prompt whose command goes into the box (or, without a box, is named): the masked form only
async function offer($, e, command) {
  const a = await checkFill($, command, e.origin?.kind)
  if (!a) {
    if (e.origin?.kind === 'sdk') return { drop: CHECK_FAILED }     // no box (claude -p, an SDK host)
    fillSoon($, '')
    return { drop: FILL_FAILED }
  }
  if (e.origin?.kind === 'sdk') return { drop: typeNote(a.masked) }
  fillSoon($, a.masked)
  return { drop: filledNote(a.masked) + maskedNote(a) }
}
const firstWord = (args) => (typeof args === 'string' ? args.trim().split(/\s+/)[0] : '') || ''
const unknownLine = (word) => `"${word.slice(0, 40)}" is no maisecrets command. Try: status, settings, ner, ` +
  'sref login, list, forget, term, audit, rules, put, send.'
const NARROW = 90       // below this many columns the choices go under the name
const pane = { sub: null, groups: [], note: null, status: null, statusSession: null, notes: [],
  showNotes: false, error: null, view: null, hint: null, statusGen: 0, open: false, statusAt: null, statusDue: false, focused: null }
// while the panel is open its status follows the session: after a tool call, at the end of a turn, when the panel
// takes the keys again; at most once in STATUS_GAP_MS (each ask starts a Python process)
const STATUS_GAP_MS = 3000
// the start (epoch seconds) of the last tool call this mod saw go through, per session id: its PreToolUse hook writes
// a row in hooks.log within the call, so no row at or after it is a hook that did not run (maisecrets/hub.py)
const lastToolCall = new Map()

async function runSettings($, stdin, ms = ASK_MS) {
  const init = { cwd: $.plugin.root, stdin, timeoutMs: ms, env: { PYTHONUTF8: '1' } }
  for (const which of [0, 1, 2]) {  // python3, py -3, python (mod-settings)
    try {
      const r = await runEntry($, 'mod-settings', which, init)
      if (r.exitCode === 0) return r
    } catch {
      // this Python cannot start or timed out: the next one
    }
  }
  return null
}

async function askEntry($, question, ms = ASK_MS) {
  const r = await runSettings($, JSON.stringify(question), ms)
  try {
    const a = r ? JSON.parse(r.stdout) : null
    return a && a.maisecrets === 'mod-settings' ? a : null
  } catch {
    return null
  }
}

async function askSettings($, question) {
  const a = await askEntry($, question)
  if (!a || !Array.isArray(a.groups)) {
    pane.error = 'maisecrets could not read its settings. /maisecrets status shows why.'
    return false
  }
  pane.groups = a.groups
  if (question.action !== 'list') pane.note = typeof a.note === 'string' ? a.note : null
  pane.error = null
  return true
}

const paneRows = () => pane.groups.reduce((n, g) => n + 1 + 2 * g.items.length, 0) + 8

const openArgs = () => ({ id: SETTINGS_PANE, title: 'maisecrets', focus: true, closeOnEscape: true,
  rows: paneRows(), columns: 100 })

// the verdict /maisecrets:status prints first, for this session: "checking…" until it comes, then its head line.
// Kept per session: a new open shows the last line at once and asks again in the background
async function refreshStatus($) {
  let id = null
  try { id = await $.session.id() } catch { id = null }
  if (pane.statusSession !== id) {
    pane.status = 'maisecrets: checking…'; pane.statusSession = id; pane.notes = []
    pane.showNotes = false
  }
  const t0 = await $.clock.now()
  pane.statusAt = t0
  // asks overlap (a tool call, the focus): only the answer of the newest ask is drawn
  const gen = ++pane.statusGen
  const a = await askEntry($, { action: 'status', session_id: id, tool_call_at: lastToolCall.get(id) ?? 0 })
  if (pane.statusSession !== id || gen !== pane.statusGen) return
  pane.status = a && typeof a.line === 'string' ? a.line : 'maisecrets: the status is unknown → /maisecrets status'
  pane.notes = a && Array.isArray(a.notes) ? a.notes.filter(n => n && typeof n.name === 'string') : []
  pane.pending = a?.pending === true       // a blocked prompt waits: the panel offers to send it
  if (!pane.notes.length) pane.showNotes = false
  pane.statusMs = Math.round((await $.clock.now()) - t0)
  try { $.ui.log(`maisecrets hub: status in ${pane.statusMs} ms`, { to: 'debug' }) } catch { /* no log */ }
  $.ui.invalidate('ui.render')
}

// the panel closed by this mod; the engine raises ui.close for the person's close (registerSettingsPane)
function closePane($) {
  pane.hint = null
  pane.open = false
  pane.focused = null
  return $.ui.close({ id: SETTINGS_PANE })
}

// the status again, while the panel is open: now, or once the gap since the last ask has passed (one wait at a time)
// a gateway sent references this turn and this computer has no login there: its login command goes into the input box,
// once per session and gateway (Python decides, sref_hooks.login_offer), and only into an empty box: what the person
// typed stays. The person's Enter starts the login; this never does. The hint line of the hook says why
let loginOfferDue = false
const LOGIN_FILL = /^\/maisecrets:sref login [A-Za-z0-9_.-]{1,64}$/

const boxEmpty = async ($) => ((await $.prompt.read())?.text ?? '').trim() === ''

// claude.ai connectors that showed references this session: each is asked once, at the end of a turn, for its
// gateway. Its answer is a proposal only: the person's login for it binds the connector (vault_refs.propose_connector)
const connectorsDue = new Set()
const connectorsAsked = new Set()
const CONNECTOR_NAME = /^claude_ai_[A-Za-z0-9_-]{1,64}$/
const CONNECTOR_TOOL = 'sensitive_references_resource'

// the one call of an MCP server in the mod: the connector's own tool, with no argument (which gateway?) or with a
// nonce of the mod only (its pairing proof, #91). { text, error } of its answer, or null when it gave none in 10 s
async function callConnector($, server, nonce) {
  // a connector that does not answer in 10 s gives no answer; the other offers go on
  let timer = null
  const late = new Promise(resolve => { try { timer = $.clock.after(10000, () => resolve(null)) } catch { resolve(null) } })
  const r = await Promise.race([$.mcp.call(server, CONNECTOR_TOOL, nonce === undefined ? undefined : { nonce }), late])
  try { timer?.cancel?.() } catch { /* ended */ }
  if (!r) return null
  const text = (r.content ?? []).filter(b => b?.type === 'text').map(b => b.text).join('').slice(0, 2000)
  return { text, error: r.isError === true }
}

// an MCP result that may hold a gateway reference: at the end of the turn Python says whether a gateway really sent
// this session references without a login here (offerLogin). A string test only; the text is never kept
function noteReferences(e, r) {
  try {
    if (typeof e?.tool === 'string' && e.tool.startsWith('mcp__') && !(loginOfferDue &&
        !e.tool.startsWith('mcp__claude_ai_')) && JSON.stringify(r ?? null).includes('\u27e6sref:')) {
      loginOfferDue = true
      // a claude.ai connector: at the end of the turn its own tool names its gateway (askConnector)
      const server = e.tool.slice('mcp__'.length, e.tool.lastIndexOf('__'))
      if (e.tool.startsWith('mcp__claude_ai_') && CONNECTOR_NAME.test(server)) connectorsDue.add(server)
    }
  } catch { /* no offer */ }
}

async function askConnector($, session, server) {
  const r = await callConnector($, server)
  if (!r || r.error) return null
  return askEntry($, { action: 'connector', session_id: session, server, answer: r.text, cwd: await $.session.cwd() })
}

// the nonce of each pairing while its connector call runs -> { key, tainted }. The gateway's contract (#91, its
// section 7a): the nonce goes to exactly one call, the mod's own; the same nonce in any other tool call, a tool
// result or a prompt (the AI could carry it to the person's real gateway connector and its proof back) taints the
// pairing, and nothing binds
const pairings = new Map()
const PLUGIN_CALL = 'toolu_plugin_'      // the tool_use_id of the mod's own call (measured on Claude Code 2.1.330)

// the mod's own pairing call: the AI cannot choose a tool_use_id of this form
function ownPairingCall(e, p) {
  return e?.tool === `mcp__claude_ai_${p.key}__${CONNECTOR_TOOL}` && typeof e?.tool_use_id === 'string' &&
    e.tool_use_id.startsWith(PLUGIN_CALL)
}

// true when this text holds the nonce of a running pairing: that pairing is tainted. `e` is the tool call the text
// belongs to (its own call is exempt), or null for a prompt
function notePairingUse(text, e) {
  let hit = false
  for (const [nonce, p] of pairings) {
    if (!text.includes(nonce) || (e && ownPairingCall(e, p))) continue
    p.tainted = true
    hit = true
  }
  return hit
}

const PAIR_DENY = 'maisecrets: this call carried the nonce of a running pairing, which only the maisecrets mod ' +
  'sends to one connector. Nothing ran, and that connector is not bound.'

// #91: a proposed connector is bound only when it proves that it reaches the gateway with the person's account: after
// the person's login for it succeeded, the connector answers a fresh nonce, and Python compares its proof with the
// one the gateway gives that login (sref_hooks.pair_connector). The nonce goes to the connector and to Python only
const PAIR_MS = 20000           // Python's discovery and one request to the gateway (PAIR_DISCOVERY_S, PAIR_REQUEST_S)
const PAIR_KEY = /^[A-Za-z0-9_-]{1,64}$/
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

// 32 random bytes in base64url without padding (43 characters); no source of randomness: no nonce, no pairing
function pairingNonce() {
  const b = new Uint8Array(32)
  globalThis.crypto.getRandomValues(b)
  let s = ''
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i] << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0)
    s += B64URL[(n >> 18) & 63] + B64URL[(n >> 12) & 63]
    if (i + 1 < b.length) s += B64URL[(n >> 6) & 63]
    if (i + 2 < b.length) s += B64URL[n & 63]
  }
  return s
}

async function pairConnector($, key) {
  if (!PAIR_KEY.test(key)) return
  const due = await askEntry($, { action: 'pair_due', key })
  if (due && due.due !== true) return          // no proposal waits for a proof (a gateway without pairing bound it)
  let line = null
  let why = 'its proof could not be checked'
  if (due) {
    try {
      const nonce = pairingNonce()
      const p = { key, tainted: false }
      pairings.set(nonce, p)
      let r = null
      try { r = await callConnector($, 'claude_ai_' + key, nonce) } finally { pairings.delete(nonce) }
      if (p.tainted) why = 'another tool call, a tool result or a prompt carried the nonce of this pairing, which ' +
        'only the connector may get'
      else if (r === null) why = 'the connector did not answer'
      else {
        const a = await askEntry($, { action: 'pair', key, nonce, answer: r.text, error: r.error }, PAIR_MS)
        line = typeof a?.note === 'string' ? a.note : null
      }
    } catch { line = null }
  }
  if (line === null) {
    // the pairing did not run: the unused login mark goes, so only a new typed login allows one (#91)
    try { await askEntry($, { action: 'pair_cancel', key }) } catch { /* the next login clears it */ }
    line = `maisecrets: the claude.ai connector ${key} was not bound: ${why}. To try again, send ` +
      `/maisecrets:sref login ${key}.`
  }
  toast($, line)
  try { $.ui.log(line.slice(0, 300)) } catch { /* the toast says it */ }
}

async function offerLogin($) {
  // a box with the person's text keeps the offer for the end of a later turn
  if (!(await boxEmpty($))) return
  loginOfferDue = false
  const session = await $.session.id()
  for (const server of [...connectorsDue].slice(0, 4)) {
    connectorsDue.delete(server)
    if (connectorsAsked.has(server)) continue
    connectorsAsked.add(server)
    let c = null
    try { c = await askConnector($, session, server) } catch { c = null }
    const fill = typeof c?.fill === 'string' && LOGIN_FILL.test(c.fill) ? c.fill : null
    if (!fill) continue
    if (!(await boxEmpty($))) { connectorsAsked.delete(server); connectorsDue.add(server); loginOfferDue = true; return }
    const done = await $.prompt.fill({ text: fill, mode: 'append' })
    if (done?.isFilled === true) {
      if (typeof c.note === 'string') try { $.ui.log(c.note.slice(0, 500)) } catch { /* the box says it */ }
      await askEntry($, { action: 'login_offered', session_id: session, fill })
      // the box holds a command now: the other offers wait for the end of a later turn
      loginOfferDue = true
      return
    }
  }
  if (connectorsDue.size > 0) loginOfferDue = true
  const a = await askEntry($, { action: 'login_offer', session_id: session })
  const text = typeof a?.fill === 'string' && LOGIN_FILL.test(a.fill) ? a.fill : null
  if (!text) return
  // read again right before the fill; append, never replace, so a key typed in between is not lost
  if (!(await boxEmpty($))) { loginOfferDue = true; return }
  const done = await $.prompt.fill({ text, mode: 'append' })
  // Python records the offer only now: a fill that did not happen leaves it for a later turn
  if (done?.isFilled === true) await askEntry($, { action: 'login_offered', session_id: session, fill: text })
}

async function statusSoon($) {
  if (!pane.open || pane.statusDue) return
  const now = await $.clock.now()
  const wait = pane.statusAt == null ? 0 : pane.statusAt + STATUS_GAP_MS - now
  if (wait <= 0) return void refreshStatus($).catch(() => {})
  pane.statusDue = true
  try {
    $.clock.after(wait, () => {
      pane.statusDue = false
      if (pane.open) void refreshStatus($).catch(() => {})
    })
  } catch { pane.statusDue = false }
}

async function openSettings($) {
  // the rows of the last answer draw at once; a fresh answer follows in the background (a change made by a typed
  // prompt or another session shows a moment later)
  const cached = pane.groups.length > 0
  pane.note = null
  pane.view = null
  pane.sub = null
  if (!cached && !(await askSettings($, { action: 'list' }))) return false
  if (cached) void askSettings($, { action: 'list' }).then(() => $.ui.invalidate('ui.render')).catch(() => {})
  void refreshStatus($).catch(() => {})
  const opened = await $.ui.open(openArgs())
  if (!opened?.isPlaced) {
    try { await closePane($) } catch { /* not open */ }
    return false
  }
  pane.open = true
  pane.focused = true
  $.ui.invalidate('ui.render')
  return true
}

async function pick($, key, value) {
  const t0 = await $.clock.now()
  await askSettings($, { action: 'set', key, value })
  try { $.ui.log(`maisecrets hub: ${key} saved in ${Math.round((await $.clock.now()) - t0)} ms`, { to: 'debug' }) }
  catch { /* no log */ }
  if (key === 'show_values') {
    try { await askValues($, []) } catch { /* the mode stays */ }
  }
  $.ui.invalidate('ui.render')
}

// ---- the views of the hub: stored values, name service (each change goes through the pane entry: the person's press)
async function showValues($, offset = 0) {
  pane.view = 'values'
  pane.confirm = null
  const a = await askEntry($, { action: 'values', offset })
  pane.values = a && Array.isArray(a.rows) ? a : { rows: [], total: 0, offset: 0, error: true }
  pane.viewNote = null
  $.ui.invalidate('ui.render')
}

// the sentence the entry wants with a wipe (maisecrets/hub.py WIPE_CONFIRM), sent only after the person's yes
const WIPE_CONFIRM = 'forget every stored value'

async function valuesAction($, action, key) {
  const question = { action, key, session_id: await $.session.id().catch(() => null) }
  if (action === 'forget_all') question.confirm = WIPE_CONFIRM
  const a = await askEntry($, question)
  pane.confirm = null
  if (a && Array.isArray(a.rows)) pane.values = a
  pane.viewNote = a && typeof a.note === 'string' ? a.note : 'maisecrets could not do that.'
  $.ui.invalidate('ui.render')
}

async function showNer($) {
  pane.view = 'ner'
  pane.nerSub = null
  pane.viewNote = null
  await loadNer($)
}

async function loadNer($, question = { action: 'ner' }) {
  const a = await askEntry($, question)
  if (a && typeof a.source === 'string') pane.ner = a
  if (a && typeof a.note === 'string') pane.viewNote = a.note
  pane.login = a && typeof a.login === 'string' ? a.login : null
  $.ui.invalidate('ui.render')
  return a
}

function pollNer($, left) {
  // the container downloads and loads its model: look again every 5 s, for about two minutes
  if (left <= 0 || pane.view !== 'ner') { pane.starting = false; $.ui.invalidate('ui.render'); return }
  try {
    $.clock.after(5000, () => { void loadNer($).then(() => pollNer($, left - 1)).catch(() => {}) })
  } catch { pane.starting = false }
}

async function setNer($, value) {
  pane.nerSub = null
  const a = await loadNer($, { action: 'ner_set', value })
  if (a && a.starting) { pane.starting = true; pollNer($, 24); watchNerStart($) }
}

// the start of the local service that the person's choice began (ner_setup.start_typed): the status line says that it
// loads until the service answers or the start ends, every 5 s, for at most NER_WATCH_ROUNDS
const NER_LOADING = 'maisecrets: loading the name service (starting)'
const NER_WATCH_ROUNDS = 180
let nerWatching = false
function watchNerStart($, left = NER_WATCH_ROUNDS) {
  if (nerWatching && left === NER_WATCH_ROUNDS) return
  nerWatching = true
  try { $.ui.status(NER_LOADING) } catch { /* no status line */ }
  const done = (text) => {
    nerWatching = false
    try { $.ui.status(undefined) } catch { /* no status line */ }
    if (text) try { $.ui.toast(text, { timeoutMs: 8000 }) } catch { /* a note only */ }
  }
  try {
    $.clock.after(5000, () => {
      void askEntry($, { action: 'ner' }).then(a => {
        if (a?.answers === true) return done('maisecrets: the name service runs and checks names now.')
        if (a && a.starting !== true) return done('maisecrets: the name service did not start. /maisecrets ner shows why.')
        if (left <= 1) return done('maisecrets: the name service still loads. /maisecrets ner shows its state.')
        watchNerStart($, left - 1)
      }).catch(() => done(null))
    })
  } catch { done(null) }
}

async function fillPrompt($, text) {
  try { await closePane($) } catch { /* closed already */ }
  try { await $.prompt.fill({ text }) } catch { /* the box stays as it is */ }
}

function drawCountries($, e, Box, Text, Button) {
  const it = pane.groups.flatMap(g => g.items).find(i => i.key === 'regions')
  if (!it) { pane.sub = null; return null }
  const toggles = it.choices.map(c => {
    const chosen = Array.isArray(it.values) && it.values.includes(c)
    return h(Box, { marginRight: 1, flexShrink: 0, key: `b:${c}` }, h(Button, { key: `set:regions:${c}`,
      label: chosen ? `● ${c}` : c, variant: chosen ? 'primary' : undefined, dimColor: !chosen,
      onPress: () => pick($, 'regions', c) }))
  })
  return h(Box, { flexDirection: 'column' },
    h(Text, { bold: true, key: 't' }, 'Countries for personal data'),
    h(Text, { dimColor: true, key: 'd' }, 'auto = the country of this computer. Pick one or more; auto clears them.'),
    pane.note ? h(Text, { color: 'green', key: 'note' }, pane.note) : h(Text, { key: 'sp' }, ' '),
    h(Box, { flexDirection: 'row', flexWrap: 'wrap', key: 'c' }, ...toggles),
    h(Box, { flexDirection: 'row', marginTop: 1, key: 'f' },
      h(Box, { marginRight: 2, key: 'back' }, h(Button, { key: 'back', label: 'Back', autoFocus: true,
        onPress: () => { pane.sub = null; $.ui.invalidate('ui.render') } })),
      h(Button, { key: 'close', label: 'Close', role: 'dismiss', onPress: () => closePane($) })))
}

async function checkOldLeaks($) {
  try { await closePane($) } catch { /* closed already */ }
  try { await $.prompt.fill({ text: '/maisecrets:secret-hygiene' }) } catch { /* the box stays as it is */ }
}

function viewFoot($, Box, Button, extra = [], focusBack = true) {
  return h(Box, { flexDirection: 'row', flexWrap: 'wrap', marginTop: 1, key: 'vfoot' }, ...extra,
    h(Box, { marginRight: 1, key: 'back' }, h(Button, { key: 'back', label: 'Back', ...(focusBack ? { autoFocus: true } : {}),
      onPress: () => { pane.view = null; $.ui.invalidate('ui.render') } })),
    h(Button, { key: 'close', label: 'Close', role: 'dismiss', onPress: () => closePane($) }))
}

const btn = (Box, Button, key, label, onPress, extra = {}) =>
  h(Box, { marginRight: 1, flexShrink: 0, key: `b:${key}` }, h(Button, { key, label, onPress, ...extra }))

function drawValues($, e, Box, Text, Button) {
  const v = pane.values || { rows: [], total: 0, offset: 0 }
  const rows = [h(Text, { bold: true, key: 't' }, `Stored values (${v.total})`)]
  rows.push(h(Text, { dimColor: true, key: 'd' }, 'Newest first. Only the masked form is shown, never a value.'))
  if (pane.viewNote) rows.push(h(Text, { color: 'green', key: 'note' }, pane.viewNote))
  if (v.error) rows.push(h(Text, { color: 'red', key: 'err' }, 'maisecrets could not read the store.'))
  if (!v.rows.length && !v.error) rows.push(h(Text, { key: 'none' }, 'Nothing is stored.'))
  for (const r of v.rows) {
    rows.push(h(Box, { marginTop: 1, key: `r:${r.key}` },
      h(Text, { bold: true }, `${r.key}`), h(Text, {}, `  ${r.shown}`),
      h(Text, { dimColor: true }, `  ${r.age} · ${r.uses} use${r.uses === 1 ? '' : 's'} · ${r.expires}`)))
    const c = pane.confirm
    if (c && c.key === r.key) {
      const q = c.action === 'forget' ? `Forget ${r.key}?` : `${r.key} is no secret, never mask it again?`
      rows.push(h(Box, { flexDirection: 'row', marginLeft: 2, key: `c:${r.key}` },
        h(Box, { marginRight: 1, key: 'q' }, h(Text, { color: 'yellow' }, q)),
        btn(Box, Button, `yes:${r.key}`, 'yes', () => valuesAction($, c.action, r.key)),
        btn(Box, Button, `no:${r.key}`, 'no', () => { pane.confirm = null; $.ui.invalidate('ui.render') },
          { autoFocus: true })))
    } else if (r.live) {
      rows.push(h(Box, { flexDirection: 'row', marginLeft: 2, key: `a:${r.key}` },
        btn(Box, Button, `forget:${r.key}`, 'forget', () => {
          pane.confirm = { action: 'forget', key: r.key }; $.ui.invalidate('ui.render') }, { dimColor: true }),
        btn(Box, Button, `allow:${r.key}`, 'not a secret', async () => {
          // the first of the two steps a typed prompt takes; the yes below is the second
          await askEntry($, { action: 'allow_ask', key: r.key, session_id: await $.session.id().catch(() => null) })
          pane.confirm = { action: 'allow', key: r.key }; $.ui.invalidate('ui.render') }, { dimColor: true })))
    }
  }
  const extra = []
  if (v.offset > 0) extra.push(btn(Box, Button, 'newer', 'newer', () => showValues($, Math.max(0, v.offset - 20))))
  if (v.offset + v.rows.length < v.total) extra.push(btn(Box, Button, 'more', 'more', () => showValues($, v.offset + 20)))
  if (v.total > 0) {
    if (pane.confirm && pane.confirm.action === 'all') {
      extra.push(h(Box, { marginRight: 1, key: 'qa' }, h(Text, { color: 'yellow' }, 'Forget every stored value? The logs and records stay.')))
      extra.push(btn(Box, Button, 'yes:all', 'yes', () => valuesAction($, 'forget_all', '')))
      extra.push(btn(Box, Button, 'no:all', 'no', () => { pane.confirm = null; $.ui.invalidate('ui.render') },
        { autoFocus: true }))
    } else {
      extra.push(btn(Box, Button, 'forget-all', 'forget all…', () => {
        pane.confirm = { action: 'all' }; $.ui.invalidate('ui.render') }, { dimColor: true }))
    }
  }
  rows.push(viewFoot($, Box, Button, extra, !pane.confirm))
  return h(Box, { flexDirection: 'column' }, ...rows)
}

function drawNer($, e, Box, Text, Button) {
  const n = pane.ner || { source: 'off', lines: [], servers: [] }
  const rows = [h(Text, { bold: true, key: 't' }, 'Name service'),
    h(Text, { dimColor: true, key: 'd' }, 'A service that finds names in tool results, after the rules.')]
  if (n.locked) {
    rows.push(h(Text, { bold: true, key: 'lk' }, `${n.source} ⚙  set by your admin`))
  } else if (pane.nerSub === 'gateway') {
    rows.push(h(Box, { marginTop: 1, key: 'gq' }, h(Text, {}, 'The gateway of which MCP server?')))
    if (!n.servers.length) {
      rows.push(h(Text, { dimColor: true, key: 'gn' },
        'Your configuration has no MCP server with an https address. /maisecrets ner gateway URL takes one.'))
    }
    rows.push(h(Box, { flexDirection: 'row', flexWrap: 'wrap', key: 'gs' },
      ...n.servers.map(s => btn(Box, Button, `gw:${s}`, s, () => setNer($, 'gateway:' + s))),
      btn(Box, Button, 'cancel', 'cancel', () => { pane.nerSub = null; $.ui.invalidate('ui.render') })))
  } else {
    const choice = (key, label, onPress) => btn(Box, Button, `ner:${key}`, n.source === key ? `● ${label}` : label,
      onPress, n.source === key ? { variant: 'primary' } : { dimColor: true })
    rows.push(h(Box, { flexDirection: 'row', flexWrap: 'wrap', marginTop: 1, key: 'src' },
      choice('off', 'off', () => setNer($, 'off')),
      // the press is the person's choice: it starts the service at once, and the note says how to stop it
      choice('local', 'local', () => setNer($, 'local')),
      choice('url', 'url…', () => fillPrompt($, 'maisecrets: ner url ')),
      choice('gateway', n.source === 'gateway' && n.gateway_name ? `gateway: ${n.gateway_name}` : 'gateway…',
        () => { pane.nerSub = 'gateway'; $.ui.invalidate('ui.render') })))
  }
  if (pane.viewNote) rows.push(h(Text, { color: 'green', key: 'note' }, pane.viewNote))
  if (pane.login) {
    rows.push(h(Box, { flexDirection: 'row', key: 'login' },
      h(Box, { marginRight: 1, key: 'lt' }, h(Text, {}, 'The gateway may need a login:')),
      btn(Box, Button, 'login', 'log in', () => fillPrompt($, `/maisecrets:sref login ${pane.login}`))))
  }
  if (pane.starting) rows.push(h(Text, { color: 'yellow', key: 'st' }, 'starting… (the download can take minutes)'))
  rows.push(h(Box, { flexDirection: 'column', marginTop: 1, key: 'lines' },
    ...n.lines.map((l, i) => h(Text, { key: `l${i}` }, l || ' '))))
  rows.push(viewFoot($, Box, Button))
  return h(Box, { flexDirection: 'column' }, ...rows)
}

function drawSettings($, e) {
  const { Box, Text, Button } = $.ui.resolve(e)
  // the panel takes the keys again (a click, the focus chord): its status may be old
  const focused = e.props?.isFocused === true
  if (focused && pane.focused === false) void statusSoon($).catch(() => {})
  pane.focused = focused
  if (pane.view === 'values') return drawValues($, e, Box, Text, Button)
  if (pane.view === 'ner') return drawNer($, e, Box, Text, Button)
  if (pane.sub === 'regions') { const t = drawCountries($, e, Box, Text, Button); if (t) return t }
  const narrow = (e.props?.bodyColumns ?? 100) < NARROW
  // the desktop app fills a chosen button: no dot in it, and "set by you" goes after the buttons as grey text (the
  // terminal keeps both in the button: there a fill alone can be lost)
  const desk = e.surface === 'desktop'
  const rows = []
  // the top stays in view on a short terminal: the status, the last change, the buttons
  if (pane.hint) rows.push(h(Text, { color: 'yellow', key: 'hint' }, pane.hint))
  if (pane.status) {
    const line = [h(Text, { bold: true, key: 'status' }, pane.status)]
    if (pane.notes.length) {
      line.push(h(Box, { marginLeft: 1, flexShrink: 0, key: 'nb' }, h(Button, { key: 'notes',
        label: `${pane.notes.length} note${pane.notes.length === 1 ? '' : 's'}`,
        onPress: () => { pane.showNotes = !pane.showNotes; $.ui.invalidate('ui.render') } })))
    }
    rows.push(h(Box, { flexDirection: 'row', flexWrap: 'wrap', key: 'sl' }, ...line))
    if (pane.showNotes) {
      for (const n of pane.notes) {
        rows.push(h(Text, { key: `n:${n.name}` }, `  ! ${n.name}: ${n.fact}` + (n.next ? ` → ${n.next}` : '')))
      }
    }
  }
  if (pane.error) rows.push(h(Text, { color: 'red', key: 'err' }, pane.error))
  else if (pane.note) rows.push(h(Text, { color: 'green', key: 'note' }, pane.note))
  const foot = [...(pane.pending ? [['send', 'Send the blocked prompt', () => sendFromPane($)]] : []),
    ['stored', 'Stored values', () => showValues($, 0)],
    ['names', 'Name service', () => showNer($)],
    ['leaks', 'Check old leaks', () => checkOldLeaks($)]]
    .map(([key, label, onPress]) => h(Box, { marginRight: 1, flexShrink: 0, key }, h(Button, { key, label, onPress })))
  // the first focus: Close, so an Enter right after /maisecrets changes nothing
  foot.push(h(Button, { key: 'close', label: 'Close', role: 'dismiss', autoFocus: true, onPress: () => closePane($) }))
  rows.push(h(Box, { flexDirection: 'row', flexWrap: 'wrap', marginTop: 1, key: 'foot' }, ...foot))
  for (const g of pane.groups) {
    rows.push(h(Box, { marginTop: 1, key: `g:${g.title}` }, h(Text, { bold: true }, g.title)))
    for (const it of g.items) {
      const cells = []
      if (it.locked) {
        cells.push(h(Text, { bold: true, key: 'v' }, `${it.value} ⚙`))
        cells.push(h(Text, { dimColor: true, key: 'why' }, '  set by your admin'))
      } else if (it.list) {
        // a list: its entries, and the prompt box for a change (the person types the folder, host or file)
        cells.push(h(Box, { marginRight: 1, flexShrink: 1, key: 'v' },
          h(Text, { bold: true, wrap: 'truncate-end' }, it.value + (it.mark ? ` ${it.mark}` : ''))))
        cells.push(h(Box, { marginRight: 1, flexShrink: 0, key: 'add' }, h(Button, { key: `add:${it.key}`,
          label: 'add…', onPress: () => fillPrompt($, `maisecrets: set ${it.key} add `) })))
        if (it.count > 0) {
          cells.push(h(Box, { flexShrink: 0, key: 'rm' }, h(Button, { key: `remove:${it.key}`, label: 'remove…',
            onPress: () => fillPrompt($, `maisecrets: set ${it.key} remove `) })))
        }
      } else if (it.multi) {
        // the countries: compact here, the toggles in their own view
        const isAuto = Array.isArray(it.values) && it.values.length === 1 && it.values[0] === 'auto'
        if (isAuto) {
          cells.push(h(Box, { marginRight: 1, flexShrink: 0, key: 'auto' }, h(Button, { key: 'set:regions:auto',
            label: desk ? 'auto' : `● auto${it.mark ? ' ' + it.mark : ''}`, variant: 'primary',
            onPress: () => pick($, 'regions', 'auto') })))
        } else {
          cells.push(h(Box, { marginRight: 1, key: 'v' }, h(Text, { bold: true }, it.value + (it.mark ? ` ${it.mark}` : ''))))
        }
        cells.push(h(Box, { flexShrink: 0, key: 'choose' }, h(Button, { key: 'regions:choose',
          label: isAuto ? 'choose…' : 'change…', onPress: () => { pane.sub = 'regions'; $.ui.invalidate('ui.render') } })))
        if (desk && isAuto && it.mark === '✎') cells.push(h(Text, { dimColor: true, key: 'mark' }, 'set by you'))
      } else if (!it.choices.length) {
        cells.push(h(Text, { bold: true, key: 'v' }, it.value + (it.mark ? ` ${it.mark}` : '')))
      } else {
        for (const c of it.choices) {
          // several countries: a toggle per code; one value: the current one
          const now = it.multi && Array.isArray(it.values) ? it.values.includes(c) : c === it.value
          const shown = (it.labels && it.labels[c]) || c
          const props = { key: `set:${it.key}:${c}`,
            label: now && !desk ? `● ${shown}${it.mark ? ' ' + it.mark : ''}` : shown, onPress: () => pick($, it.key, c) }
          if (now) props.variant = 'primary'
          else props.dimColor = true
          cells.push(h(Box, { marginRight: 1, flexShrink: 0, key: `b:${c}` }, h(Button, props)))
        }
        if (desk && it.mark === '✎') cells.push(h(Text, { dimColor: true, key: 'mark' }, 'set by you'))
      }
      const label = h(Text, { key: 'label', wrap: 'truncate-end' }, '  ' + it.label)
      if (narrow) {
        rows.push(h(Box, { flexDirection: 'column', key: `r:${it.key}` }, label,
          h(Box, { flexDirection: 'row', flexWrap: 'wrap', marginLeft: desk ? 2 : 4, key: 'c' }, ...cells)))
      } else {
        rows.push(h(Box, { flexDirection: 'row', key: `r:${it.key}` },
          h(Box, { width: 44, flexShrink: 0, key: 'l' }, label), h(Box, { flexDirection: 'row', key: 'c' }, ...cells)))
      }
    }
  }
  rows.push(h(Box, { marginTop: 1, key: 'help' }, h(Text, { dimColor: true },
    'Tab moves · Enter picks · Esc closes')))
  return h(Box, { flexDirection: 'column' }, ...rows)
}

// the engine puts a dropped prompt back into the box, and a pane takes the keys only over an empty composer: empty it
// once the drop landed, then ask for the keys again
function takeKeysSoon($, args = openArgs) {
  try {
    $.clock.after(60, () => {
      void (async () => {
        try { await $.prompt.fill({ text: '' }) } catch { /* the text stays */ }
        try { await $.ui.open(args()) } catch { /* open without the keys */ }
      })()
    })
  } catch { /* no timer: the pane is open without the keys */ }
}

// ---- the person's own commands, run here without the AI (0.9.19)
// A slash command whose command file only runs one CLI entry and shows its output (prompt_commands.run_plan). Typed by
// the person, the prompt hook decides it first, with the call it makes for the command file (dispatch.py mod-prompt:
// its value check, a settings or ner change, the note of a typed forget). Then the mod drops the prompt and starts that
// entry itself, in the background: the prompt.submit hook returns at once, and the box is free. The output goes into a
// pane of its own (above the prompt where no pane is placed); a login shows its wait in the status line and its end
// in a toast. Codex, claude -p (origin sdk) and a client without mods keep the command files.
const RUN_ORIGINS = new Set(['composer', 'bridge'])
const RUN_NAMES = ['audit', 'forget', 'guard', 'list', 'ner', 'put', 'report', 'rules', 'send', 'settings', 'shortcut',
  'sref', 'status', 'term', 'maisecrets']
const RUN_CMD = new RegExp(`^\\s*/maisecrets:(?:${RUN_NAMES.join('|')})(?:[ \\t][^\\r\\n]*)?\\s*$`, 'i')
// the entries of hooks/dispatch.py a run may start, and the words of its command line: fixed words only, the typed
// arguments go on stdin (--args-stdin), as in the command files
const RUN_ENTRIES = new Set(['audit', 'forget', 'guard', 'list', 'ner', 'put', 'report', 'rules', 'settings',
  'shortcut', 'sref', 'status', 'terms', 'pending', 'entry'])
const RUN_WORD = /^(?:[a-z]+|--[a-z-]+)$/
const RUN_MS = 30000
const LONG_MS = 130000          // the login waits up to 110 s for the consent (cli.cmd_sref)
const PYTHONS = [['python3'], ['py', '-3'], ['python']]
const OUTPUT_PANE = 'maisecrets-out'      // the start of each run's own pane id (paneOf)
const OUTPUT_LINES = 400
const SESSION_RE = /^[A-Za-z0-9_-]{1,128}$/
const SERVER_RE = /^[\w.-]{1,64}$/
// the notes of `run.sh pending` (hooks.NOTHING_WAITING, TWO_WAITING): any other output is the prompt
const PENDING_NOTES = ['(maisecrets: no blocked prompt is waiting', '(maisecrets: blocked prompts of two sessions']
// the first line of `run.sh entry` alone when a blocked prompt waits (cli.ENTRY_SEND_HEAD): the prompt follows it
const ENTRY_SEND_HEAD = '(maisecrets: the blocked prompt follows)'

const running = new Map()       // one run per flight at a time: flight -> { title, stop, replaced }
// the output of each flight in a pane of its own: a login that waits and a list keep their own titles and lines
const outputs = new Map()       // pane id -> { title, lines, markdown, done, note, waiting, placed }
const FLIGHTS = ['sref-login', ...RUN_NAMES.map(n => 'cmd:' + n)]
const paneOf = (flight) => `${OUTPUT_PANE}-${flight.replace(/[^a-z0-9-]/g, '-')}`

// what may not run twice at once: a login or logout of a gateway (one browser flow), else the same command
function flightOf(text) {
  const m = /^\s*\/maisecrets:([a-z-]+)(?:[ \t]+(\S+))?/i.exec(text) || []
  const name = (m[1] || '').toLowerCase()
  if (name === 'sref' && /^log(?:in|out)$/i.test(m[2] || '')) return 'sref-login'
  return 'cmd:' + name
}

// the command as a title: its name and a first word of a fixed form (login, all), never a typed value
function titleOf(text) {
  const m = /^\s*\/maisecrets:([a-z-]+)(?:[ \t]+([a-z-]{1,12})(?=\s|$))?/i.exec(text) || []
  const name = (m[1] || '').toLowerCase()
  if (name === 'maisecrets') return '/maisecrets'
  return `/maisecrets ${name}${m[2] ? ' ' + m[2].toLowerCase() : ''}`
}

function validRun(run) {
  return !!run && typeof run === 'object' && Array.isArray(run.argv) && run.argv.length > 0 && run.argv.length <= 4
    && RUN_ENTRIES.has(run.argv[0]) && run.argv.every(w => typeof w === 'string' && RUN_WORD.test(w))
    && (run.stdin === undefined || typeof run.stdin === 'string')
}

const LOGIN_TITLE = '/maisecrets sref login'
const AGAIN_LINE = 'maisecrets: the earlier login was stopped, and a new one opens your browser. For another browser ' +
  'or profile, copy the login URL from the panel into it.'
const busyLine = (flight) => flight === 'sref-login'
  ? 'maisecrets: a login runs already; the status line shows it. Nothing else was started.'
  : 'maisecrets: this command runs already. Nothing else was started.'

const outputArgs = (id) => () => {
  const out = outputs.get(id) ?? { title: 'maisecrets', lines: [] }
  return { id, title: out.title, focus: true, closeOnEscape: true, rows: Math.min(out.lines.length + 6, 40),
    columns: 100 }
}

function drawOutput($, e, id) {
  const { Box, Text, Markdown, Button } = $.ui.resolve(e)
  const out = outputs.get(id) ?? { lines: [], done: true }
  const rows = []
  if (out.note) rows.push(h(Text, { color: 'green', key: 'note' }, out.note))
  if (out.markdown && out.done && Markdown) rows.push(h(Markdown, { key: 'md', text: out.lines.join('\n') }))
  else rows.push(...out.lines.map((l, i) => h(Text, { key: `l${i}` }, l || ' ')))
  if (!out.done && out.waiting) rows.push(h(Text, { color: 'yellow', key: 'wait' }, out.waiting))
  // the output of /maisecrets:sref names the login command of a server: one button per server starts it
  const names = id === paneOf('cmd:sref') && out.done ? loginNames(out.lines).slice(0, 6) : []
  rows.push(h(Box, { marginTop: 1, key: 'foot' },
    ...names.map(n => h(Box, { marginRight: 1, flexShrink: 0, key: `b:${n}` }, h(Button, { key: `login:${n}`,
      label: `log in: ${n}`, variant: 'primary', onPress: () => loginFromPane($, id, n) }))),
    h(Button, { key: 'close', label: 'Close', role: 'dismiss', autoFocus: true,
      onPress: () => $.ui.close({ id }) })))
  return h(Box, { flexDirection: 'column' }, ...rows)
}

// the output on the person's screen: the run's own pane, or rows above the prompt where no pane is placed (`placed`
// remembers which, so a login that streams writes its lines above the prompt then). Never to the model
async function showOutput($, id) {
  const out = outputs.get(id)
  let placed = false
  try { placed = (await $.ui.open(outputArgs(id)()))?.isPlaced === true } catch { placed = false }
  out.placed = placed
  if (placed) {
    $.ui.invalidate('ui.render')
    takeKeysSoon($, outputArgs(id))
    return true
  }
  try {
    if (out.note) $.ui.log(out.note)
    for (const l of out.lines.filter(x => x.trim()).slice(0, 80)) $.ui.log(l)
  } catch { /* no rows either */ }
  return false
}

const toast = ($, text) => { try { $.ui.toast(text.slice(0, 300), { timeoutMs: 8000 }) } catch { /* a note only */ } }

// hooks/dispatch.py with the words of the plan, by the Python that answered the prompt check (it can start), streamed:
// a login prints its URL early, for the person whose browser did not open
async function spawnOwn($, run, env, onText, ms, entry) {
  const req = { argv: [...PYTHONS[lastPython], 'hooks/dispatch.py', ...run.argv], cwd: $.plugin.root, env }
  if (typeof run.stdin === 'string') req.input = run.stdin
  const stream = $.process.spawn(req)
  // a newer login of the same flight stops this one: return() on the stream kills the child (process.spawn)
  if (entry) entry.stop = () => { try { void Promise.resolve(stream.return(undefined)).catch(() => {}) } catch { /* ended */ } }
  let timer = null
  let timedOut = false
  try {
    timer = $.clock.after(ms, () => {
      timedOut = true
      try { void Promise.resolve(stream.return(undefined)).catch(() => {}) } catch { /* it ends by itself */ }
    })
  } catch { timer = null }
  try {
    for await (const piece of stream) onText(typeof piece?.text === 'string' ? piece.text : '')
    const end = await stream.result
    return { code: typeof end?.code === 'number' ? end.code : 1, timedOut }
  } catch (err) {
    if (timedOut) return { code: null, timedOut }
    throw err
  } finally {
    try { timer?.cancel?.() } catch { /* the timer ends by itself */ }
  }
}

function startOwn($, run, flight, title, entry = running.get(flight)) {
  const server = typeof run.server === 'string' && SERVER_RE.test(run.server) ? run.server : null
  const id = paneOf(flight)
  // a run that a newer one replaced leaves the flight, the status line and the pane to the newer one
  const mine = () => !!entry && running.get(flight) === entry && !entry.replaced
  const leave = () => { if (entry && running.get(flight) === entry) running.delete(flight) }
  void (async () => {
    let text = ''
    let logged = 0                  // the complete lines of a login already written above the prompt
    let result = null
    let out = null
    try {
      if (run.view === 'panel') {
        // the entry alone (/ms, as /maisecrets alone): the panel; where none is placed, the overview runs below
        let opened = false
        try { opened = await openSettings($) } catch { opened = false }
        if (opened) {
          takeKeysSoon($)
          return
        }
      }
      if (run.view === 'ner') {
        // the change is made: the panel's name-service view shows the source, the login button and the start
        let opened = false
        try { opened = await openSettings($) } catch { opened = false }
        if (opened) {
          await showNer($)
          if (typeof run.note === 'string') pane.viewNote = run.note.replace(/^maisecrets: /, '')
          if (run.starting === true) { pane.starting = true; watchNerStart($) }
          $.ui.invalidate('ui.render')
          takeKeysSoon($)
          return
        }
      }
      out = { title: `maisecrets: ${title}`, lines: [], markdown: run.markdown === true,
        note: typeof run.note === 'string' ? run.note : null, done: false, waiting: null, placed: null }
      outputs.set(id, out)
      if (run.long) {
        out.waiting = `waiting for your consent in the browser (${server ?? 'your gateway'}), up to 110 s`
        try { $.ui.status(`maisecrets: waiting for your consent in the browser (${server ?? 'your gateway'})`) }
        catch { /* the pane says it */ }
        await showOutput($, id)
      }
      if (run.starting === true) watchNerStart($)
      const sid = await $.session.id()
      const env = { PYTHONUTF8: '1' }
      // the session of the command, as Claude Code gives it to a command file's shell (status names it; a typed
      // forget and /maisecrets:send find their record by it)
      if (typeof sid === 'string' && SESSION_RE.test(sid)) env.CLAUDE_CODE_SESSION_ID = sid
      result = await spawnOwn($, run, env, (t) => {
        // a piece already on its way when the stop came writes no rows: the newer run has the screen (no test can send
        // one: the fake child ends at its next piece)
        if (entry?.replaced) return
        text += t
        if (run.long) {
          out.lines = text.split(/\r?\n/).slice(0, OUTPUT_LINES)
          if (out.placed === false) {
            // no pane: each complete line goes above the prompt as it comes (the URL for a browser that did not open)
            const done = text.split(/\r?\n/).slice(0, -1)
            try { for (const l of done.slice(logged)) if (l.trim()) $.ui.log(l) } catch { /* no rows */ }
            logged = Math.max(logged, done.length)
          }
          $.ui.invalidate('ui.render')
        }
      }, run.long ? LONG_MS : RUN_MS, entry)
    } catch {
      result = null
    } finally {
      if (entry) entry.ended = true
      const replaced = !mine()
      leave()
      if (run.long && !replaced) try { $.ui.status(undefined) } catch { /* no status line */ }
    }
    if (entry?.replaced) return
    const lines = text.replace(/\s+$/, '').split(/\r?\n/).slice(0, OUTPUT_LINES)
    const last = lines.filter(l => l.trim()).pop() ?? ''
    if (run.long && out?.placed === false) {
      try { for (const l of lines.slice(logged)) if (l.trim()) $.ui.log(l) } catch { /* no rows */ }
    }
    out = out ?? { lines: [], done: true }
    if (result === null) {
      out.done = true
      return toast($, `maisecrets could not run ${title}. Send it again.`)
    }
    if (result.timedOut) {
      out.done = true
      out.lines = lines
      return toast($, `maisecrets: ${title} did not end within ${Math.round((run.long ? LONG_MS : RUN_MS) / 1000)} s and ` +
        'was stopped.')
    }
    const sent = run.fill && text.trim().startsWith(ENTRY_SEND_HEAD)
    if (run.fill && run.argv[0] === 'entry' && !sent) {
      // the entry alone and no blocked prompt: its overview shows like any output (below)
    } else if (run.fill) {
      const said = sent ? text.trim().slice(ENTRY_SEND_HEAD.length).trim() : text.trim()
      if (!said || PENDING_NOTES.some(n => said.startsWith(n))) {
        fillSoon($, '')
        return toast($, said || 'maisecrets: no blocked prompt is waiting.')
      }
      // the prompt as maisecrets rewrote it (placeholders, never a value) waits in the box for the person's Enter
      fillSoon($, said)
      return toast($, 'maisecrets: the cleaned prompt is in your input box. Press Enter to send it.')
    }
    out.lines = lines
    out.done = true
    if (run.view === 'lines') {
      // a confirmation (forget): its lines above the prompt, no panel for them
      const said = lines.filter(l => l.trim()).slice(0, 20)
      try { for (const l of said) $.ui.log(l) } catch { toast($, said.join(' ') || `maisecrets: ${title} ended.`) }
      return
    }
    if (run.long) {
      const said = result.code === 0 && server ? `maisecrets: logged in at ${server}` : last ||
        `maisecrets: the login did not complete (exit ${result.code}).`
      toast($, said)
      // a row in the transcript too: the person is in the browser when the login ends, and a toast goes after 8 s
      try { $.ui.log(said.slice(0, 300)) } catch { /* the toast says it */ }
      $.ui.invalidate('ui.render')
      // a proposed claude.ai connector of this login: its pairing proof binds it (#91)
      if (result.code === 0 && typeof run.pair === 'string' && run.pair === server) await pairConnector($, run.pair)
      return
    }
    await showOutput($, id)
  })().catch(() => { leave() })
}

// a command the mod runs itself, or Python's answer to an own-command shape: { drop } when it is answered here, else
// { answer } with Python's answer for the steps of any prompt. `fill` empties the box for a prompt; a pane button leaves the box alone
async function runOwn($, own, kind, runnable, ownCmd, fill, viaMs = false, passOn = false) {
  let ownAnswer = null      // Python's answer to an own-command shape: the steps below use it, not a second ask
  // one run per flight, taken before the first await, so two quick prompts cannot both pass
  const flight = runnable ? flightOf(own) : null
  // a login again while one waits in the browser replaces it: the person found the wrong browser or profile and
  // starts over (the earlier one is stopped only once the new one can start). A login that has not started yet
  // (two quick prompts) and any other run of the flight start nothing
  const before = flight ? running.get(flight) : undefined
  const again = !!before && before.title === LOGIN_TITLE && titleOf(own) === LOGIN_TITLE && !!before.stop
  if (before && !again) {
    if (fill) fillSoon($, '')
    return { drop: busyLine(flight) }
  }
  const entry = flight ? { title: titleOf(own), stop: null, replaced: false } : null
  if (flight) running.set(flight, entry)
  try { ownAnswer = await askOwn($, own, kind, viaMs) } catch { ownAnswer = null }
  const run = ownAnswer?.run
  if (runnable && validRun(run)) {
    if (fill) fillSoon($, '')
    // a login that ended while this one was checked was not stopped: the plain start line then
    const stopped = again && !before.ended
    if (stopped) { before.replaced = true; before.stop?.() }
    startOwn($, run, flight, titleOf(own), entry)
    return { drop: stopped ? AGAIN_LINE : startedLine(run, titleOf(own)) }
  }
  if (flight && running.get(flight) === entry) {
    // the earlier login waits on, unless it ended meanwhile: then the flight is free and its status line goes
    if (again && !before.replaced && !before.ended) running.set(flight, before)
    else {
      running.delete(flight)
      if (again) try { $.ui.status(undefined) } catch { /* no status line */ }
    }
  }
  if (ownAnswer === null && ownCmd) return { drop: OWN_FAILED }
  if (ownAnswer !== null && validEntry(ownAnswer.entry)) {
    // a command that needs the model: the entry command file runs it. A line that already names that file goes on as
    // typed (the prompt hook decides it, as without the mod); any other form waits in the box as that file's line,
    // and the person's Enter runs it. The mod runs no command itself (the plugin directory: MOD_RUNS_COMMAND)
    if (passOn) return { pass: true }
    const form = `${ENTRY_FORM} ${ownAnswer.entry}`
    const name = ownAnswer.entry.split(/\s+/)[0]
    if (fill) {
      fillSoon($, form)
      return { drop: `maisecrets: /maisecrets ${name} needs the AI. It is in your input box: press Enter to run it.` }
    }
    return { drop: `maisecrets: /maisecrets ${name} needs the AI. Send ${form} to run it.`, entryBox: form }
  }
  if (ownAnswer !== null && typeof ownAnswer.drop === 'string') {
    if (fill) fillSoon($, typeof ownAnswer.fill === 'string' ? ownAnswer.fill : '')
    return { drop: showOwn($, ownAnswer.drop, OWN_ABOVE), box: ownAnswer.box }
  }
  return { answer: ownAnswer }
}

// the words of the entry for a command that needs the model (prompt_commands.mod_command): one line, a command name first
const ENTRY_FORM = '/maisecrets:maisecrets'
function validEntry(words) {
  return typeof words === 'string' && words.length <= 2000 && !/[\r\n]/.test(words) &&
    COMMANDS.includes(words.split(/[ \t]+/)[0])
}
// a typed line that names an entry command file with words (commands/maisecrets.md, commands/ms.md): passed on, the
// client runs that file with the words. Not `/maisecrets NAME`: that is the mod's own command (command.run only)
const ENTRY_LINE = /^\s*\/(?:maisecrets:(?:maisecrets|ms)|ms)[ \t]+\S/i
// the entry's line for a command from the command.run route: into the box only when it is empty, never over the
// person's own text; the person's Enter sends it as their own prompt
async function boxedEntry($, form) {
  if (typeof form !== 'string' || !form.startsWith(ENTRY_FORM + ' ') || /[\r\n]/.test(form)) return false
  try {
    if (!(await boxEmpty($))) return false
    return (await $.prompt.fill({ text: form, mode: 'append' }))?.isFilled === true
  } catch { return false }
}

// the person's own command typed as the mod's `/maisecrets NAME` or as a hidden `/maisecrets:NAME` (the client refuses
// a hidden command typed by the person; the command.run hook sees it first): the steps of a typed prompt for its colon
// form `own`, with the answer as the command's output for the person alone. Measured on 2.1.330: neither line passes
// prompt.submit or the settings hook
const ownText = (line) => ({ text: String(line).replace(/^maisecrets: /, ''), isTextDisplayOnly: true })
// the origin Python gets for this route (prompt_commands.COMMAND_ROUTE): the engine stamps every local command run
// `composer`, so it is no proof that the person typed it. Python makes no change there that only the person's own
// prompt may make (C22): it names the prompt to send, which goes through prompt.submit and the prompt hook
const COMMAND_ROUTE = 'command'
// the refused commands of this route that may wait in an empty input box (prompt_commands._BOX_SREF_RE): a logout,
// and a login, which opens the browser for the person's consent and binds a connector only with its proof, as the
// login offer (LOGIN_FILL). The person's Enter sends it as their own prompt; every other change is only named
const SREF_BOX = /^\/maisecrets:sref log(?:in|out)(?: [A-Za-z0-9_.-]{1,64})?$/
async function boxed($, text) {
  if (typeof text !== 'string' || !SREF_BOX.test(text)) return false
  try {
    if (!(await boxEmpty($))) return false
    return (await $.prompt.fill({ text, mode: 'append' }))?.isFilled === true
  } catch { return false }
}
async function runTyped($, own) {
  const kind = COMMAND_ROUTE
  if (DEMO_CMD.test(own)) {
    try { demo.delete(await $.session.id()) } catch { /* the step asks */ }
  }
  afterPrompt($, own)
  if (SETTINGS_CMD.test(own)) {
    pane.hint = null
    let opened = false
    try { opened = await openSettings($) } catch { opened = false }
    if (opened) {
      takeKeysSoon($)
      return {}
    }
  }
  if (OWN_SLASH.test(own) && !DEMO_CMD.test(own)) {
    let shown = null
    try { shown = await ownInDemo($, own, kind) } catch { shown = null }
    if (shown !== null) return ownText(showOwn($, shown))
  }
  let done = null
  try { done = await runOwn($, own, kind, RUN_CMD.test(own), true, false) } catch { done = null }
  if (typeof done?.drop === 'string' && await boxed($, done.box)) return ownText(filledNote(done.box))
  if (typeof done?.drop === 'string' && await boxedEntry($, done.entryBox)) return ownText(filledNote(done.entryBox))
  return ownText(typeof done?.drop === 'string' ? done.drop : OWN_FAILED)
}

// the panel's send button (a blocked prompt waits): the person's press runs /maisecrets send as the typed command
// would; the cleaned prompt goes into the box, and the person's Enter sends it
async function sendFromPane($) {
  try { await closePane($) } catch { /* closed already */ }
  let done
  try { done = await runOwn($, '/maisecrets:send', 'composer', true, false, false) } catch { done = undefined }
  toast($, done?.drop ?? OWN_FAILED)
}

// a login button of the output pane of /maisecrets:sref: the person's press, which the AI cannot make, starts the login
// as the typed command would (its checks in Python, one flight, a login again starts over). A server name of the output
// only, in the form the box takes
const LOGIN_NAME = /\/maisecrets[: ]sref login ([A-Za-z0-9_.-]{1,64})(?=[\s)]|$)/g
const loginNames = (lines) => [...new Set(lines.flatMap(l => [...String(l).matchAll(LOGIN_NAME)].map(m => m[1])))]

async function loginFromPane($, id, name) {
  try { await $.ui.close({ id }) } catch { /* closed already */ }
  const own = `/maisecrets:sref login ${name}`
  let done
  try { done = await runOwn($, own, 'composer', true, true, false) } catch { done = undefined }
  toast($, done?.drop ?? OWN_FAILED)
}

const startedLine = (run, title) => run.long
  ? `maisecrets: ${title} opens your browser; the status line shows the wait.`
  : run.view === 'panel' ? 'maisecrets: the panel opens. Esc closes it.'
    : run.view === 'lines' ? `maisecrets: ${title} runs without the AI; its answer shows above the prompt.`
      : `maisecrets: ${title} runs without the AI; its output opens in a panel.`

function registerSettingsPane(on) {
  on('ui.render', { component: 'Pane', requestId: SETTINGS_PANE }, async ($, e) => drawSettings($, e))
  // one pane per flight (paneOf): a fixed list, each with its own matched hook
  for (const flight of FLIGHTS) {
    const id = paneOf(flight)
    on('ui.render', { component: 'Pane', requestId: id }, async ($, e) => drawOutput($, e, id))
  }
  on('ui.close', ($, e, next) => {
    if (e.id === SETTINGS_PANE) { pane.open = false; pane.focused = null }
    return next(e)
  })
  // a tool call or a turn of this session runs the hooks: the open panel asks for the status again. Neither hook
  // changes the call or the answer, and a failure of its own never reaches them
  on('tool.call', async ($, e, next) => {
    try { noteCalled(e) } catch { /* no note: an error of this call is masked */ }
    // a pairing runs: its nonce in any call but the mod's own taints it, and that call never runs (#91)
    if (pairings.size > 0) {
      let hit = true
      try { hit = notePairingUse(JSON.stringify(e ?? null), e) } catch { hit = true }
      if (hit) return { deny: PAIR_DENY }
    }
    let start = null
    try { start = (await $.clock.now()) / 1000 } catch { start = null }
    const r = await next(e)
    // the nonce in the result of any call but the mod's own taints the pairing too (a connector that echoes it)
    if (pairings.size > 0) try { notePairingUse(JSON.stringify(r ?? null), e) } catch { /* see the call above */ }
    try { noteReferences(e, r) } catch { /* a failure of its own never reaches the result */ }
    try {
      // a call another hook refused may not have reached PreToolUse: it is not kept
      if (start !== null && (!r || r.deny === undefined)) {
        // calls run in parallel: one that started earlier and ends later keeps the newer start
        void $.session.id().then(id => { if (id) lastToolCall.set(id, Math.max(lastToolCall.get(id) ?? 0, start)) })
          .catch(() => {}).finally(() => statusSoon($).catch(() => {}))
      } else void statusSoon($).catch(() => {})
    } catch { /* the line stays */ }
    return r
  })
  on('turn.complete', async ($, e, next) => {
    const r = await next(e)
    try { void statusSoon($).catch(() => {}) } catch { /* the line stays */ }
    // the end of the main turn only: a subagent's end comes while the turn still runs and the person may type
    if (loginOfferDue && !e.agentId) void offerLogin($).catch(() => {})
    return r
  })
  // /maisecrets: the menu. A mod's own command, served here with no model turn (a typed /maisecrets alone is no
  // command file: the typeahead would turn it into the first /maisecrets:… command on Enter)
  on('command.run', { command: 'maisecrets' }, async ($, e) => {
    const t0 = await $.clock.now()
    // `/maisecrets sref login` that no person's prompt brought (the prompt.submit hook drops a person's), or a
    // mistyped name: the box gets the command with its colon, and the person decides
    const spaced = `/maisecrets ${e?.args ?? ''}`
    const typed = meantCommand(spaced)
    // `/maisecrets status`, typed by the person: it runs now, as its colon form (no second Enter)
    if (typed && RUN_ORIGINS.has(e?.origin?.kind)) return await runTyped($, typed)
    const meant = typed ?? nearCommand(spaced)
    if (meant) {
      const a = await checkFill($, meant, e?.origin?.kind)
      if (!a) return { text: CHECK_FAILED }      // a command run: nothing was put into the box
      try { await $.prompt.fill({ text: a.masked }) } catch { /* the line names it */ }
      return { text: filledNote(a.masked) + maskedNote(a) }
    }
    const word = firstWord(e?.args)
    pane.hint = word ? unknownLine(word) : null
    let opened = false
    try { opened = await openSettings($) } catch { opened = false }
    if (!opened) return { text: '/maisecrets status shows the protection, /maisecrets settings the settings.' }
    takeKeysSoon($)
    // no text: a plugin command's text goes into the next request; the time goes to the pane's own line
    try { $.ui.log(`maisecrets hub: opened in ${Math.round((await $.clock.now()) - t0)} ms`, { to: 'debug' }) }
    catch { /* no log */ }
    return {}
  })
}

// ---- the second net for tool results (C2) and the hooks watch (C13)

// The PostToolUse hook masks a tool result. In Claude Code a PostToolUse hook that fails (crashes, times out, cannot
// start) does not withhold the output, also with onFailure block (that counts as exit code 2), and a session whose
// hooks never run masks nothing. The mod sees each row before it is stored and sent (session.append, the door
// tool-result) and masks a result that no PostToolUse hook of maisecrets checked, through dispatch.py mod-result.
//
// It decides from positive evidence only. While the settings hooks of PostToolUse and PostToolUseFailure run, the mod
// sets MAISECRETS_MOD_NET to `on`; the maisecrets tool-result hook then ends its additionalContext with a marker line
// (maisecrets/second_net.py): `masked MAC HASH` when it replaced the output (HASH: of that output's texts), else
// `checked MAC`, and only after it scanned a result. MAC is an HMAC-SHA256 with the key of the maisecrets home
// (second_net.net_key, mode 600; the mod gets it once from mod-result) over the kind, the call's tool_use_id, the hash
// and the rest. The mod reads the marker in the classic answer (classic.PostToolUse, which runs the settings hooks as
// `next`): only as the last line of an entry and only with the MAC it computes for that call, so a copied text, a
// marker of another call or another plugin's entry cannot stand in. It takes every marker line out, so none reaches
// the model. Per call:
//   masked:  the masked marker, no block, and the output that reaches the mod has the hash the hook gave: as it is
//   checked: the checked marker, no block, no replaced output: as it is, no Python
//   every other answer is masked: no marker (no maisecrets hook ran for this call), a block (a failed hook), a replaced
//   output with another hash or with the checked marker (another plugin's hook replaced it), PostToolUseFailure (its
//   answer cannot replace the output, anthropics/claude-code#97278), and a call with no state at all (a mod reload, a
//   hook of its own that threw, the REPL of Code Mode, which raises no classic hook or tool.call here)
//   refused: an error of a call whose start this mod saw (tool.call) and for which neither classic.PostToolUse nor
//   classic.PostToolUseFailure came: the call never ran (a PreToolUse refusal, a rule, the person's no, the engine's
//   onFailure block, this mod's pairing guard), so the row holds no output of a tool, and it goes on as it is (the
//   engine's text of a moved plugin folder and the guard's reason must reach the model when no Python can run). A call
//   that ran raises one of the two, also when the maisecrets command hooks crash, are missing or cannot start (the
//   harness: failed_output_*); its error takes the strict path. tool.call alone cannot tell: a refusal beneath it
//   returns the same { result, isError } as a tool that ran and failed (claude plugin test, Claude Code 2.1.331).
//   Limit: an error that another mod answers itself in place of the tool (its tool.call or tool.run below this one)
//   raises no classic event and passes as a refusal here
//
// Fail closed without a lock: when Python gives no well-formed answer, or this hook fails, the row is stored with the
// text WITHHELD in place of each unchecked result. The row is always stored and the turn goes on, so the session never
// waits on maisecrets for more than RESULT_MS, and the next call is checked again. Placeholders stay as they are:
// Python's masking leaves them, and a result PostToolUse masked never reaches Python.
const RESULT_MS = 20000
const POSTS_MAX = 500
const posts = new Map()        // tool_use_id -> state: what the tool-result hooks answered, the oldest first
// The form of a marker line; it counts only with the MAC of the call (verifyMark). The key lies in the maisecrets home
// and is made anew at each start of the mod. The hooks refuse a tool call that names the home, the key, its module or
// mod-result (C8, C22), and the result hook masks the key wherever it stands in a tool result, so a tool's text that
// an ordinary agent caused carries no valid marker. Limits (docs/THREAT-MODEL.md, C2 and C22): an agent that evades
// on purpose (a name built at run time, `M=mod-result; dispatch.py $M`) can read the key, and so can another plugin's
// hook, a program that runs as the person; either could then write a marker that passes.
// ` rest SHARE MODE`: the name check left a rest of this result (#105, B11), for the band below; no text of the result
const MARK_RE = /^\[maisecrets: result (checked|masked) ([0-9a-f]{32})(?: ([0-9a-f]{16}))?(?: rest (\d{1,2}) (rules|cut|whole|long))?\]$/
const CALL_ID = /^[A-Za-z0-9_-]{1,128}$/
const KEY_MS = 5000
const PASSES = new Set(['masked', 'checked'])
// tool_use_ids of the calls whose start this mod saw (tool.call), the oldest first
const calls = new Set()

function noteCalled(e) {
  const id = e?.tool_use_id
  if (typeof id !== 'string' || !id) return
  calls.delete(id)
  calls.add(id)
  if (calls.size > POSTS_MAX) calls.delete(calls.values().next().value)
}

const refused = (b) => b.is_error === true && calls.has(b.tool_use_id) && !posts.has(b.tool_use_id)
// an error result (is_error): the call may never have run (a refusal), so its text says nothing of a run
const WITHHELD_ERROR = '[maisecrets: the tool call ended with an error, but maisecrets could not check the error text, ' +
  'so it is withheld. /maisecrets status shows why.]'
const WITHHELD = '[maisecrets: the tool ran and finished, but maisecrets could not check its output, so the output ' +
  'is withheld. Do not run the tool again to see it; /maisecrets status shows why.]'
const MASKED_NOTE = '[maisecrets masked values in this tool result (its result hook did not check it). The tool ran ' +
  'and finished; use the ⟦TYPE_cN⟧ placeholders as they are.]'
const MASKED_TOAST = 'maisecrets masked values in a tool result that its result hook did not check. ' +
  '/maisecrets status shows why.'

function notePost(e, state) {
  const id = e?.tool_use_id
  if (typeof id !== 'string' || !id) return
  posts.delete(id)
  posts.set(id, state)
  if (posts.size > POSTS_MAX) posts.delete(posts.keys().next().value)
}

// The key of the marker: from Python (mod-result), 32 bytes. At each session start the mod asks for a new one
// (renewKey, the request {"net_key": "new"}), then for the current one ({"net_key": true}) when a marker does not
// verify. It stays in this process: no log, no state, no text of the model. No answer: null, and the next marker asks
// again (until then every result goes to the second net)
let netKey = null              // a promise of the key bytes or null
async function fetchKey($, fresh = false) {
  try {
    const r = await runResult($, JSON.stringify({ net_key: fresh ? 'new' : true }), KEY_MS)
    const a = r ? JSON.parse(r.stdout) : null
    if (!a || a.maisecrets !== 'mod-result' || typeof a.net_key !== 'string' || !/^[0-9a-f]{64}$/.test(a.net_key)) {
      return null
    }
    const raw = new Uint8Array(32)
    for (let i = 0; i < 32; i++) raw[i] = parseInt(a.net_key.slice(2 * i, 2 * i + 2), 16)
    return raw
  } catch {
    return null
  }
}
function keyOf($) {
  if (netKey === null) netKey = fetchKey($)
  return netKey
}
// a session starts: the key of the last one goes, so a key that stood in its output is worth nothing now
function renewKey($) {
  netKey = fetchKey($, true)
  return netKey
}

// HMAC-SHA256 (RFC 2104) from SHA-256 alone: a hooks module has crypto.subtle.digest, no importKey or sign. The key
// has 32 bytes, less than the block of 64
const sha256 = async (bytes) => new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes))
async function hmacSha256(key, message) {
  const inner = new Uint8Array(64 + message.length)
  const outer = new Uint8Array(64 + 32)
  for (let i = 0; i < 64; i++) {
    inner[i] = (key[i] ?? 0) ^ 0x36
    outer[i] = (key[i] ?? 0) ^ 0x5c
  }
  inner.set(message, 64)
  outer.set(await sha256(inner), 64)
  return sha256(outer)
}

// maisecrets/second_net.py mac: the first 32 hex digits of HMAC-SHA256(key, kind, tool_use_id, hash, rest), one line each
async function markMac(key, kind, id, hash, rest) {
  const sig = await hmacSha256(key, new TextEncoder().encode([kind, id, hash, rest].join('\n')))
  return [...sig.slice(0, 16)].map(n => n.toString(16).padStart(2, '0')).join('')
}

// a marker line (MARK_RE's match) of the call `id`: true only with the MAC of that call under the key of the home. A
// wrong MAC drops the key of this process, so a key the home made anew is asked for again at the next marker
async function verifyMark($, id, m) {
  if (typeof id !== 'string' || !CALL_ID.test(id)) return false
  const p = keyOf($)
  const key = await p
  if (!key) {
    if (netKey === p) netKey = null     // no answer: the next marker asks again
    return false
  }
  const want = await markMac(key, m[1], id, m[3] ?? '', m[4] === undefined ? '' : `${m[4]} ${m[5]}`)
  if (want === m[2]) return true
  if (netKey === p) netKey = null
  return false
}

// the marker of maisecrets in a classic answer: the last line of an entry that `verify` accepts (the MAC of this call).
// Every marker line goes out of the answer, a forged one too, so none reaches the model; only a verified one counts
async function readMarks(r, verify) {
  const ctx = r && typeof r === 'object' ? r.additionalContext : undefined
  const list = Array.isArray(ctx) ? ctx : typeof ctx === 'string' ? [ctx] : []
  let tag = null
  const kept = []
  for (const c of list) {
    const cut = typeof c === 'string' ? c.lastIndexOf('\n') : -1
    const line = typeof c === 'string' ? c.slice(cut + 1) : null
    const m = line === null ? null : MARK_RE.exec(line)
    if (!m) { kept.push(c); continue }
    let ok = false
    try { ok = tag === null && verify !== null && await verify(m) } catch { ok = false }
    if (ok) tag = { kind: m[1], hash: m[3] ?? null, rest: m[4] === undefined ? null : { share: Number(m[4]), mode: m[5] } }
    const before = cut < 0 ? '' : c.slice(0, cut).replace(/\n+$/, '')
    if (before !== '') kept.push(before)
  }
  if (ctx === undefined) return { tag, rest: r }
  const rest = { ...r }
  if (kept.length) rest.additionalContext = Array.isArray(ctx) ? kept : kept.join('\n\n')
  else delete rest.additionalContext
  return { tag, rest }
}

// the strings of an output in a fixed order, as maisecrets/second_net.py output_hash takes them
function textsOf(node, out) {
  if (typeof node === 'string') out.push(node)
  else if (Array.isArray(node)) for (const x of node) textsOf(x, out)
  else if (node && typeof node === 'object') {
    for (const k of Object.keys(node).sort()) { out.push(k); textsOf(node[k], out) }
  }
  return out
}

async function outputHash(output) {
  const bytes = new TextEncoder().encode(textsOf(output, []).join('\0'))
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes))
  return [...digest.slice(0, 8)].map(n => n.toString(16).padStart(2, '0')).join('')
}

// masked: the output that reaches the mod is the one the maisecrets hook made (its hash); checked: no hook replaced it
async function postState(tag, r) {
  if (!tag || !r || typeof r !== 'object' || r.block !== undefined) return 'unchecked'
  const updated = r.updatedToolOutput !== undefined ? r.updatedToolOutput : r.updatedMCPToolOutput
  if (tag.kind === 'checked') return updated === undefined ? 'checked' : 'unchecked'
  if (updated === undefined || !tag.hash) return 'unchecked'
  return (await outputHash(updated)) === tag.hash ? 'masked' : 'unchecked'
}

// `on` goes to the hooks only while the settings hooks of a tool result run (calls run in parallel: it stays set while
// any of them runs). It is a flag only: the proof is the MAC under the key of the home (see MARK_RE for its limits)
let marksOpen = 0
async function openMarks($) {
  marksOpen += 1
  try { void keyOf($) } catch { /* asked again at the marker */ }
  if (marksOpen === 1) await $.env.set('MAISECRETS_MOD_NET', 'on')
}
async function closeMarks($) {
  marksOpen = Math.max(0, marksOpen - 1)
  if (marksOpen === 0) await $.env.set('MAISECRETS_MOD_NET', '')
}
async function withMarks($, run) {
  try { await openMarks($) } catch { /* no marker: the second net masks the result */ }
  try { return await run() } finally {
    try { await closeMarks($) } catch { /* the next close tries again */ }
  }
}

// the texts of one tool_result block, in order: its content string, or the text of each text block in it
function resultTexts(block) {
  if (typeof block.content === 'string') return [block.content]
  if (!Array.isArray(block.content)) return []
  return block.content.filter(c => c?.type === 'text' && typeof c.text === 'string').map(c => c.text)
}

function withTexts(block, texts, note) {
  if (typeof block.content === 'string') return { ...block, content: (note ? note + '\n\n' : '') + texts[0] }
  let i = 0
  const content = block.content.map(c => (c?.type === 'text' && typeof c.text === 'string') ? { ...c, text: texts[i++] } : c)
  return { ...block, content: note ? [{ type: 'text', text: note }, ...content] : content }
}

// an unchecked result: the text WITHHELD alone, its media dropped too (a media block may be dropped, not changed)
const withheld = (block) => ({ ...block, content: block?.is_error === true ? WITHHELD_ERROR : WITHHELD })

// the tool_result blocks of a row that must go to Python: every one but those with positive evidence
function dueBlocks(e) {
  const content = Array.isArray(e?.message?.content) ? e.message.content : []
  const due = []
  content.forEach((b, i) => {
    if (b?.type === 'tool_result' && !PASSES.has(posts.get(b.tool_use_id)) && !refused(b)) due.push(i)
  })
  return due
}

// One Python start per row. The next interpreter only when this one cannot start (a rejection that names a missing
// program), exits 3 (dispatch.py on a Python older than 3.9) or 9009 (the store alias of Windows): a timeout or another
// failure ends the search, and the row is withheld
const NO_PROGRAM = /ENOENT|not found|no such file|cannot find|is not recognized/i
async function runResult($, stdin, ms = RESULT_MS) {
  const init = { cwd: $.plugin.root, stdin, timeoutMs: ms, env: { PYTHONUTF8: '1' } }
  for (const which of [0, 1, 2]) {  // python3, py -3, python (mod-result)
    let r
    try {
      r = await runEntry($, 'mod-result', which, init)
    } catch (err) {
      const why = String(err?.code ?? err?.message ?? err).slice(0, 120)
      try { $.ui.log(`maisecrets second net: ${PY_NAMES[which]} did not run (${why})`, { to: 'debug' }) } catch { /* no log */ }
      if (NO_PROGRAM.test(why)) continue
      return null
    }
    if (r.exitCode === 0) return r
    if (r.exitCode !== 3 && r.exitCode !== 9009) return null
  }
  return null
}

// Python's answer for the texts of one row: { texts, changed, note }, 'withheld', or null (no answer)
async function askResult($, session, cwd, tool, agent, texts) {
  const r = await runResult($, JSON.stringify({ session_id: session, cwd, tool_name: tool, agent_id: agent, texts }))
  let a
  try { a = r ? JSON.parse(r.stdout) : null } catch { a = null }
  if (!a || a.maisecrets !== 'mod-result') return null
  const rest = restOf(a.rest)
  if (a.withheld === true) return { withheld: true, rest }
  if (!Array.isArray(a.texts) || a.texts.length !== texts.length || !a.texts.every(t => typeof t === 'string')) {
    return null
  }
  return { texts: a.texts, changed: a.changed === true, note: typeof a.note === 'string' ? a.note : '', rest }
}

async function secondNet($, e, next) {
  const due = dueBlocks(e)
  if (!due.length) return next(e)
  let session = null
  try { session = await $.session.id() } catch { session = null }
  let cwd = ''
  try { cwd = await $.session.cwd() } catch { cwd = '' }
  const tool = typeof e?.origin?.tool === 'string' ? e.origin.tool : 'tool'
  const content = [...e.message.content]
  const parts = due.map(i => resultTexts(content[i]))
  let a = null
  let t0 = 0
  try { t0 = await $.clock.now() } catch { t0 = 0 }
  try {
    a = await askResult($, session, cwd, tool, typeof e?.agentId === 'string' ? e.agentId : null, parts.flat())
  } catch { a = null }
  try {
    const ms = Math.round((await $.clock.now()) - t0)
    $.ui.log(`maisecrets second net: ${due.length} result(s) of ${tool} checked in ${ms} ms`, { to: 'debug' })
  } catch { /* no log */ }
  if (a !== null) addRest($, a.rest)
  let at = 0
  let masked = false
  due.forEach((i, n) => {
    if (a === null || a.withheld === true) { content[i] = withheld(content[i]); return }
    const texts = a.texts.slice(at, at + parts[n].length)
    at += parts[n].length
    const changed = texts.some((t, k) => t !== parts[n][k])
    if (changed) masked = true
    const note = [changed ? MASKED_NOTE : '', a.note].filter(Boolean).join('\n\n')
    content[i] = withTexts(content[i], texts, note || null)
  })
  if (masked) toast($, MASKED_TOAST)
  return next({ ...e, message: { ...e.message, content } })
}

// The band (#105, B11): when the name check of a tool result of this turn (since the person's last prompt, parallel
// calls and subagents included) left a rest, one line above the prompt says how much was checked and where the rest
// went, for the worst such result. The share and the mode come from the marker of the result hook or from the answer
// of the second net, never a text of the result. A result without a rest never takes the line away: only the person's
// next prompt does, so a line about an old result never stands over a new question
const BAND_RANK = { whole: 0, cut: 1, rules: 2, long: 3 }          // the worse first, at the same share
const BAND_REST = { rules: 'the rest went to the AI with the rules only', cut: 'the rest was withheld from the AI',
                    whole: 'the whole result was withheld from the AI' }
let band = null                // { n: results with a rest in this turn, worst: { share, mode } }

const restOf = (r) => (r && typeof r === 'object' && Number.isInteger(r.share) && r.share >= 0 && r.share <= 99 &&
  Object.hasOwn(BAND_RANK, r.mode)) ? { share: r.share, mode: r.mode } : null

const worse = (a, b) => b.share < a.share || (b.share === a.share && BAND_RANK[b.mode] < BAND_RANK[a.mode])

function bandWhat(b) {
  if (b.mode === 'long') {
    return 'was not checked for names (too long for one request to the name service); it went to the AI with the ' +
      'rules only'
  }
  if (b.share > 0) return `was checked for names in part (${b.share} %); ${BAND_REST[b.mode]}`
  if (b.mode === 'rules') return 'was not checked for names (the name service did not answer); it went to the AI ' +
    'with the rules only'
  return 'was not checked for names; it was withheld from the AI'
}

function bandLine(state) {
  if (state.n === 1) return `maisecrets: a result of this turn ${bandWhat(state.worst)}`
  return `maisecrets: ${state.n} results of this turn were not fully checked for names; the worst ${bandWhat(state.worst)}`
}

function drawBand($) {
  // the debug log too: claude -p draws no band, and the harness reads this line (harness/run.py ner_rest_*)
  try { $.ui.log(`maisecrets band: ${band ? bandLine(band) : 'none'}`, { to: 'debug' }) } catch { /* no log */ }
  try { $.ui.invalidate('ui.render') } catch { /* the next drawing shows it */ }
}

// a result of this turn: its rest counts; a result without one changes nothing
function addRest($, rest) {
  const r = restOf(rest)
  if (r === null) return
  band = band === null ? { n: 1, worst: r } : { n: band.n + 1, worst: worse(band.worst, r) ? r : band.worst }
  drawBand($)
}

// the person's prompt: a new turn
function clearBand($) {
  if (band === null) return
  band = null
  drawBand($)
}

function registerBand(on) {
  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (band === null || e.props?.hasSurvey) return next(e)
    const { Text } = $.ui.resolve(e)
    return h(Text, { color: 'warning', wrap: 'truncate-end' }, bandLine(band))
  })
}

// The hooks watch: the mod runs without the hooks. A person's prompt that the settings hooks of UserPromptSubmit let
// through (classic.UserPromptSubmit, which runs them as `next`, so only a prompt the hook gets: no slash command the
// hook does not see, no /clear, no prompt the mod dropped or answered) must leave a row of the prompt hook in hooks.log.
// WATCH_MS later the mod asks Python (status_verdict.hooks_watch). No row: one line, once per session. No answer, or
// Cowork: nothing. A session whose row came is not asked again. A row any program wrote silences the watch, never the
// second net above: that reads the marker of the hook itself
const WATCH_MS = 1500
const HOOKS_LINE = 'maisecrets hooks did not run in this session: values are not protected; run /maisecrets status'
const promptHookSeen = new Set()
const watchTold = new Set()

function watchHooks($, session, since) {
  if (typeof session !== 'string' || !session || promptHookSeen.has(session) || watchTold.has(session)) return
  $.clock.after(WATCH_MS, async () => {
    const a = await askEntry($, { action: 'hooks_ran', session_id: session, since })
    if (a?.ran === true) { promptHookSeen.add(session); return }
    if (a?.ran !== false || watchTold.has(session)) return
    watchTold.add(session)
    try { $.ui.log(HOOKS_LINE) } catch { /* a line for the person only */ }
  })
}

// A hook answer the classic chain of the mod does not see (measured on 2.1.330: in Code Mode the REPL's own
// PostToolUse) reaches the session as a context row (door hook-context, name hook_additional_context) with the marker
// in it: the marker line, and the label it alone filled, go out of each such row, so the model never reads it. The
// REPL's result then has no state and is masked
const unmarkedLine = (l) => !MARK_RE.test(l.replace(/^[^\n]{0,80} hook additional context: /, ''))
const hasMark = (t) => t.includes('[maisecrets: result ') && !t.split('\n').every(unmarkedLine)
const unmarked = (t) => {
  if (!hasMark(t)) return t
  return t.split('\n').filter(unmarkedLine).join('\n').replace(/\n{3,}/g, '\n\n').replace(/^\n+|\n+$/g, '')
}

function contextWithoutMarks(e, next) {
  const content = Array.isArray(e?.message?.content) ? e.message.content : null
  if (e?.message?.name !== 'hook_additional_context' || !content ||
      !content.some(b => b?.type === 'text' && typeof b.text === 'string' && hasMark(b.text))) {
    return next(e)
  }
  const kept = content.map(b => (b?.type === 'text' && typeof b.text === 'string') ? { ...b, text: unmarked(b.text) } : b)
  return next({ ...e, message: { ...e.message, content: kept } })
}

// a classic hook of the mod only reads: when it fails, what the settings hooks answered stands, without the marker.
// Not called yet: the settings hooks run now, once, with the flag; called: next(e) replays what they answered (no
// second run). Either way the call keeps no state, so the second net masks its result
async function relayClassic($, e, next) {
  const r = next.called ? await next(e) : await withMarks($, () => next(e))
  return (await readMarks(r, null)).rest
}

// the result as the tool gave it, before the maisecrets hook masked it: a reference of a server that is not bound yet
// is masked whole there (placeholder.whole_references), and the connector that showed it must still be asked (#91).
// A string test only; a failure of its own never reaches the answer
function referencesOf(e, output) {
  try { noteReferences({ tool: e?.tool_name }, output) } catch { /* no offer */ }
}

function registerSecondNet(on) {
  on('classic.PostToolUse', async ($, e, next) => {
    referencesOf(e, e?.tool_response)
    const r = await withMarks($, () => next(e))
    const { tag, rest } = await readMarks(r, (m) => verifyMark($, e?.tool_use_id, m))
    try {
      const state = await postState(tag, r)
      notePost(e, state)
      // a result that passes: its own rest, or none; any other goes to the second net, whose answer sets the band
      if (PASSES.has(state)) addRest($, tag.rest)
    } catch { /* no state: the row is masked */ }
    return rest
  }).catch(relayClassic)
  on('classic.PostToolUseFailure', async ($, e, next) => {
    referencesOf(e, e?.error)
    const r = await withMarks($, () => next(e))
    try { notePost(e, 'failure') } catch { /* no state: the row is masked */ }
    return (await readMarks(r, null)).rest
  }).catch(relayClassic)
  on('session.append', { door: 'tool-result' }, secondNet).catch(async ($, e, next) => {
    // the hook threw or ran out of its budget: a row it passed on stays; one it did not goes on withheld
    if (next.called) return next(e)
    const content = Array.isArray(e?.message?.content) ? e.message.content : []
    return next({ ...e, message: { ...e.message, content: content.map(b => b?.type === 'tool_result' ? withheld(b) : b) } })
  })
  on('session.append', { door: 'hook-context' }, async ($, e, next) => contextWithoutMarks(e, next))
    .catch(async ($, e, next) => next(e))
  on('classic.UserPromptSubmit', async ($, e, next) => {
    let at = null
    try { at = (await $.clock.now()) / 1000 } catch { at = null }
    const r = await next(e)
    // a blocked prompt went nowhere, and the person sees the block
    try { if (at !== null && (!r || r.block === undefined)) watchHooks($, e?.session_id, at) } catch { /* no line */ }
    return r
  }).catch(relayClassic)
}

export function register(on) {
  registerSecondNet(on)
  registerBand(on)
  // a hidden command the person typed (`/maisecrets:status`, the form of 0.9.21 and before): it runs as typed
  on('command.run', async ($, e, next) => {
    const name = typeof e?.command === 'string' && e.command.startsWith('maisecrets:') ? e.command.slice(11) : ''
    if (!HIDDEN.includes(name) || !RUN_ORIGINS.has(e?.origin?.kind)) return next(e)
    const args = typeof e.args === 'string' ? e.args.trim() : ''
    return await runTyped($, `/maisecrets:${name}${args ? ' ' + args : ''}`)
  })
  registerDemo(on)
  // the values on the person's screen (the part above): one hooks module per plugin, so it registers from here
  registerShowValues(on)
  registerSettingsPane(on)
  on('prompt.submit', async ($, e, next) => {
    noteSession($)          // before every check below: a slash line and another origin count too
    // a pairing runs: its nonce in any prompt taints it (#91)
    if (pairings.size > 0) try { notePairingUse(String(e?.text ?? ''), null) } catch { /* the pairing goes on */ }
    const person = PERSON.has(e.origin?.kind)
    if (person) clearBand($)         // a new turn: the band names the results of this one only (#105)
    // `/maisecrets demo on`, typed by the person, is `/maisecrets:demo on`: the steps below read `own`, the colon
    // form, with the person's origin as it came, so it has the same path and checks as the colon form and no more. Any
    // other origin keeps its text (the hook path, and the menu command only fills the box)
    const meant = person ? meantCommand(e.text) : null
    const own = meant ?? e.text
    // only the demo command changes whether a session is in the demo: the next model step asks again then. A demo
    // session is left only with /clear, a new session id, which asks anew
    if (DEMO_CMD.test(own ?? '')) {
      try { demo.delete(await $.session.id()) } catch { /* the step asks */ }
    }
    // a demo answer Python gave for an earlier prompt is never shown for this one (the hook may block this prompt, and
    // no step then takes it): only this prompt's answer sets it again below
    try { demoShow.delete(await $.session.id()) } catch { /* the step shows the demo line */ }
    if (!person && e.origin?.kind === 'task-notification' && String(e.text ?? '').includes('<summary>MCP task ')) {
      return await taskResult($, e, next)
    }
    if (!person) return next(e)
    afterPrompt($, own)
    const near = meant ? null : nearCommand(e.text)
    if (near) {
      // a mistyped name: the engine puts a dropped prompt back into the box, and the closest command goes there once
      // the drop landed. The person's Enter sends it
      return await offer($, e, near)
    }
    const asked = SETTINGS_CMD.exec(own)
    const kind = e.origin?.kind
    if (asked) {
      pane.hint = null
      // the panel in place of the text view; the command never renders, so the model gets no turn
      let opened = false
      const t0 = await $.clock.now()
      try { opened = await openSettings($) } catch { opened = false }
      if (opened) {
        takeKeysSoon($)
        try { $.ui.log(`maisecrets hub: opened in ${Math.round((await $.clock.now()) - t0)} ms`, { to: 'debug' }) }
        catch { /* no log */ }
        return { drop: 'maisecrets: the panel is open. Esc closes it.' }
      }
    }
    if (OWN_SLASH.test(own) && !DEMO_CMD.test(own)) {
      let shown = null
      try { shown = await ownInDemo($, own, kind) } catch { shown = null }
      if (shown !== null) return { drop: showOwn($, shown) }
    }
    let ownAnswer = null      // Python's answer to an own-command shape: the steps below use it, not a second ask
    // a command that the mod runs itself (0.9.19): only the person's own prompt typed or sent through Remote Control;
    // the space form runs as its colon form `own`, with the colon form's checks
    const runnable = RUN_ORIGINS.has(kind) && RUN_CMD.test(own)
    const ownCmd = OWN_CMD.test(own)
    if (ownCmd || runnable) {
      const done = await runOwn($, own, kind, runnable, ownCmd, true, MS_TYPED.test(e.text), ENTRY_LINE.test(e.text))
      if (done.pass) return next(e)
      if (done.drop !== undefined) return { drop: done.drop }
      ownAnswer = done.answer
      // no command of the mod's: the steps below, as for any prompt (a slash command goes on to its command file)
    }
    // an entry form the mod did not answer (Cowork, where the command file shows the output) goes on as typed: the
    // engine throws away a change of a slash line (#44), and the prompt hook reads the line as its colon form. A text
    // answer is no use here, so Python gives none for a slash line in Cowork (sref runs there in its text form)
    if (SLASH.test(e.text)) return next(e)
    if (CHECK.test(e.text)) {
      // a check of a value is never passed on: the verdict, or this sentence when Python gives none in time
      let verdict = null
      try {
        verdict = await ask($, e.text, await $.session.id(), await $.session.cwd(), e.origin?.kind)
      } catch {
        // the sentence below
      }
      if (verdict && typeof verdict.drop === 'string') return { drop: verdict.drop }
      return { drop: 'maisecrets could not check this value. Nothing was sent.' }
    }
    let answer = null
    try {
      answer = ownAnswer !== null ? takeAnswer(ownAnswer, await $.session.id())
        : await ask($, e.text, await $.session.id(), await $.session.cwd(), e.origin?.kind)
    } catch {
      // the hook decides it
    }
    // a prompt of a session out of the demo: the client's next-prompt guess comes back (only if the demo switched it)
    try { if (demo.get(await $.session.id()) === false) await loudAgain($) } catch { /* it stays off */ }
    // a drop (a damaged demo state): never sent
    if (answer && typeof answer.drop === 'string') return { drop: answer.drop }
    if (!answer || typeof answer.text !== 'string') return next(e)
    // the demo: the masked prompt enters as the person's row; its model steps are answered above, none is sent
    if (answer.demo === true) {
      await quietForTheDemo($)
      try { if (typeof answer.show === 'string') demoShow.set(await $.session.id(), answer.show) } catch { /* the line */ }
      // one line: what was masked, and once per session that names were not checked (maisecrets/demo.py)
      try {
        const id = await $.session.id()
        const parts = []
        if (typeof answer.masked === 'string' && answer.masked) parts.push(answer.masked)
        if (answer.namesUnchecked === true && !namesTold.has(id)) { parts.push('names: not checked'); namesTold.add(id) }
        if (parts.length) $.ui.log(`demo · ${parts.join(' · ')}`)     // the client leads it with "maisecrets:"
      } catch { /* a line for the person only */ }
      return next({ ...e, text: answer.text })
    }
    try {
      // count 0: the prompt goes on as typed, with a note (the name service did not check it)
      if (answer.count > 0) $.ui.log(`maisecrets masked ${answer.count} value(s) before the prompt was sent`)
      // once: the line that names ms:(…), a check of a value that never reaches the model (hooks._check_tip)
      if (typeof answer.tip === 'string') $.ui.log(answer.tip)
    } catch {
      // a line for the person only; the rewrite does not depend on it
    }
    return next({ ...e, text: answer.text })
  }).catch(async ($, e, next) => {
    // the hook above threw or timed out before it passed the prompt on: the prompt goes on unchanged,
    // to the settings hook, which decides it as without the mod. A person's check is never passed on
    if (PERSON.has(e.origin?.kind) && CHECK.test(e.text)) {
      return { drop: 'maisecrets could not check this value. Nothing was sent.' }
    }
    if (!next.called) return next(e)
    // it failed after it had passed the prompt on: nothing is sent a second time
    return { drop: 'maisecrets could not finish its check of this prompt. Send it again.' }
  })
}
