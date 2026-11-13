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

async function runValues($, stdin) {
  // the same Pythons as the prompt path, fixed command lines (runDispatch below)
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
        (names ? 'A click copies the value.' : docker ? '💡 To find names too: /maisecrets:ner local (a local model).'
          : '💡 A name it missed? /maisecrets:term add NAME'), { timeoutMs: 15000 })
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
    for (const argv of [['python3', 'hooks/dispatch.py', 'mod-reveal'], ['py', '-3', 'hooks/dispatch.py', 'mod-reveal'],
      ['python', 'hooks/dispatch.py', 'mod-reveal']]) {
      try {
        r = await $.process.run(argv, init)
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
    try {
      if (await askValues($, [])) $.ui.invalidate('ui.render')
    } catch { /* off until an answer */ }
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
    if (r.exitCode === 0) return r
  }
  return null
}

async function ask($, prompt, session, cwd, origin) {
  // origin: the hook takes a {{name}} marker only from a prompt the person typed (composer, bridge)
  const r = await runDispatch($, JSON.stringify({ prompt, session_id: session, cwd, origin }))
  if (!r) return null
  const answer = JSON.parse(r.stdout)
  if (!answer || answer.maisecrets !== MARK) return null
  if (typeof answer.text !== 'string' && typeof answer.drop !== 'string') return null
  return answer
}

export function register(on) {
  // the values on the person's screen (the part above): one hooks module per plugin, so it registers from here
  registerShowValues(on)
  on('prompt.submit', async ($, e, next) => {
    if (!PERSON.has(e.origin?.kind)) return next(e)
    afterPrompt($, e.text)
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
      answer = await ask($, e.text, await $.session.id(), await $.session.cwd(), e.origin?.kind)
    } catch {
      // the hook decides it
    }
    if (!answer || typeof answer.text !== 'string') return next(e)
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
