// maisecrets as a Claude Code mod (Claude Code 2.1.287 and later). A prompt with a secret or
// personal data goes through with placeholders in place of the values, instead of being blocked
// and sent again. The detection is the plugin's own (hooks/dispatch.py mod-prompt), not a copy.
//
// The settings hook in hooks/hooks.json stays the gate. It runs after this mod, on the text the
// mod passes on. Whenever the mod gives no rewrite (it does not load, the launcher fails, the
// answer has another shape, the hook times out), the prompt reaches that hook unchanged and the
// hook blocks it as without the mod. So no path here may pass on a value.

const MARK = 'mod-prompt'
// a person's own prompt: typed or queued at the terminal, sent through Remote Control, or the turn of
// claude -p. A subagent's report or a channel's message stays with the settings hook (C19)
const PERSON = new Set(['composer', 'bridge', 'sdk'])
// a message of another Claude session (SendMessage): no person sends it again after a block, so a block lost it
// without a word (2026-10-21: the sender saw it delivered, the model never saw it). It is rewritten as a prompt is;
// it is never a check of a value, and its {{name}} markers stay text (the hook takes them only from a person)
const PEER = new Set(['peer', 'peer-send-message'])
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
  on('prompt.submit', async ($, e, next) => {
    const person = PERSON.has(e.origin?.kind)
    if (!person && !PEER.has(e.origin?.kind)) return next(e)
    if (!person && CHECK.test(e.text)) return next(e)       // the settings hook blocks a peer's check
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
      $.ui.log(`replaced ${answer.count} value(s) with placeholders before the prompt was sent`)
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
