# Slack responses: 0.8.17 against 0.8.18

`findings_by_leaf` (layout lines, the ai-gateway's configuration: regions de, its default languages, no sources) on
two generated Slack responses (`bench/slack_speed.py`, synthetic values only):

- `slack_prod_45`: 45 messages with rich-text blocks (text, user mentions, links, emoji), user profiles and reactions.
- `slack_prose_90`: 90 messages of 50 words each, the text once in `text` and once in `blocks`.

| Response | 0.8.17 (98281e31) | 0.8.18 (ee5efeed) | Ratio | 0.8.18 faster in |
|---|---:|---:|---:|---|
| slack_prod_45 | 7.758 µs/char | 5.539 µs/char | 0.714 | 15 of 15 rounds |
| slack_prose_90 | 3.807 µs/char | 1.440 µs/char | 0.378 | 15 of 15 rounds |

Median of 15 rounds; each round runs both versions in turns, and each value is the median of 7 calls of CPU time
(`time.process_time`) divided by the characters of the response's strings. Raw lines: `ab.log`.

Host: netcup RS 2000 G12, AMD EPYC 9645 (Zen 5), 8 vCPU, one core (`taskset -c 4`), Debian 13, Python 3.13.5; no CI
build and load 0.33 at the start, no build at the end. Run on 2026-11-04 with
`bash bench/slack_speed_ab.sh <v0.8.17 worktree> <v0.8.18 worktree> 15`.
