# The JSON benchmark: personal data and secrets in API responses

Status: version 1 (2026-11-04). `bench/json_bench.py`, responses from `bench/json_shapes.py`.

**What this benchmark is, and what it is not.** It compares tools on parsed API responses, the input of a gateway or of
a library user that holds a response as an object. This project chose the four shapes, the fields, the values and the
expected classes, and it saw maisecrets while it wrote them; another tool's maintainer would choose differently. Read
the numbers as a measurement of these shapes, not as independent evidence of a ranking.

## The responses

Four shapes, after the public API documentation of each service, 40 responses each, half English and half German:

| Shape | What it holds |
|---|---|
| `jira_issue` | reporter, assignee and comment author (display name, address), an IBAN in a custom field, a description in the Atlassian document format with a name, a phone number or a token in a node of its own, a comment with a phone number |
| `gitlab_mr` | author and reviewer (name, user name), a description with a token after its label, commit hashes |
| `slack_history` | six messages, each with a user profile (real name) and its text twice (`text` and `blocks`), some with an address, a phone number or a token after its label |
| `graph_users` | four users: display, given and family name, mail, principal name, mobile and business phones, street |

Every value is synthetic (`bench/structvalues.py`); mail domains are made up at run time, because maisecrets leaves
example.com and example.org alone on purpose (a test value) and another tool does not.

## The tools, each in its own mode

| Tool | Mode |
|---|---|
| maisecrets record | `leaves.findings_by_leaf(detector, obj)`, regions generic, de, us |
| maisecrets text | the response as JSON text through the bench adapter |
| Presidio text | presidio-analyzer 2.2.364 on the JSON text (en_core_web_lg) |
| Presidio structured | presidio-structured 0.0.10 (`JsonAnalysisBuilder`): one entity per key. It refuses a list of objects (`ValueError`), so each response is cut at its lists into list-free parts, each analysed alone |
| pii-anon text | pii-anon 1.7.0rc1 on the JSON text |
| detect-secrets text | detect-secrets 1.5.0 on the JSON text (secrets only) |

A finding in JSON text belongs to the string its first character stands in.

## The score

Per string field and class: a class the field holds and the tool names there is found; one it misses is missed; one it
names that the field does not hold is a false alarm. Timing: CPU time of the scan per response, in each tool's own
process; `cpu_ms_per_kb` is the sum over all responses per KB of JSON.

## Run

```bash
BENCH_PRESIDIO_PYTHON=… BENCH_PII_ANON_PYTHON=… BENCH_DETECT_SECRETS_PYTHON=… python3 bench/json_bench.py OUT --n 40
```

Results: `bench/results/<date>-json-<version>/`.
