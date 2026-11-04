# AI security review

An optional, local-only review that helps you understand HTTP and JavaScript
security risks in content Devils Eyes is authorized to collect. You can correct
inaccurate analyses, and owners can approve corrections as **project memory**.

> Approved examples can guide future reviews in this project. This does not
> retrain the model.

Project memory means saved, approved examples are retrieved into the model's
context for later reviews of the same project. Nothing is trained or fine-tuned,
and the model's weights never change. Delete or disable an example and it stops
being used.

The feature is **off by default**. With AI disabled, unavailable, slow or broken,
scanning, continuous monitoring, findings, alerts, the dashboard and the
terminal behave exactly as before.

## What it can and cannot see

Every review says which sources it used, for example "This review is based on
the HTML of 1 page and 4 in-scope scripts. Server-side code is not visible to
scans."

| Source | When it is available | Label in the UI |
| --- | --- | --- |
| Stored scan evidence | Always: URLs, status codes, titles, the few headers scans keep, existing findings | stored scan evidence |
| Page security headers | After a **Collect for AI review** run | page headers from a collection run |
| Page HTML and inline scripts | Only when the project owner turns on **response-body retention** | page HTML kept because response-body retention is on |
| In-scope scripts | Fetched by a **Collect for AI review** run | in-scope script fetched by a collection run |
| Third-party or out-of-scope scripts | Never fetched; host, path, integrity attribute and version hints are recorded | reference only |
| Source maps | Only when the owner turns on **source maps** and the map URL is in scope | recovered from an in-scope source map |
| Repository or server source code | Not available. A website scan never exposes backend source code | - |

Reviews are static: downloaded JavaScript is tokenized, never executed,
evaluated or rendered.

## Setup

### 1. A local model (your choice)

Devils Eyes never downloads models and never uses an external AI provider.
Installing [Ollama](https://ollama.com) and a model is up to you, for example:

```bash
ollama pull qwen3:8b-q4_K_M     # about 5 GB; fits an 8 GB GPU comfortably
ollama pull qwen3:14b-q4_K_M    # about 9 GB; better answers, slower on 8 GB GPUs
```

Hardware expectations: an 8B model at 4-bit runs at interactive speed on a GPU
with 8 GB of memory. A 14B model on the same GPU partly runs on the CPU and is
several times slower. CPU-only machines work but expect minutes per chunk.
`ai.num_ctx` (default 8192) is the context window; larger windows need more GPU
memory.

### 2. Reaching the model from Ubuntu on WSL

Ollama on Windows is not always reachable at WSL's `localhost`. Choose one:

* **Ollama inside Ubuntu.** `ai.endpoint` stays `http://127.0.0.1:11434`.
* **WSL mirrored networking.** Add `networkingMode=mirrored` under `[wsl2]` in
  `%UserProfile%\.wslconfig`, run `wsl --shutdown`, and `localhost` works.
* **The Windows host address.** On Windows, set `OLLAMA_HOST=0.0.0.0` and
  restart Ollama. Then allow only WSL through the firewall (PowerShell as
  Administrator):

  ```powershell
  New-NetFirewallRule -DisplayName "Ollama from WSL only" -Direction Inbound -Protocol TCP -LocalPort 11434 `
    -RemoteAddress 172.16.0.0/12 -InterfaceAlias "vEthernet (WSL (Hyper-V firewall))" -Action Allow
  ```

  Then set `ai.endpoint = "http://windows-host:11434"` and confirm it is your own
  machine with `ai.allow_private_endpoint = true`. The `windows-host` name means
  "the Windows host as seen from WSL". Its address changes between reboots, so it
  is looked up each time.

### 3. Turn it on

Settings come from the profile (`config/profiles/<profile>.toml`, section
`[ai]`) or the environment (`.env`):

```bash
WATCHTOWER__AI__ENABLED=true
WATCHTOWER__AI__ENDPOINT=http://windows-host:11434
WATCHTOWER__AI__ALLOW_PRIVATE_ENDPOINT=true
WATCHTOWER__AI__MODEL=qwen3:8b-q4_K_M
```

Apply the database migration (`0004`) once, then check the connection:

```bash
watchtower --project <slug> ai check
```

Choose `ai.model` from the installed models that the check lists. The name
must match exactly. The check suggests Qwen3 models when they are installed.

## Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Master switch. When false, only pre-analysis-only reviews run |
| `endpoint` | `http://127.0.0.1:11434` | Loopback, or a private address confirmed with `allow_private_endpoint`. Public hosts, other schemes and URLs with credentials are refused |
| `allow_private_endpoint` | `false` | Your confirmation that a LAN or WSL host address is your own machine |
| `model` | `qwen3:8b-q4_K_M` | Exact installed model name; verified before every use |
| `request_timeout_seconds` / `connect_timeout_seconds` | 180 / 5 | Per model call |
| `num_ctx`, `max_output_tokens`, `temperature`, `thinking` | 8192, 1536, 0.1, off | Sent explicitly with every request |
| `max_concurrent_analyses` | 1 | Analyses running at once across all AI workers |
| `max_files`, `max_file_bytes`, `max_total_bytes` | 20, 512 KiB, 4 MiB | Per collection and review |
| `max_chunks`, `max_review_seconds`, `max_fetch_depth` | 24, 1800, 1 | Per review; depth 1 fetches scripts the page references, 2 also their static imports |
| `max_examples`, `example_token_budget` | 3, 800 | Project memory retrieved per chunk |
| `retention_days` | 30 | Collected scripts and retained bodies are not read after this |

Per-project switches (owner only, audited) are under **Advanced** in the terminal
and dashboard, or `watchtower ai settings`:

* `retain_response_bodies`: keep page HTML and inline scripts for review.
* `allow_source_maps`: fetch in-scope source maps.
* `memory_require_second_reviewer`: an owner cannot approve their own submission.
* `review_changed_scripts`: after each continuous-monitoring scan, collect and
  review again. Unchanged code is served from the review cache, so only new or
  changed scripts reach the model.

## Using it

**Terminal:** Home > **a) AI security review**:

* **Review latest scan** reviews stored scan evidence plus the latest
  collection.
* **Collect scripts for review** (operator) collects in-scope pages and scripts,
  then optionally reviews them.
* **View results**, **Give feedback**, **Memory awaiting approval** (owner),
  **Approved examples**, **Model status** and **Advanced** do what their names
  say.

Every review first shows **Preview what will be sent**: files, sizes,
redactions and a token estimate. Collections and analyses run in the usual
separate window. Analysis runs in its own worker process, which can reach only
the database and the local model.

**Dashboard:** **AI Review** lists results with state, candidate counts and the
outdated flag. A review shows what was and was not visible, the evidence with
verified quotes highlighted, the claim types, the examples used and why, and
the feedback form.

**CLI:**

```bash
watchtower ai status | check | settings
watchtower ai collect --url https://www.example.com/ --review
watchtower ai preview ; watchtower ai review [--no-model] [--finding ID]
watchtower ai results ; watchtower ai show REVIEW
watchtower ai feedback CANDIDATE --kind false_positive --reason "..." [--memory]
watchtower ai memory list|show|approve|reject|edit|disable|enable|supersede ...
watchtower-worker ai            # the AI analysis worker
```

**API:** `/api/v1/projects/{id}/ai/...` (`status`, `check`, `settings`,
`collections`, `preview`, `reviews`, `candidates/{id}/feedback`, `memory`).

## What a result means

* **Pre-analysis facts** come from deterministic static checks run before any
  model call, with file and line locations. They cover endpoints, libraries
  matched against your advisory data, storage, auth code, dangerous sinks with
  source-to-sink hints, security headers, and secret-like values. They show
  even when AI is off or fails.
* **Candidates** come from the model. Each needs exact quotes from the reviewed
  content, and each quote is verified against the stored, redacted content.
  Quotes that cannot be found are removed and the candidate is flagged
  *citation not verified*. A candidate with no verified evidence is shown as
  **unsupported**, not as an issue.
* **Claim types:**
  * *observed fact*: visible in the quoted code.
  * *model inference*: the model's reasoning.
  * *user-reviewed conclusion*: someone marked it as looking correct.
  * *verified by an existing check*: a related finding exists, which is linked.
* **Suggested severity** is an unverified suggestion and is never written to
  findings. Candidates are never promoted to findings and never change one.

## Feedback and approval

For each candidate you can mark **Looks correct** (your review, not a
verification), **False positive** (a reason is required), or **Edit analysis**.
Tick **Submit as a project-memory example for approval** to propose it as an
example. Feedback never changes the finding's workflow status. The existing
finding actions remain the only way to triage or resolve.

Owners approve, reject, edit, disable, re-enable or supersede examples:

* **Self-approval** is a separate, explicit action and is recorded as
  *self-approved*. Projects can require a second reviewer instead.
* **History:** edits create new revisions, and the full history is kept.
* **Outdated reviews:** when an example that a review used is approved,
  edited or disabled, that review is marked *may be outdated*. Request a
  reanalysis to refresh it. The old result is never rewritten.

Retrieval stays within the project and uses approved examples only. It checks
the requester's access again at review time. An example applies only when its
category matches *and* a specific condition matches: the same code, most of its
identifiers, its path pattern, or a compatible library version. Examples that
disagree about the same code are withheld and flagged for the owner.

Roles:

* **Viewer:** reads reviews, evidence summaries and approved examples.
* **Operator:** also requests collections and reviews, and gives feedback.
* **Owner:** also approves and manages examples and changes AI and retention
  switches.

Every change is audited.

## Privacy and redaction

Content is redacted before it is stored and again before it reaches the model.
That covers private keys, cloud and API key formats, JWTs, bearer tokens,
credentials in URLs, and literal values assigned to secret-like names. Code
that only *refers* to a secret, such as `localStorage.getItem("token")`, stays
readable, because that is what a review must see. Cookies, `Authorization` and
session headers are never kept.

A review notes where redaction limits it. The original content is never
stored. Its SHA-256 and an offset map let citations point back to it.

Prompts mark all website content, examples and user notes as untrusted data
between random per-request delimiters, and tell the model to ignore
instructions inside them. The model gets no tools and no actions, and its
output can only become stored data. Scope, destinations, budgets, permissions
and redaction are enforced in application code, never by the prompt.

## Limitations

* Static analysis only: no execution, no browser and no server-side view.
  Absence of a candidate is not proof of safety.
* Models make mistakes, which is why every answer is validated and
  citation-checked and nothing becomes a finding.
* Large files are split into chunks. When budgets, time or the context window
  run out, a review is **partial** and lists what was left out and why.
  Cancellation keeps the chunks already reviewed.
* Without response-body retention, inline scripts and page HTML are not
  reviewed.
* Scans keep only a few headers. CSP, framing and CORS checks need a
  collection run.

## Troubleshooting (connection check)

| Message | What to do |
| --- | --- |
| **Disabled** | Set `WATCHTOWER__AI__ENABLED=true`. Pre-analysis-only reviews work without it |
| **Refused by policy** | The endpoint is public, reserved, has a path or credentials, or is private without `allow_private_endpoint = true`. Use loopback or confirm your own private address |
| **Unreachable** | Start Ollama (`ollama serve`) and check the address and port. On WSL, see the networking options above. On Windows, check `OLLAMA_HOST` and the firewall rule |
| **Timeout** | The server is busy or loading a model. Retry, or raise `connect_timeout_seconds` / `request_timeout_seconds` |
| **Malformed** | Something other than the Ollama API answered. Check the port (usually 11434) |
| **Model missing** | Pick one of the installed models listed by the check for `ai.model`, or install one yourself with `ollama pull` |
| **Ready** | Reviews can use the model. A warning appears if `num_ctx` exceeds what the model was trained for |

## Evaluation

`python -m watchtower.services.ai.evaluate tests/ai/eval/fixtures --recorded FILE --memory`
replays recorded model answers for the lab fixtures. Each fixture is a
vulnerable or safe script, with expectations kept outside what the model sees.
It reports matched issues, false positives, missed issues, unsupported
candidates and the citation verification rate, with and without project
memory. `--record FILE` asks your configured local model instead and saves its
answers. Reported numbers come only from runs that were actually performed.
