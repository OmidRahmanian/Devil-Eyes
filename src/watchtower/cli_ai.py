"""``watchtower ai ...``: AI review from the terminal, through the same service and permission checks as the API.

    watchtower ai status | check | settings [--retain-bodies on|off ...]
    watchtower ai collect [--url URL] [--review] [--no-model]
    watchtower ai preview | review [--run RUN] [--no-scan] [--no-model] [--finding ID]
    watchtower ai results | show ANALYSIS
    watchtower ai feedback CANDIDATE --kind looks_correct|false_positive|edit [--reason ...] [--memory]
    watchtower ai memory list|show|approve|reject|edit|disable|enable|supersede ...

Website content in results is printed with control characters escaped.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from typing import Any
from uuid import UUID

from watchtower.api import schemas
from watchtower.cli import App, CliError, context, safe, table, when
from watchtower.services.ai import MEMORY_SENTENCE
from watchtower.services.ai.preanalysis import CATEGORIES, CATEGORY_LABELS
from watchtower.services.ai.service import AiService

SWITCHES = {"retain_bodies": "retain_response_bodies", "source_maps": "allow_source_maps",
            "second_reviewer": "memory_require_second_reviewer", "review_changed": "review_changed_scripts"}
STATUS_COLOURS = {"completed": "green", "partial": "yellow", "failed": "red", "cancelled": "grey", "queued": "cyan",
                  "running": "cyan"}


def _service(app: App) -> AiService:
    from watchtower.api.storage import default_evidence_root
    from watchtower.services.evidence_store import FilesystemBlobStore
    return AiService(app.database, app.scope, app.settings, blobs=FilesystemBlobStore(default_evidence_root(app.settings)))


def _dump(value: Any) -> str:
    return json.dumps(value, indent=2, default=str, ensure_ascii=True)


def _with_run(result: dict[str, Any]) -> dict[str, Any]:
    return {**result, "run": schemas.run_out(result["run"]).model_dump(mode="json")}


def cmd_status(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    status = _service(app).status(ctx.project_id, actor=ctx)
    if args.json:
        app.say(_dump(status))
        return 0
    app.say(f"AI review: {app.style('enabled', 'green') if status['enabled'] else app.style('disabled', 'grey')}")
    app.say(f"  endpoint {safe(status['endpoint'])}  model {safe(status['model'])}  context {status['num_ctx']} tokens")
    for key, value in status["project"].items():
        app.say(f"  {key.replace('_', ' ')}: {'on' if value else 'off'}")
    memory = status["memory"]
    waiting = f", {memory['awaiting_approval']} awaiting approval" if memory["awaiting_approval"] is not None else ""
    app.say(f"  project memory: {memory['approved']} approved example(s){waiting}")
    app.say(f"  {MEMORY_SENTENCE}")
    return 0


def cmd_check(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    report = _service(app).check(ctx.project_id, actor=ctx)
    if args.json:
        app.say(_dump(report))  # the outcome is in the JSON; scripts read "ready"
        return 0
    colour = "green" if report["ready"] else ("grey" if report["outcome"] == "disabled" else "red")
    app.say(f"{app.style(report['outcome'].upper().replace('_', ' '), colour)}: {safe(report['message'])}")
    if report["endpoint"]:
        app.say(f"  endpoint {safe(report['endpoint'])} {('(' + report['endpoint_kind'] + ')') if report['endpoint_kind'] else ''}")
    if report["installed_models"]:
        app.say("  installed models: " + ", ".join(safe(m) for m in report["installed_models"]))
    for line in report["guidance"]:
        app.say("  " + safe(line))
    return 0 if report["ready"] else 5


def cmd_settings(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    service = _service(app)
    changes = {column: getattr(args, flag) == "on" for flag, column in SWITCHES.items() if getattr(args, flag)}
    result = service.update_settings(ctx.project_id, changes, actor=ctx) if changes else \
        service.status(ctx.project_id, actor=ctx)["project"]
    if args.json:
        app.say(_dump(result))
        return 0
    for key, value in result.items():
        app.say(f"{key.replace('_', ' ')}: {'on' if value else 'off'}")
    return 0


def cmd_collect(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    result = _with_run(_service(app).request_collection(
        ctx.project_id, actor=ctx, targets=args.target or None, urls=args.url or None, review=args.review,
        use_model=not args.no_model, idempotency_key=args.idempotency_key))
    if args.json:
        app.say(_dump(result))
        return 0
    app.say(f"Queued collection run {result['run']['run_id']}" +
            (f" with review {result['analysis_id']}" if result["analysis_id"] else "") + ".")
    app.say("It fetches in-scope pages and scripts only; third-party scripts are recorded, not fetched.")
    return 0


def _review_options(args: argparse.Namespace) -> dict[str, Any]:
    return {"run_id": UUID(args.run) if args.run else None, "source_ids": args.source or None,
            "include_scan": not args.no_scan, "finding_id": UUID(args.finding) if args.finding else None}


def cmd_preview(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    plan = _service(app).preview(ctx.project_id, actor=ctx, **_review_options(args))
    if args.json:
        app.say(_dump(plan))
        return 0
    app.say(safe(plan["visible"]))
    table(app.out, [[f["kind"], safe(f["url"])[:70], str(f["size_bytes"]), str(f["redactions"]),
                     "yes" if f["sent"] else "no"] for f in plan["files"]],
          ["kind", "url", "bytes", "redacted", "sent"])
    app.say(f"{plan['chunks']} chunk(s), about {plan['token_estimate']} tokens, {plan['redactions']} redaction(s); "
            f"model {safe(plan['model'])} with {plan['num_ctx']}-token context.")
    for item in plan["skipped"][:10]:
        app.say(f"  skipped {safe(item['url'])} lines {item['lines']}: {safe(item['reason'])}")
    return 0


def cmd_review(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    result = _with_run(_service(app).request_review(
        ctx.project_id, actor=ctx, use_model=not args.no_model, idempotency_key=args.idempotency_key,
        reanalysis_of=UUID(args.reanalysis_of) if args.reanalysis_of else None, **_review_options(args)))
    if args.json:
        app.say(_dump(result))
        return 0
    app.say(f"Queued review {result['analysis_id']} (run {result['run']['run_id']}). "
            "An AI worker processes it: watchtower-worker ai, or Home > AI security review.")
    return 0


def cmd_results(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    rows = _service(app).results(ctx.project_id, actor=ctx, limit=args.limit)
    if args.json:
        app.say(_dump(rows))
        return 0
    table(app.out, [[r["id"][:8], app.style(r["status"], STATUS_COLOURS.get(r["status"], "bold")), r["mode"],
                     str(r["candidates"]["supported"]), str(r["candidates"]["unsupported"]),
                     "yes" if r["outdated"] else "", when(r["created_at"])] for r in rows],
          ["review", "status", "mode", "supported", "unsupported", "outdated", "created"])
    return 0


def _analysis(app: App, ctx: Any, reference: str) -> UUID:
    try:
        return UUID(reference)
    except ValueError:
        pass
    matches = [UUID(r["id"]) for r in _service(app).results(ctx.project_id, actor=ctx, limit=200)
               if r["id"].startswith(reference.lower())]
    if len(matches) != 1:
        raise CliError(f"no single recent review starts with {reference!r}")
    return matches[0]


def cmd_show(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    detail = _service(app).result(ctx.project_id, _analysis(app, ctx, args.analysis), actor=ctx)
    if args.json:
        app.say(_dump(detail))
        return 0
    s = app.style
    app.say(f"Review {detail['id']} {s(detail['status'].upper(), STATUS_COLOURS.get(detail['status'], 'bold'))} "
            f"({detail['mode']}, model {safe(detail['model']) or '-'})")
    if detail["outdated"]:
        app.say(s(f"  may be outdated: {safe(detail['outdated_reason'])} - request a reanalysis", "yellow"))
    if detail["error"]:
        app.say(s("  " + safe(detail["error"]), "red"))
    coverage = detail["coverage"]
    app.say("  " + safe(coverage.get("visible", "")))
    for note in coverage.get("not_visible", []) + coverage.get("model_notes", []):
        app.say("  - " + safe(note))
    if coverage.get("redaction_note"):
        app.say("  - " + safe(coverage["redaction_note"]))
    counts = (detail["preanalysis"] or {}).get("counts", {})
    if counts:
        app.say("  pre-analysis facts: " + ", ".join(f"{CATEGORY_LABELS.get(k, k)} {v}" for k, v in sorted(counts.items())))
    for candidate in detail["candidates"]:
        data = candidate["data"]
        label = "ISSUE CANDIDATE" if candidate["supported"] else "UNSUPPORTED (no verified evidence)"
        app.say("")
        app.say(f"{s(label, 'bold' if candidate['supported'] else 'grey')} {candidate['id'][:8]}  "
                f"[{CATEGORY_LABELS.get(candidate['category'], candidate['category'])}]  confidence {candidate['confidence']}")
        app.say("  " + s(safe(candidate["title"]), "bold"))
        app.say("  " + safe(data.get("explanation", "")))
        for citation in data.get("citations", []):
            app.say(f"  evidence line {citation['line']}: {safe(citation['quote'])[:200]}")
        for claim in data.get("claims", []):
            app.say(f"  [{claim['claim_type'].replace('_', ' ')}] {safe(claim['text'])}")
        for flag in data.get("flags", []):
            app.say(s(f"  ! {safe(flag)}", "yellow"))
        if candidate["matched_finding_id"]:
            app.say(f"  related finding {candidate['matched_finding_id']}")
        for used in data.get("examples_used", []):
            app.say(f"  used example {used['id'][:8]} r{used['revision']}: {safe(used['why_retrieved'])}; "
                    f"effect: {safe(used['effect'])}")
        if data.get("suggested_severity") not in (None, "none"):
            app.say(f"  suggested severity (unverified): {data['suggested_severity']}")
        for item in candidate["feedback"]:
            app.say(f"  feedback: {item['kind']}" + (f", memory {item['memory_state']}" if item["memory_state"] else ""))
    return 0


def cmd_feedback(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    corrected = {k: v for k, v in {"explanation": args.explanation, "category": args.category,
                                   "applicability": args.applicability}.items() if v}
    result = _service(app).submit_feedback(ctx.project_id, UUID(args.candidate), actor=ctx, kind=args.kind,
                                           reason=args.reason or "", corrected=corrected, submit_memory=args.memory,
                                           context=args.context or "")
    if args.json:
        app.say(_dump(result))
        return 0
    app.say(f"Feedback {result['feedback_id']} recorded. The finding's status is unchanged.")
    if result["example_id"]:
        app.say(f"Submitted memory example {result['example_id']} for owner approval. {MEMORY_SENTENCE}")
    return 0


def cmd_memory(app: App, args: argparse.Namespace) -> int:
    ctx = context(app, args)
    service = _service(app)
    action = args.memory_action
    if action == "list":
        rows = service.memory(ctx.project_id, actor=ctx, status=args.status)
        if args.json:
            app.say(_dump(rows))
            return 0
        app.say(MEMORY_SENTENCE)
        table(app.out, [[r["id"][:8], r["status"], f"r{r['current_revision']}",
                         safe((r["content"] or {}).get("verdict", "")), safe((r["content"] or {}).get("title", ""))[:60]]
                        for r in rows], ["example", "status", "revision", "verdict", "title"])
        return 0
    example_id = UUID(args.example)
    if action == "show":
        result = service.memory_example(ctx.project_id, example_id, actor=ctx)
    elif action == "approve":
        result = service.approve(ctx.project_id, example_id, actor=ctx, self_approve=args.self_approve, note=args.note or "")
    elif action == "reject":
        result = service.reject(ctx.project_id, example_id, actor=ctx, reason=args.reason)
    elif action == "edit":
        content = {k: v for k, v in {"explanation": args.explanation, "category": args.category,
                                     "applicability": args.applicability}.items() if v}
        conditions: dict[str, Any] = {}
        for item in args.condition or []:
            key, _, value = item.partition("=")
            conditions[key.strip()] = [v.strip() for v in value.split(",")] if key.strip() in ("identifiers", "keywords") \
                else value.strip()
        result = service.edit(ctx.project_id, example_id, actor=ctx, content=content, conditions=conditions,
                              note=args.note or "")
    elif action == "disable":
        result = service.disable(ctx.project_id, example_id, actor=ctx, reason=args.reason or "")
    elif action == "enable":
        result = service.enable(ctx.project_id, example_id, actor=ctx, reason=args.reason or "")
    else:
        result = service.supersede(ctx.project_id, example_id, actor=ctx, by=UUID(args.by), reason=args.reason or "")
    if args.json:
        app.say(_dump(result))
        return 0
    app.say(f"Example {result['id']}: {result['status']}, revision {result['current_revision']}"
            + (" (self-approved)" if result.get("self_approved") else ""))
    if action == "show":
        app.say(_dump({"content": result["content"], "conditions": result["conditions"]}))
        for event in result["events"]:
            app.say(f"  {when(event['at'])} {event['action']} r{event['revision']} {safe(event['reason'])}")
    if result.get("analyses_marked_outdated"):
        app.say(f"{result['analyses_marked_outdated']} review(s) that used it are now marked as possibly outdated.")
    return 0


def register(commands: Any, add: Callable[..., argparse.ArgumentParser]) -> None:
    ai = commands.add_parser("ai", help="optional local AI security review").add_subparsers(dest="sub", required=True)
    add("status", cmd_status, "AI review status, project switches and memory counts", json_output=True, parent=ai)
    add("check", cmd_check, "check the local model connection (sends no prompt)", json_output=True, parent=ai)
    settings = add("settings", cmd_settings, "show or change this project's AI switches (needs owner)",
                   json_output=True, parent=ai)
    for flag in SWITCHES:
        settings.add_argument("--" + flag.replace("_", "-"), dest=flag, choices=["on", "off"])
    collect = add("collect", cmd_collect, "queue a Collect for AI review run (in-scope pages and scripts)",
                  json_output=True, parent=ai)
    collect.add_argument("--target", action="append", help="root domain; default: every root in scope")
    collect.add_argument("--url", action="append", help="start page (in scope); repeat up to 5")
    collect.add_argument("--review", action="store_true", help="review the collected content when collection ends")
    collect.add_argument("--no-model", action="store_true", help="pre-analysis only")
    collect.add_argument("--idempotency-key")
    for name, handler, help_text in (("preview", cmd_preview, "show what a review would send (sends nothing)"),
                                     ("review", cmd_review, "queue an AI review of collected or scan evidence")):
        sub = add(name, handler, help_text, json_output=True, parent=ai)
        sub.add_argument("--run", help="collection run id (default: the latest collection)")
        sub.add_argument("--source", action="append", help="source id; repeat for more")
        sub.add_argument("--no-scan", action="store_true", help="leave out stored scan evidence")
        sub.add_argument("--finding", help="explain this finding")
        if name == "review":
            sub.add_argument("--no-model", action="store_true", help="pre-analysis only (works while AI is disabled)")
            sub.add_argument("--reanalysis-of", help="review the same sources again")
            sub.add_argument("--idempotency-key")
    results = add("results", cmd_results, "recent reviews", json_output=True, parent=ai)
    results.add_argument("--limit", type=int, default=20)
    add("show", cmd_show, "one review: coverage, candidates and evidence", json_output=True, parent=ai).add_argument("analysis")
    feedback = add("feedback", cmd_feedback, "record feedback on a candidate (needs operator)", json_output=True, parent=ai)
    feedback.add_argument("candidate")
    feedback.add_argument("--kind", required=True, choices=["looks_correct", "false_positive", "edit"])
    feedback.add_argument("--reason", help="required for false_positive: why it does not apply here")
    feedback.add_argument("--explanation")
    feedback.add_argument("--category", choices=list(CATEGORIES))
    feedback.add_argument("--applicability")
    feedback.add_argument("--memory", action="store_true", help="submit as a project-memory example for approval")
    feedback.add_argument("--context", help="when the example applies")
    memory = commands_parser(ai, "memory", "project-memory examples")
    listing = add("list", cmd_memory, "examples you may see", json_output=True, parent=memory)
    listing.add_argument("--status", choices=["submitted", "approved", "rejected", "superseded", "disabled"])
    listing.set_defaults(memory_action="list")
    for name, help_text in (("show", "one example with its revisions and history"), ("approve", "approve (needs owner)"),
                            ("reject", "reject (needs owner)"), ("edit", "edit as a new revision (needs owner)"),
                            ("disable", "stop using it (needs owner)"), ("enable", "use it again (needs owner)"),
                            ("supersede", "replace it with another approved example (needs owner)")):
        sub = add(name, cmd_memory, help_text, json_output=True, parent=memory)
        sub.set_defaults(memory_action=name)
        sub.add_argument("example")
        if name == "approve":
            sub.add_argument("--self-approve", action="store_true", help="explicitly approve your own submission")
            sub.add_argument("--note")
        elif name in ("reject",):
            sub.add_argument("--reason", required=True)
        elif name in ("disable", "enable"):
            sub.add_argument("--reason")
        elif name == "edit":
            sub.add_argument("--explanation")
            sub.add_argument("--category", choices=list(CATEGORIES))
            sub.add_argument("--applicability")
            sub.add_argument("--condition", action="append", metavar="KEY=VALUE",
                             help="path_pattern, context, review_by, identifiers (comma list) ...")
            sub.add_argument("--note")
        elif name == "supersede":
            sub.add_argument("--by", required=True)
            sub.add_argument("--reason")


def commands_parser(parent: Any, name: str, help_text: str) -> Any:
    return parent.add_parser(name, help=help_text).add_subparsers(dest="memory_sub", required=True)
