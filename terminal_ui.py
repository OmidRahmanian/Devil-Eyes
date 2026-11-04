#!/usr/bin/env python3
"""Interactive platform presentation. All mutations use the existing CLI/services.

Window commands contain identifiers and paths only. Every new terminal loads .env
itself; no credentials are embedded in shell commands or generated scripts.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import random
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import urlopen
from uuid import UUID, uuid4
import webbrowser

import launcher
from watchtower.cli import safe, Style, RUN_COLOURS

ROOT = Path(__file__).resolve().parent
FINISHED = {"succeeded", "partial", "failed", "cancelled"}
PROFILES = ("development", "lab", "production")
PHASES = ("discovery", "dns", "http", "checks", "finalize")
HOME = {
    "1": "Start scan", "2": "View scan progress", "3": "Browse inventory",
    "4": "Browse findings", "5": "Advanced target settings", "6": "View alerts",
    "7": "Open dashboard", "8": "Switch saved targets / projects", "9": "Settings and help",
    "a": "AI security review", "0": "Exit",
}


def is_ai(run):
    return str(run.get("kind", "scan")).startswith("ai.")


class UiError(Exception):
    pass


class Back(Exception):
    pass


class Screen:
    """A fixed banner and status header above a content area that is redrawn in place.

    Only a live terminal is redrawn; pipes, TERM=dumb and --no-clear keep plain
    sequential output. Content lines are already escaped and bounded by tell().
    """
    def __init__(self):
        self.enabled = False
        self.status = []
        self.lines = []        # content shown since the user last moved to another screen
        self.stale = True      # the terminal does not show self.lines yet
        self.holding = False
        self.prompting = False
        self.tagline = None
        self.output = None

    @property
    def stream(self):
        return self.output or sys.stdout

    def start(self, *, no_clear=False, stream=None):
        self.output = stream
        self.enabled = not no_clear and self.stream.isatty() and os.environ.get("TERM") != "dumb"
        tagline = os.environ.get("DEVILS_EYES_TAGLINE")
        self.tagline = tagline if tagline in launcher.TAGLINES else random.choice(launcher.TAGLINES)

    def note(self, text):
        if not self.enabled:
            print(text, file=self.stream, flush=True)
            return
        self.lines.append(text)
        if self.holding:
            return
        if self.stale:
            self.render()
        else:
            print(text, file=self.stream, flush=True)
        self.prompting = False

    def record(self, text):
        """Keep an answered prompt on screen when the content is redrawn."""
        if self.enabled:
            self.lines.append(safe(text)[:4000])

    def show_status(self, lines):
        if not self.enabled:
            tell()
            for line in lines:
                tell(line)
            return
        self.status = [safe(line)[:4000] for line in lines]

    def page(self):
        """The user moved to another screen: its output replaces this content."""
        self.lines = []
        self.stale = True

    def invalidate(self):
        """Another process drew on this terminal."""
        self.stale = True

    def mark(self):
        return len(self.lines)

    @contextmanager
    def frame(self, mark):
        """Replace the content after mark with the block's output, drawn at once."""
        if not self.enabled:
            yield
            return
        del self.lines[mark:]
        self.holding = True
        try:
            yield
        finally:
            self.holding = False
        self.render()

    def header(self, width, room):
        colour = "NO_COLOR" not in os.environ
        red, reset = ("\033[1;31m", "\033[0m") if colour else ("", "")
        status = [part for line in self.status for part in textwrap.wrap(line, width) or [""]]
        banner = io.StringIO()
        launcher.banner(banner, tagline=self.tagline, colour=colour, animate=False)
        eye = banner.getvalue().split("\n")[:-1]
        if len(eye) + len(status) + 2 <= room:
            return [*eye, *([""] + status if status else []), ""]
        # Too short for the eye: one compact line keeps the brand and status visible.
        compact = " | ".join(self.status or ["DEVILS EYES"])
        return [*textwrap.wrap(compact, width), red + "-" * min(width, 76) + reset, ""]

    def render(self, extra=()):
        if not self.enabled:
            return
        size = shutil.get_terminal_size((80, 24))
        width = max(20, min(size.columns, 120))
        body = [part for line in (*self.lines, *extra) for part in str(line).split("\n")]
        while body and not body[0]:
            body.pop(0)
        rows = self.header(width, size.lines - len(body) - 1) + body
        # Home and overwrite each row, then clear below and the scrollback:
        # no flicker on live refresh and no stacked copies of earlier screens.
        self.stream.write("\033[H\033[3J" + "".join(row + "\033[K\n" for row in rows) + "\033[J")
        self.stream.flush()
        self.stale = False

    def close(self):
        if self.enabled:
            self.stream.write("\033[0m" + ("\n" if self.prompting else ""))
            self.stream.flush()


SCREEN = Screen()


def tell(value=""):
    """Bound and wrap untrusted data; never interpret terminal control sequences."""
    width = max(20, min(shutil.get_terminal_size((80, 24)).columns, 120))
    for line in str(value).split("\n"):
        SCREEN.note(textwrap.fill(safe(line)[:4000], width=width, replace_whitespace=False) or "")


def prompt(label, default, check, below=()):
    """Ask until check accepts. A live terminal redraws the same screen with the error."""
    error = None
    while True:
        if SCREEN.enabled and (error or below or SCREEN.stale):
            SCREEN.render([*([error] if error else []), *below])
        SCREEN.prompting = True
        answer = launcher.ask(label, default)
        SCREEN.prompting = False
        try:
            value = check(answer)
        except ValueError as exc:
            if not SCREEN.enabled:
                tell(exc)
            error = safe(str(exc))
            continue
        SCREEN.record(label + (" [" + default + "]" if default else "") + ": " + answer)
        return value


def field(label, default="", validate=None):
    def check(answer):
        if answer.lower() == "b":
            raise Back()
        return validate(answer) if validate else answer
    return prompt(label + " (b: Back)", default, check)


def yes_no(question, default=True):
    if not SCREEN.enabled:
        return launcher.yes_no(question, default)

    def check(answer):
        if answer.lower() not in ("y", "yes", "n", "no"):
            raise ValueError("Please enter y or n.")
        return answer.lower() in ("y", "yes")
    return prompt(question + (" (Y/n)" if default else " (y/N)"), "y" if default else "n", check)


def menu(label, options, default="0"):
    if not SCREEN.enabled:
        return launcher.choose(label, options, default)

    def check(answer):
        if answer not in options:
            raise ValueError("Please choose one of the listed numbers.")
        return answer
    lines = ["", safe(label), *(f"  {key}) {safe(text)}" for key, text in options.items())]
    answer = prompt("Choose", default, check, below=lines)
    SCREEN.page()
    return answer


class Preferences:
    """Per-checkout UI preferences; token paths only, never token contents."""
    def __init__(self, root=ROOT):
        self.directory = root / "files" / "terminal-ui"
        self.path = self.directory / "preferences.json"
        try:
            data = json.loads(self.path.read_text())
            self.data = data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            self.data = {}
        if not isinstance(self.data.get("tokens"), dict):
            self.data["tokens"] = {}
        for key in ("profile", "project", "token_file"):
            if key in self.data and not isinstance(self.data[key], str):
                self.data.pop(key)

    def save(self, profile, project, token_file):
        self.data.update(profile=profile, project=project, token_file=str(token_file))
        self.data["tokens"][profile + ":" + project] = str(token_file)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, name = tempfile.mkstemp(dir=self.directory)
        try:
            with os.fdopen(descriptor, "w") as output:
                json.dump(self.data, output, indent=2)
            os.replace(name, self.path)
        finally:
            Path(name).unlink(missing_ok=True)


class Client:
    def __init__(self, root=ROOT, *, profile="development", project="", token_file=None, env=None):
        self.root = Path(root).absolute()
        self.python = launcher.python_executable(self.root)
        self.env = dict(env if env is not None else launcher.runtime_environment(self.root, self.python))
        # Separate WSL windows do not inherit an activated virtual environment.
        self.env["PATH"] = str(Path(self.python).parent) + os.pathsep + self.env.get("PATH", os.defpath)
        self.profile = profile
        self.project = project
        self.token_file = Path(token_file or self.env.get("WATCHTOWER_TOKEN_FILE", "~/.config/watchtower/token")).expanduser().absolute()
        # An explicit selection must not be silently overridden by an old shell token.
        if token_file is not None:
            self.env.pop("WATCHTOWER_TOKEN", None)

    def command(self, *args):
        return [self.python, "-m", "watchtower.cli", "--profile", self.profile,
                "--project", self.project, "--token-file", str(self.token_file), *args]

    def call(self, *args, data=False):
        result = subprocess.run(self.command(*args, *(["--json"] if data else [])), cwd=self.root,
                                env=self.env, text=True, capture_output=True, timeout=45)
        if result.returncode:
            # Do not replay tracebacks, URLs or credentials from a database driver.
            lines = [line for line in result.stderr.splitlines() if line.startswith("watchtower:")]
            message = lines[-1] if lines else "Command failed. Check database connectivity, credentials and project access."
            if "://" in message:
                message = "Command failed. Check connection settings in .env and project access."
            raise UiError(message)
        if not data:
            return result.stdout
        try:
            return json.loads(result.stdout)
        except ValueError:
            raise UiError("The CLI returned an unreadable response; no action will be repeated automatically.") from None

    def json(self, *args):
        return self.call(*args, data=True)

    def show(self, *args):
        tell(self.call(*args))


@contextmanager
def session_lock(client, key):
    directory = client.root / "files" / "terminal-ui" / "locks"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = hashlib.sha256((client.profile + ":" + client.project + ":" + key).encode()).hexdigest()
    with (directory / name).open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise UiError("Another terminal is already performing this action. View the existing run instead.") from None
        yield


def window_arguments(client, *, run=None, dashboard=False, monitor=False):
    argv = [client.python, str(client.root / "terminal_ui.py"), "--profile", client.profile,
            "--project", client.project, "--token-file", str(client.token_file), "--hold"]
    if dashboard:
        argv.append("--dashboard")
    elif monitor:
        argv.append("--monitor")
    else:
        argv += ["--run", str(UUID(str(run)))]
    return argv


def open_window(client, *, run=None, dashboard=False, monitor=False):
    """Best-effort dispatch. A run remains queued if the OS refuses a window."""
    argv = window_arguments(client, run=run, dashboard=dashboard, monitor=monitor)
    title = "Devils Eyes - " + safe(client.project)
    if sys.platform.startswith("linux") and client.env.get("WSL_DISTRO_NAME"):
        powershell = shutil.which("powershell.exe", path=client.env.get("PATH"))
        if not powershell:
            raise UiError("Windows PowerShell is unavailable in WSL. Check Windows interoperability, or choose Process in this terminal.")
        arguments = subprocess.list2cmdline(["--distribution", client.env["WSL_DISTRO_NAME"],
                                            "--cd", str(client.root), "--exec", *argv])
        payload = base64.b64encode(arguments.encode("utf-8")).decode("ascii")
        # Only paths/identifiers cross this boundary, as data. Windows opens a
        # new console; its Python process privately reloads the checkout's .env.
        script = ("$ErrorActionPreference = 'Stop'; "
                  "$arguments = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + payload + "')); "
                  "Start-Process -FilePath 'wsl.exe' -ArgumentList $arguments -WindowStyle Normal -ErrorAction Stop")
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise UiError("Windows could not open a new terminal. Retry or choose Process in this terminal.")
        return
    if sys.platform == "darwin":
        command = "cd " + shlex.quote(str(client.root)) + " && exec " + shlex.join(argv)
        script = ('on run argv\n tell application "Terminal"\n activate\n'
                  ' do script (item 1 of argv)\n end tell\nend run')
        result = subprocess.run(["osascript", "-e", script, command], capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise UiError("macOS could not open Terminal. Allow terminal automation if prompted, or use this terminal.")
        return
    if sys.platform.startswith("linux"):
        variants = (
            ("gnome-terminal", ["--title", title, "--"]),
            ("konsole", ["--new-window", "-p", "tabtitle=" + title, "-e"]),
            ("xfce4-terminal", ["--disable-server", "--title", title, "-x"]),
            ("xterm", ["-T", title, "-e"]),
        )
        for executable, flags in variants:
            if shutil.which(executable):
                process = subprocess.Popen([executable, *flags, *argv], cwd=client.root,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           start_new_session=True)
                try:
                    code = process.wait(timeout=0.5)
                    if code != 0:
                        raise UiError("The terminal emulator could not open a window.")
                except subprocess.TimeoutExpired:
                    pass
                return
    raise UiError("No supported terminal window launcher was found. Use this terminal instead.")


def scope_summary(status):
    revision = status.get("scope")
    if not revision:
        return "No target yet - choose 1 to add one and scan"
    return ", ".join(("exclude " if r["effect"] == "exclude" else "") + r["pattern"] for r in revision["rules"])


def current_phase(detail):
    active = sorted({j["kind"].removeprefix("monitor.") for j in detail.get("jobs", []) if j["status"] == "running"})
    return ", ".join(active) if active else "waiting for worker / next due job"


def render_progress(detail, project):
    run = detail["run"]
    end = run.get("finished_at") or datetime.now(timezone.utc).isoformat()
    elapsed = max(0, int((datetime.fromisoformat(end) - datetime.fromisoformat(run["created_at"])).total_seconds()))
    tell(f"\n{project} | Run {run['run_id']} | Elapsed {elapsed // 60}m {elapsed % 60}s")
    style = Style(sys.stdout)
    SCREEN.note(style(run["status"].upper(), RUN_COLOURS.get(run["status"], "bold")))
    if is_ai(run):
        render_ai_progress(detail)
        return
    tell("Discovery > DNS > HTTP > Checks > Finalize")
    tell("Current: " + ("finished" if run["status"] in FINISHED else current_phase(detail)))
    for phase in PHASES:
        jobs = [j for j in detail.get("jobs", []) if j["kind"].split(".")[-1] == phase]
        if jobs:
            states = ", ".join(sorted({j["status"] for j in jobs}))
            tell(f"  {phase.upper()}: {states}")
    snapshots = detail.get("snapshots", [])
    for snapshot in snapshots[-12:]:
        tell(f"  {snapshot['phase']} / {snapshot['target']}: {snapshot['status']}, {snapshot['comparison']}")
        if snapshot.get("stats"):
            tell("    Counts: " + json.dumps(snapshot["stats"], ensure_ascii=True)[:600])
    if len(snapshots) > 12:
        tell(f"  Showing the latest 12 of {len(snapshots)} phase snapshots. Use run show for full details.")
    for name, reason in detail.get("checks_not_run", {}).items():
        tell(f"  NOT RUN: {name} - {reason}")
    errors = [j for j in detail.get("jobs", []) if j.get("last_error")]
    for job in errors[-5:]:
        tell(f"  Job {job['kind']}: {job['last_error']}")
    if len(errors) > 5:
        tell(f"  Showing the latest 5 of {len(errors)} job errors. Use run show for full details.")
    if run.get("last_error"):
        tell("Error: " + run["last_error"])
    if detail.get("retest_outcome"):
        tell("Retest outcome: " + detail["retest_outcome"])
    if run["status"] == "failed":
        tell("Run failed. Check the reported phase, target connectivity and installed tools; existing findings are not resolved.")
    elif run["status"] == "partial":
        tell("Run completed with gaps. Review NOT RUN checks and phase results; this is not a complete successful scan.")


def render_ai_progress(detail):
    run = detail["run"]
    jobs = detail.get("jobs", [])
    tell("Collect for AI review > Analyze" if any(j["kind"] == "ai.collect" for j in jobs) else "AI review: Analyze")
    tell("Current: " + ("finished" if run["status"] in FINISHED else current_phase(detail)))
    for job in jobs:
        tell(f"  {job['kind'].removeprefix('ai.').upper()}: {job['status']}")
        result = job.get("result") or {}
        if job["kind"] == "ai.collect" and result:
            tell(f"    {result.get('pages', 0)} page(s), {result.get('scripts', 0)} script(s), "
                 f"{result.get('inline_scripts', 0)} inline, {result.get('references', 0)} third-party "
                 "reference(s) not fetched")
            for note in result.get("notes", [])[:5]:
                tell("    " + note)
            for item in result.get("skipped", [])[:5]:
                tell(f"    skipped {item['url']}: {item['reason']}")
        elif job["kind"] == "ai.analyze" and result:
            tell(f"    review {str(result.get('analysis_id', ''))[:8]}: {result.get('status', '')}")
        if job.get("last_error"):
            tell("    Error: " + job["last_error"])
    if run["status"] in FINISHED:
        tell("Results: Home > AI security review > View results.")


class AiProcessor:
    """The AI analysis worker in its own process: it reaches only the database and the local model."""
    def __init__(self, client):
        self.client = client
        self.process = None

    def start(self):
        if self.process is None:
            argv = [self.client.python, "-m", "watchtower.workers.cli", "--profile", self.client.profile, "ai"]
            self.process = subprocess.Popen(argv, cwd=self.client.root, env=self.client.env,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

    @property
    def error(self):
        if self.process is None or self.process.poll() is None:
            return None
        lines = (self.process.stderr.read() or "").strip().splitlines() if self.process.stderr else []
        lines = [line for line in lines if "://" not in line]  # never replay connection strings
        return (lines[-1] if lines else "exit code " + str(self.process.returncode))[:300]

    def close(self):
        if self.process is None or self.process.poll() is not None:
            return
        self.process.send_signal(signal.SIGTERM)
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()


class LocalProcessor:
    """Use the existing worker with graceful shutdown; it can claim other projects' jobs."""
    def __init__(self, client):
        from watchtower.config import load_settings
        from watchtower.persistence.database import Database
        from watchtower.services.scope import ScopeService
        from watchtower.workers import egress
        from watchtower.workers.runtime import Worker, Notifier

        settings = load_settings(client.profile)
        egress.install(settings)
        self.database = Database.from_settings(settings.database)
        self.worker = Worker(self.database, ScopeService(self.database, settings.scope), settings=settings)
        self.notifier = Notifier(self.database, settings)
        self.stop_event = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self.loop, daemon=True, name="watchtower-ui-worker")

    def loop(self):
        try:
            while not self.stop_event.is_set():
                worked = self.worker.run_once()
                if not self.stop_event.is_set():
                    self.notifier.deliver_once()
                if not worked:
                    self.stop_event.wait(1)
        except Exception as exc:
            self.error = type(exc).__name__  # no secret-bearing exception repr

    def start(self):
        self.thread.start()

    def close(self):
        self.stop_event.set()
        # The first shutdown may race a claim; repeat while the thread winds down.
        deadline = time.monotonic() + 15
        while self.thread.is_alive() and time.monotonic() < deadline:
            self.worker.shutdown()
            self.thread.join(timeout=0.2)
        if not self.thread.is_alive():
            self.database.dispose()
        else:
            tell("Local processing is stopping. In-flight leases may need to expire before another worker resumes them.")


def watch_run(client, run_id, *, work=False, interval=2):
    run_id = str(UUID(str(run_id)))
    # Validate access and the identifier before starting any worker.
    detail = client.json("run", "show", run_id)
    if work and detail["run"]["status"] in FINISHED:
        render_progress(detail, client.project)
        return 0 if detail["run"]["status"] in ("succeeded", "partial") else 4
    tell("Ctrl+C stops this viewer and its local processing, not the run. Use Cancel run in the home menu to cancel it.")
    processor = None
    ai_processor = AiProcessor(client) if work and is_ai(detail["run"]) else None
    previous = None
    last_print = 0.0
    try:
        if work and detail["run"].get("kind") != "ai.analyze":
            tell("Local worker enabled: it may also process due jobs and notifications from other projects.")
            processor = LocalProcessor(client)
            processor.start()
        if ai_processor:
            tell("The AI analysis runs in a separate worker that can reach only the database and the local model.")
        mark = SCREEN.mark()
        while True:
            detail = client.json("run", "show", run_id)
            if ai_processor and any(j["kind"] == "ai.analyze" and j["status"] in ("queued", "running")
                                    for j in detail.get("jobs", [])):
                ai_processor.start()
            signature = json.dumps(detail, sort_keys=True)
            now = time.monotonic()
            # A redrawn screen refreshes in place on every poll, so elapsed time keeps moving.
            if SCREEN.enabled or signature != previous or now - last_print >= 30:
                with SCREEN.frame(mark):
                    render_progress(detail, client.project)
                previous, last_print = signature, now
            status = detail["run"]["status"]
            if status in FINISHED:
                tell("Final result shown above. Alerts: Home > View alerts.")
                return 0 if status in ("succeeded", "partial") else 4
            if processor and processor.error:
                raise UiError("Local worker stopped (" + processor.error + "). Check configuration and resume this existing run; do not queue it again.")
            if ai_processor and ai_processor.error:
                raise UiError("The AI worker stopped (" + ai_processor.error + "). Check Home > AI security review > "
                              "Model status, then resume this run; it is not queued again.")
            time.sleep(interval)
    except KeyboardInterrupt:
        tell("Stopped viewing and local processing. The run was not cancelled; another worker can resume it.")
        return 0
    finally:
        if processor:
            processor.close()
        if ai_processor:
            ai_processor.close()


def scan_window(client, run_id):
    with session_lock(client, "process-" + str(UUID(str(run_id)))):
        return watch_run(client, run_id, work=True)


def process_here(client, run_id=None, *, monitor=False):
    # Keep the worker's process-wide egress guard and signal cleanup isolated
    # from Home, just as they are in a separate terminal window.
    argv = [arg for arg in window_arguments(client, run=run_id, monitor=monitor) if arg != "--hold"]
    process = subprocess.Popen(argv, cwd=client.root, env=client.env)
    try:
        return process.wait()
    except KeyboardInterrupt:
        tell("Waiting for local processing to stop safely; the run is not cancelled.")
        try:
            process.send_signal(signal.SIGINT)
            return process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                return process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise UiError("Worker shutdown timed out. Resume the existing run after its leases expire.") from None
    finally:
        SCREEN.invalidate()


def launch_scan(client, run_id):
    while True:
        try:
            open_window(client, run=run_id)
            tell(f"Scan window requested for {run_id}. This menu remains available.")
            tell("If no window appears, use View scan progress > Open processing window to retry this same run.")
            return
        except (UiError, OSError, subprocess.TimeoutExpired) as exc:
            tell(str(exc) if isinstance(exc, UiError) else "Could not launch the scan window.")
            tell(f"Run {run_id} is retained. No second run will be queued.")
            action = menu("Where should this run continue?", {"1": "Retry new window", "2": "Process in this terminal",
                                                            "0": "Back - leave queued for a worker"}, "0")
            if action == "2":
                process_here(client, run_id)
                return
            if action == "0":
                return


def target_domain(value):
    """Accept a website URL without guessing or expanding its parent domain."""
    value = value.strip()
    parsed = urlsplit(value if "://" in value else "//" + value)
    if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Use an http/https website link or a domain.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Use a link without embedded login credentials.")
    if parsed.port not in (None, 80, 443):
        raise ValueError("Use a domain or a website on port 80 or 443.")
    return launcher.domain_name(parsed.hostname or "")


def saved_roots(status):
    roots = set()
    for rule in (status.get("scope") or {}).get("rules", []):
        if rule["effect"] == "include":
            try:
                roots.add(launcher.domain_name(rule["pattern"].removeprefix("*.")))
            except ValueError:
                continue
    return sorted(roots)


def add_scan_target(client, status, preferences, *, separate=False):
    """Collect and confirm a target before saving anything or queueing a run."""
    tell("\nAdd a target")
    tell("Paste a root domain or website link. The hostname is used; URL paths are not scan boundaries.")
    domain = field("Domain or website link", validate=target_domain)
    tell("Target: " + domain)
    include = [domain]
    if yes_no("Discover and scan ALL subdomains (*." + domain + ") too?", default=False):
        include.append("*." + domain)
    excluded = field("Subdomains to skip (Enter: none)", "-", lambda value: launcher.exclusions(value, domain))
    choice = menu("Permission to scan", {**{k: label for k, (_, label) in launcher.AUTHORIZATIONS.items()}, "0": "Back"})
    if choice == "0":
        raise Back()
    kind = launcher.AUTHORIZATIONS[choice][0]
    if kind == "asset_owner":
        granted = field("Your name", os.environ.get("USER", ""), validate=launcher.required_text)
        reference = "Asset ownership confirmed in terminal for " + domain
    else:
        reference = field("Permission link, contract or approval reference", validate=launcher.required_text)
        granted = field("Organization or person granting permission", validate=launcher.required_text)
    tell("\nScan: " + ", ".join(include))
    tell("Skip: " + (", ".join(excluded) or "none"))
    tell("This discovers subdomains, resolves DNS, probes websites and runs approved checks.")
    if not yes_no("Confirm you are authorized for these targets, save and start the scan?", default=False):
        raise Back()
    if status.get("scope") or separate:
        # A separate project preserves the previous target's policy and history.
        slug = launcher.project_slug(domain.replace(".", "-")[:50]) + "-" + uuid4().hex[:8]
        directory = preferences.directory / "tokens"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        token = directory / (client.profile + "-" + slug + "-" + uuid4().hex)
        client.show("bootstrap", slug, "--name", domain, "--owner", os.environ.get("USER", "Local owner"), "--save-token", str(token))
        client = Client(client.root, profile=client.profile, project=slug, token_file=token, env=client.env)
        # Remember the new token immediately, even if saving permissions fails.
        preferences.save(client.profile, client.project, client.token_file)
    args = ["scope", "publish", "--authorization-kind", kind, "--reference", reference,
            "--granted-by", granted, "--i-am-authorized"]
    for pattern in include:
        args += ["--include", pattern]
    for pattern in excluded:
        args += ["--exclude", pattern]
    client.show(*args)
    preferences.save(client.profile, client.project, client.token_file)
    return client, domain


def active_scan(client):
    return [r for r in client.json("run", "list", "--limit", "200") if r["status"] not in FINISHED and not is_ai(r)]


def start_scan(client, preferences=None):
    preferences = preferences or Preferences(client.root)
    active = active_scan(client)
    add_new = False
    if active:
        tell("You have an unfinished scan. Continue it here, or add another target.")
        options = {}
        for i, run in enumerate(active, 1):
            targets = ", ".join(run.get("targets") or [client.project])
            state = "waiting to start" if run["status"] == "queued" else run["status"]
            options[str(i)] = f"Continue {targets} ({state}, {run['run_id'][:8]})"
        new_choice, saved_choice = str(len(active) + 1), str(len(active) + 2)
        action = menu("Start scan", {**options, new_choice: "Add a new target",
                      saved_choice: "Choose another saved target", "0": "Back"}, "1")
        if action == "0":
            return client
        if action == saved_choice:
            return start_scan(select_project(client, preferences), preferences)
        if action != new_choice:
            run = active[int(action) - 1]
            tell("Continuing your saved scan " + run["run_id"] + ".")
            launch_scan(client, run["run_id"])
            return client
        add_new = True
    status = client.json("status")
    roots = saved_roots(status)
    if add_new:
        client, target = add_scan_target(client, status, preferences, separate=True)
    elif status.get("scope"):
        options = {str(i): domain for i, domain in enumerate(roots, 1)}
        new_choice, saved_choice = str(len(roots) + 1), str(len(roots) + 2)
        action = menu("What would you like to scan?", {**options, new_choice: "Add a new target",
                      saved_choice: "Choose another saved target", "0": "Back"}, "1" if roots else new_choice)
        if action == "0":
            return client
        if action == saved_choice:
            return start_scan(select_project(client, preferences), preferences)
        if action == new_choice:
            client, target = add_scan_target(client, status, preferences)
        else:
            target = roots[int(action) - 1]
            tell("Target: " + target + " | Saved permissions and exclusions apply.")
            if not yes_no("Start scan?", default=False):
                return client
    else:
        client, target = add_scan_target(client, status, preferences)
    # Recheck after the wizard, under the launch lock, in case another window queued work.
    with session_lock(client, "start"):
        existing = next((r for r in active_scan(client)
                         if r.get("kind") == "scan" and r.get("targets") == [target]), None)
        run = existing or client.json("run", "start", "--target", target, "--reason", "started from terminal home", "--reuse-active",
                                      "--idempotency-key", str(uuid4()))
    tell(("Continuing your saved scan " if existing else "Queued run ") + run["run_id"])
    launch_scan(client, run["run_id"])
    return client


def select_run(client):
    runs = client.json("run", "list", "--limit", "20")
    if not runs:
        tell("No runs yet. Use Start scan from Home.")
        raise Back()
    options = {str(i): safe(f"{r['run_id'][:8]} {r['status']} {r['created_at']}") for i, r in enumerate(runs, 1)}
    choice = menu("Recent runs", {**options, "0": "Back"})
    if choice == "0":
        raise Back()
    return runs[int(choice) - 1]


def progress_menu(client):
    run = select_run(client)
    while True:
        action = menu("Run " + run["run_id"], {"1": "Show current details", "2": "Watch here (no worker)",
                      "3": "Open processing window / resume", "4": "Cancel run", "0": "Back"})
        if action == "0":
            return
        if action == "1":
            render_progress(client.json("run", "show", run["run_id"]), client.project)
        elif action == "2":
            watch_run(client, run["run_id"])
        elif action == "3":
            launch_scan(client, run["run_id"])
        elif yes_no("Cancel this run?", default=False):
            reason = field("Cancellation reason", validate=launcher.required_text)
            client.show("run", "cancel", run["run_id"], "--reason", reason)


def manage_scope(client):
    while True:
        action = menu("Targets and scope", {"1": "Show scope and history", "2": "Publish scope", "3": "Check target (no network)",
                                           "4": "Revoke current scope", "0": "Back"})
        if action == "0":
            return
        if action == "1":
            client.show("scope", "show")
        elif action == "3":
            client.show("scope", "check", field("Target to check", validate=launcher.required_text))
        elif action == "4":
            current = client.json("status").get("scope")
            if current and yes_no("Revoke current scope and stop authorization for new requests?", default=False):
                client.show("scope", "revoke", current["id"], "--reason", field("Reason", validate=launcher.required_text))
        else:
            domain = field("Target domain (text, e.g. example.com)", validate=launcher.domain_name)
            include = [domain]
            if yes_no("Also include ALL subdomains (*." + domain + ")?", default=False):
                include.append("*." + domain)
            excluded = field("Excluded exact subdomains, comma-separated (- for none)", "-",
                             lambda value: launcher.exclusions(value, domain))
            choice = menu("Authorization", {**{k: label for k, (_, label) in launcher.AUTHORIZATIONS.items()}, "0": "Back"})
            if choice == "0":
                continue
            kind = launcher.AUTHORIZATIONS[choice][0]
            reference = field("Authorization reference (policy URL, contract or ticket)", validate=launcher.required_text)
            granted = field("Person or organization granting permission", validate=launcher.required_text)
            tell("New scope: " + ", ".join(include) + "; excluded: " + (", ".join(excluded) or "none"))
            if not yes_no("Do you have authorization covering every included target?", default=False):
                tell("Cancelled. Scope unchanged.")
                continue
            args = ["scope", "publish", "--authorization-kind", kind, "--reference", reference,
                    "--granted-by", granted, "--i-am-authorized"]
            for pattern in include:
                args += ["--include", pattern]
            for pattern in excluded:
                args += ["--exclude", pattern]
            client.show(*args)


def browse_findings(client):
    client.show("findings", "--all")
    while True:
        action = menu("Findings", {"1": "Inspect finding", "2": "Retest finding", "3": "Triage finding",
                                   "4": "Assign owner / add remediation notes", "5": "Recompute priority", "0": "Back"})
        if action == "0":
            return
        finding = field("Finding ID or unique prefix", validate=launcher.required_text)
        if action == "1":
            client.show("finding", "show", finding)
            if menu("Finding", {"1": "Explain this finding (AI security review)", "0": "Back"}, "0") == "1":
                ai_review(client, finding=client.json("finding", "show", finding)["id"])
        elif action == "2":
            if yes_no("Queue a retest? It needs a worker; this does not mark the finding fixed.", default=False):
                client.show("finding", "retest", finding)
                tell("Use View scan progress to open the retest's processing window.")
        elif action == "4":
            client.show("finding", "annotate", finding, "--owner", field("Owner (Enter: unassigned)"),
                        "--remediation-notes", field("Remediation notes (Enter: clear)"))
        elif action == "5":
            client.show("finding", "prioritize", finding)
        else:
            status = menu("Triage status", {"1": "open", "2": "triaged", "3": "accepted_risk", "4": "false_positive", "5": "in_progress", "0": "Back"})
            if status != "0":
                value = {"1": "open", "2": "triaged", "3": "accepted_risk", "4": "false_positive", "5": "in_progress"}[status]
                reason = field("Reason", validate=launcher.required_text)
                if yes_no("Set this finding to " + value + "?", default=False):
                    client.show("finding", "triage", finding, "--status", value, "--reason", reason)


def dashboard_state():
    try:
        with urlopen("http://127.0.0.1:8080/api/v1/health", timeout=1) as response:
            body = json.load(response)
            return "ready" if body.get("status") == "ok" and "version" in body else "other"
    except URLError:
        return "unavailable"
    except (ValueError, OSError):
        return "other"


def open_dashboard(client):
    if dashboard_state() != "ready":
        try:
            open_window(client, dashboard=True)
        except (UiError, OSError, subprocess.TimeoutExpired):
            tell("Could not open a dashboard window. Your home menu is still available.")
            tell("From another terminal in this folder, run .venv/bin/python terminal_ui.py --dashboard")
            return
        for _ in range(10):
            if dashboard_state() == "ready":
                break
            time.sleep(0.5)
    if dashboard_state() == "ready":
        open_dashboard_browser(client)
        tell("Dashboard: http://127.0.0.1:8080 (the existing server is reused when available).")
    else:
        tell("Dashboard window requested. Check that window for startup errors or a port conflict.")
    tell("Sign in with your local token file: " + str(client.token_file))
    if client.env.get("WSL_DISTRO_NAME"):
        tell("Copy this project's token: clip.exe < " + shlex.quote(str(client.token_file)))
    else:
        tell("On macOS, copy privately: pbcopy < " + shlex.quote(str(client.token_file)))


def open_dashboard_browser(client):
    if client.env.get("WSL_DISTRO_NAME"):
        powershell = shutil.which("powershell.exe", path=client.env.get("PATH"))
        if powershell:
            result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command",
                                     "Start-Process 'http://localhost:8080'"], capture_output=True, timeout=15)
            if result.returncode == 0:
                return
        tell("Open http://localhost:8080 in your Windows browser.")
    else:
        webbrowser.open("http://127.0.0.1:8080")


def serve_dashboard(client, *, browse=False):
    """Start the server, wait for readiness, and reap it when this window closes."""
    if dashboard_state() == "ready":
        tell("Dashboard is already running at http://localhost:8080.")
        if browse:
            open_dashboard_browser(client)
        return 0
    if dashboard_state() == "other":
        raise UiError("Port 8080 is occupied by another service. Stop that service or use another dashboard port.")
    server = subprocess.Popen(client.command("serve"), cwd=client.root, env=client.env)
    try:
        for _ in range(60):
            if server.poll() is not None:
                raise UiError("Dashboard exited before it was ready. Check the server message above.")
            if dashboard_state() == "ready":
                tell("Dashboard ready: http://localhost:8080. Keep this window open; Ctrl+C stops the server.")
                tell("Login token file: " + str(client.token_file))
                if browse:
                    open_dashboard_browser(client)
                return server.wait()
            time.sleep(0.25)
        raise UiError("Dashboard startup timed out. Check database connectivity and port 8080.")
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


def accessible_projects(client, preferences):
    """(project, token file) for every active project the remembered tokens of this profile can open."""
    candidates = {}
    paths = [client.token_file]
    paths += [Path(p) for key, p in preferences.data["tokens"].items()
              if isinstance(key, str) and key.startswith(client.profile + ":") and isinstance(p, str)]
    for path in dict.fromkeys(paths):
        candidate = Client(client.root, profile=client.profile, token_file=path, env=client.env)
        try:
            for project in candidate.json("projects"):
                if not project["archived"]:
                    candidates[project["slug"]] = (project, path)
        except UiError:
            continue
    return sorted(candidates.values(), key=lambda entry: entry[0]["slug"])


def select_project(client, preferences):
    while True:
        rows = accessible_projects(client, preferences)
        if not rows:
            tell("No accessible projects found with the selected token files. Create a project, choose another token, or check .env and PostgreSQL.")
        options = {str(i): safe(f"{p['name']} ({p['slug']}, {p['role']})") for i, (p, _) in enumerate(rows, 1)}
        default = next((str(i) for i, (p, _) in enumerate(rows, 1) if p["slug"] == preferences.data.get("project")), "1" if rows else "0")
        action = menu("Projects - choose a number", {**options, "c": "Create project", "t": "Use another token file",
                      "p": "Change profile (current: " + client.profile + ")", "0": "Back"}, default)
        if action == "0":
            raise Back()
        if action == "p":
            choice = menu("Profile", {"1": "Development", "2": "Lab", "3": "Production", "0": "Back"})
            if choice != "0":
                client = Client(client.root, profile=PROFILES[int(choice) - 1], env=client.env)
        elif action == "t":
            path = field("Existing token FILE path (not the token itself)", validate=launcher.required_text)
            client = Client(client.root, profile=client.profile, token_file=path, env=client.env)
            # Validate immediately, with useful failure feedback.
            client.json("projects")
        elif action == "c":
            slug = field("New project NAME (text, e.g. acme-lab)", validate=launcher.project_slug)
            owner = field("Your name", validate=launcher.required_text)
            if not yes_no("Create this project using your configured database access?", default=False):
                continue
            directory = preferences.directory / "tokens"
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            token = directory / (client.profile + "-" + slug + "-" + uuid4().hex)
            client.show("bootstrap", slug, "--owner", owner, "--save-token", str(token))
            client = Client(client.root, profile=client.profile, project=slug, token_file=token, env=client.env)
            preferences.save(client.profile, slug, token)
            return client
        else:
            project, token = rows[int(action) - 1]
            client = Client(client.root, profile=client.profile, project=project["slug"], token_file=token, env=client.env)
            preferences.save(client.profile, client.project, token)
            return client


def settings_menu(client, preferences):
    while True:
        action = menu("Settings and help", {"1": "Change profile", "2": "Token and configuration help", "3": "Legacy discovery help",
                                            "4": "Effective settings and rule coverage", "5": "Intelligence feed status", "0": "Back"})
        if action == "0":
            return client
        if action == "1":
            choice = menu("Profile", {"1": "Development", "2": "Lab (isolated lab setup required)", "3": "Production", "0": "Back"})
            if choice != "0":
                candidate = Client(client.root, profile=PROFILES[int(choice) - 1], env=client.env)
                client = select_project(candidate, preferences)
                return client
        elif action == "2":
            tell("Platform: PostgreSQL, scope revisions and owner/operator/viewer roles.")
            tell("Secrets load from .env. UI remembers project/profile and token FILE paths only.")
            tell("Token file: " + str(client.token_file))
            tell("New windows read .env again. Shell-only credentials are not embedded in launch commands.")
            tell("Pending detection rules stay disabled. See docs/installation.md and rules/README.md.")
            tell("Closing a scan window stops its local processing, not the queued run. Cancel explicitly in View scan progress.")
            tell("Noninteractive commands: watchtower projects; watchtower --project <slug> run list; watchtower --help.")
        elif action == "4":
            tell(json.dumps(client.json("settings"), indent=2))
        elif action == "5":
            client.show("intelligence", "status")
        else:
            tell("Legacy discovery is separate: python launcher.py --legacy")
            tell("It uses MongoDB, targets.json and setting.json. Platform scope lives in PostgreSQL.")


# -- Continuous monitoring --------------------------------------------------
#
# Home writes a monitoring plan; a separate window runs the worker and starts
# one scan per monitored target each interval. Scans start through the same CLI
# as Scan once, so saved authorization, exclusions, request limits and
# detection-rule approvals apply unchanged.

INTERVALS = {"1": ("1 hour", 3600), "2": ("3 hours", 3 * 3600), "3": ("6 hours", 6 * 3600),
             "4": ("12 hours", 12 * 3600), "5": ("24 hours", 24 * 3600)}
DEFAULT_INTERVAL = 6 * 3600
AWAKE = ("Monitoring runs only while this computer is awake and the monitoring window stays open. "
         "Sleep, shutdown or closing the window pauses it. Missed scans are not replayed: one scan "
         "starts when monitoring resumes.")


def interval_seconds(value):
    match = re.fullmatch(r"(\d{1,6})\s*([mhd])", value.strip().lower())
    if not match:
        raise ValueError("Use a number followed by m, h or d, for example 90m, 8h or 2d.")
    seconds = int(match.group(1)) * {"m": 60, "h": 3600, "d": 86400}[match.group(2)]
    if not 15 * 60 <= seconds <= 30 * 86400:
        raise ValueError("Choose an interval between 15 minutes and 30 days.")
    return seconds


def describe_interval(seconds):
    if seconds % 86400 == 0 and seconds > 86400:
        return f"{seconds // 86400} days"
    for unit, size in (("hour", 3600), ("minute", 60)):
        if seconds % size == 0:
            count = seconds // size
            return f"{count} {unit}" + ("" if count == 1 else "s")
    return f"{seconds} seconds"


def local_time(value):
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return "-"


def watch_key(watch):
    return watch["project"] + ":" + ",".join(watch["targets"])


class MonitorStore:
    """One monitoring plan per profile, under the ignored files/terminal-ui directory.

    Home writes the plan and the monitoring window writes its progress, so
    neither process overwrites the other. The window holds a lock while it runs;
    a closed or crashed window releases it.
    """
    def __init__(self, root, profile):
        files = Path(root) / "files" / "terminal-ui"
        self.directory = files / "monitors"
        self.plan_path = self.directory / (profile + ".json")
        self.progress_path = self.directory / (profile + ".progress.json")
        self.lock_path = files / "locks" / ("monitor-" + profile)

    @staticmethod
    def _read(path):
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _write(self, path, data):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, name = tempfile.mkstemp(dir=self.directory)
        try:
            with os.fdopen(descriptor, "w") as output:
                json.dump(data, output, indent=2)
            os.replace(name, path)
        finally:
            Path(name).unlink(missing_ok=True)

    def plan(self):
        """The plan, unless it is missing, stopped or unreadable."""
        plan = self._read(self.plan_path)
        valid = (plan.get("state") in ("active", "paused") and isinstance(plan.get("interval"), int)
                 and isinstance(plan.get("watches"), list) and plan["watches"])
        return plan if valid else {}

    def save_plan(self, plan):
        self._write(self.plan_path, plan)

    def progress(self, plan):
        progress = self._read(self.progress_path)
        if progress.get("plan") != plan.get("id") or not isinstance(progress.get("watches"), dict):
            return {"plan": plan.get("id"), "watches": {}}
        return progress

    def save_progress(self, progress):
        self._write(self.progress_path, progress)

    def running(self):
        if not self.lock_path.exists():
            return False
        with self.lock_path.open("a") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(handle, fcntl.LOCK_UN)
            return False

    @contextmanager
    def hold(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.lock_path.open("a") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise UiError("Continuous monitoring is already running in another window.") from None
            yield


def monitored_scans(runs, watch):
    """Scans of this watch's targets, newest first. A whole-scope watch counts every scan in its project."""
    return [r for r in runs if r.get("kind") == "scan" and (not watch["targets"] or r.get("targets") == watch["targets"])]


def next_scan(plan, entry, current, running, now):
    if not running:
        return "when monitoring resumes"
    if plan["state"] == "paused":
        return "paused"
    started = entry.get("started_at")
    due = datetime.fromisoformat(started) + timedelta(seconds=plan["interval"]) if started else now
    if due > now:
        return local_time(due.isoformat())
    return "after the current scan finishes" if current else "now"


class Monitor:
    """Starts one scan per monitored target each interval, never two for the same target at once."""
    def __init__(self, client, store, *, clock=None):
        self.client = client
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.clients = {}
        self.ai_requested = False  # an AI review was queued; the window then starts its AI worker

    def client_for(self, watch):
        key = (watch["project"], watch["token_file"])
        if key not in self.clients:
            self.clients[key] = Client(self.client.root, profile=self.client.profile, project=watch["project"],
                                       token_file=watch["token_file"], env=self.client.env)
        return self.clients[key]

    def tick(self, plan, progress, *, start=True):
        """Start due scans when start is set; return what each watch shows."""
        now = self.clock()
        views = []
        for watch in plan["watches"]:
            entry = progress["watches"].setdefault(watch_key(watch), {"sequence": 0})
            client = self.client_for(watch)
            view = {"watch": watch, "entry": entry, "runs": None, "phase": None}
            views.append(view)
            try:
                view["runs"] = client.json("run", "list", "--limit", "50")
            except UiError as exc:
                entry["error"] = str(exc)
                continue
            try:
                busy = any(r["status"] not in FINISHED for r in monitored_scans(view["runs"], watch))
                if start and plan["state"] == "active" and not busy and self.due(plan, entry, now):
                    self.start(plan, progress, watch, entry, client, now)
                    view["runs"] = client.json("run", "list", "--limit", "50")
                elif start:
                    entry.pop("error", None)
                current = next((r for r in monitored_scans(view["runs"], watch) if r["status"] not in FINISHED), None)
                if current:
                    view["phase"] = current_phase(client.json("run", "show", current["run_id"]))
                elif start:
                    self.review_changed(watch, entry, client, view["runs"])
            except UiError as exc:
                entry["error"] = str(exc)
        return views

    def review_changed(self, watch, entry, client, runs):
        """Opt-in: after a scan this monitor started, collect and AI-review the target's scripts once.

        Unchanged code is answered from the review cache, so only new or changed scripts reach the model.
        """
        last = next((r for r in monitored_scans(runs, watch) if r["status"] in ("succeeded", "partial")), None)
        if not last or last["run_id"] != entry.get("run_id") or entry.get("ai_after") == last["run_id"]:
            return
        entry["ai_after"] = last["run_id"]  # decided once per scan, whatever the answer
        try:
            status = client.json("ai", "status")
        except (UiError, KeyError, TypeError):
            return  # AI review being unavailable never affects monitoring
        if not (isinstance(status, dict) and status.get("enabled") and
                (status.get("project") or {}).get("review_changed_scripts")):
            return
        args = ["ai", "collect", "--review", "--idempotency-key", "monitor-ai-" + last["run_id"]]
        for target in watch["targets"]:
            args += ["--target", target]
        # Keyed by the scan, so a restart before progress is saved returns the same run instead of a second one.
        run = client.json(*args)
        entry.update(ai_after=last["run_id"], ai_run=run["run"]["run_id"])
        self.ai_requested = True

    @staticmethod
    def due(plan, entry, now):
        started = entry.get("started_at")
        return not started or datetime.fromisoformat(started) + timedelta(seconds=plan["interval"]) <= now

    def start(self, plan, progress, watch, entry, client, now):
        # The key only changes once this start is saved, so a crash in between
        # returns the same run on restart instead of queueing a second one.
        digest = hashlib.sha256(watch_key(watch).encode()).hexdigest()[:16]
        key = f"monitor-{plan['id']}-{digest}-{entry['sequence']}"
        args = ["run", "start", "--reason", "continuous monitoring every " + describe_interval(plan["interval"]),
                "--reuse-active", "--idempotency-key", key]
        for target in watch["targets"]:
            args += ["--target", target]
        # The same lock as Scan once, so Home and monitoring cannot queue the same target together.
        with session_lock(client, "start"):
            try:
                run = client.json(*args)
            except UiError as exc:
                if "idempotency key" in str(exc):
                    # The scope changed since this key was used; retry with a new key.
                    entry["sequence"] += 1
                    self.store.save_progress(progress)
                raise
        entry.update(sequence=entry["sequence"] + 1, run_id=run["run_id"], started_at=now.isoformat())
        entry.pop("error", None)
        self.store.save_progress(progress)


def monitoring_lines(plan, views, now, running):
    state = plan["state"].upper() if running else "NOT RUNNING (monitoring window closed)"
    count = len(plan["watches"])
    lines = [f"Continuous monitoring: {state} | every {describe_interval(plan['interval'])} | "
             f"{count} target{'' if count == 1 else 's'}"]
    for view in views:
        watch, entry, runs = view["watch"], view["entry"], view["runs"]
        lines.append(watch["label"] + " (project " + watch["project"] + ")")
        if runs is None:
            lines.append("  Status unavailable: " + entry.get("error", "check .env and PostgreSQL"))
            continue
        scans = monitored_scans(runs, watch)
        current = next((r for r in scans if r["status"] not in FINISHED), None)
        last = next((r for r in scans if r["status"] in FINISHED), None)
        lines.append("  Current scan: " + (f"{current['status'].upper()} {current['run_id'][:8]}"
                                           + (" - " + view["phase"] if view["phase"] else "") if current else "none"))
        lines.append("  Last scan: " + (f"{last['status'].upper()} {last['run_id'][:8]}, finished "
                                        + local_time(last.get("finished_at")) if last else "none yet"))
        lines.append("  Next scan: " + next_scan(plan, entry, current, running, now))
        if entry.get("error"):
            lines.append("  Problem: " + entry["error"])
    return lines


def monitoring_status(client):
    """Home's status line, or None when nothing is monitored."""
    store = MonitorStore(client.root, client.profile)
    plan = store.plan()
    if not plan:
        return None
    if not store.running():
        return "Monitoring: NOT RUNNING - resume it from Start scan > Continuous monitoring"
    line = f"Monitoring: {plan['state'].upper()} every {describe_interval(plan['interval'])}"
    progress = store.progress(plan)
    starts = [progress["watches"].get(watch_key(w), {}).get("started_at") for w in plan["watches"]]
    if plan["state"] == "active" and all(starts):
        due = min(datetime.fromisoformat(s) for s in starts) + timedelta(seconds=plan["interval"])
        line += " | next " + (local_time(due.isoformat()) if due > datetime.now(timezone.utc) else "now")
    return line


def monitor_window(client, *, interval=10):
    """The separate monitoring terminal: worker, schedule and live status until stopped or closed."""
    store = MonitorStore(client.root, client.profile)
    with store.hold():
        plan = store.plan()
        if not plan:
            tell("Continuous monitoring is not set up. Use Home > Start scan > Continuous monitoring.")
            return 0
        tell(AWAKE)
        tell("Closing this window or Ctrl+C pauses monitoring and cancels no scan. "
             "Pause, resume or stop it from Home > Start scan > Continuous monitoring.")
        tell("This window's worker may also process due jobs and notifications from other projects.")
        monitor = Monitor(client, store)
        processor = LocalProcessor(client)
        processor.start()
        ai_processor = AiProcessor(client)
        mark = SCREEN.mark()
        previous = None
        try:
            while True:
                plan = store.plan()
                if not plan:
                    tell("Monitoring was stopped from Home. Scans in progress were not cancelled by this window.")
                    return 0
                progress = store.progress(plan)
                lines = monitoring_lines(plan, monitor.tick(plan, progress), monitor.clock(), True)
                store.save_progress(progress)
                if SCREEN.enabled or lines != previous:
                    with SCREEN.frame(mark):
                        tell()
                        for line in lines:
                            tell(line)
                    previous = lines
                if processor.error:
                    raise UiError("The local worker stopped (" + processor.error + "). Monitoring is paused; "
                                  "resume it from Home. No scan was cancelled.")
                if monitor.ai_requested:
                    ai_processor.start()
                if ai_processor.error:
                    tell("The AI worker stopped (" + ai_processor.error + "). Scans continue; AI reviews wait "
                         "until monitoring is resumed.")
                    ai_processor = AiProcessor(client)
                    monitor.ai_requested = False
                time.sleep(interval)
        except KeyboardInterrupt:
            tell("Monitoring window closed. Monitoring is paused until you resume it from Home; "
                 "scans in progress were not cancelled.")
            return 0
        finally:
            processor.close()
            ai_processor.close()


def launch_monitor(client):
    while True:
        try:
            open_window(client, monitor=True)
            tell("Monitoring window requested. Home stays available here.")
            tell("If no window appears, choose Resume monitoring in Continuous monitoring to retry.")
            return
        except (UiError, OSError, subprocess.TimeoutExpired) as exc:
            tell(str(exc) if isinstance(exc, UiError) else "Could not open the monitoring window.")
            action = menu("Where should monitoring run?", {"1": "Retry new window", "2": "Run monitoring in this terminal",
                                                         "0": "Back - monitoring stays set up; resume it later"}, "0")
            if action == "2":
                process_here(client, monitor=True)
                return
            if action == "0":
                return


def choose_interval(current=DEFAULT_INTERVAL):
    options = {key: label + (" (default)" if seconds == DEFAULT_INTERVAL else "") for key, (label, seconds) in INTERVALS.items()}
    default = next((key for key, (_, seconds) in INTERVALS.items() if seconds == current), "6")
    choice = menu("How often should it scan?", {**options, "6": "Custom interval", "0": "Back"}, default)
    if choice == "0":
        raise Back()
    if choice == "6":
        return field("Interval, for example 90m, 8h or 2d", validate=interval_seconds)
    return INTERVALS[choice][1]


def all_watches(client, preferences):
    """Every authorized project you can operate, monitoring all targets in its published scope."""
    watches = []
    for project, token in accessible_projects(client, preferences):
        if project["role"] not in ("owner", "operator"):
            continue
        candidate = Client(client.root, profile=client.profile, project=project["slug"], token_file=token, env=client.env)
        try:
            roots = saved_roots(candidate.json("status"))
        except UiError:
            continue
        if roots:
            watches.append({"project": project["slug"], "token_file": str(token), "targets": [], "label": ", ".join(roots)})
    return watches


def setup_monitoring(client, preferences, store):
    tell("Continuous monitoring scans now, then again at the interval you choose.")
    status = client.json("status")
    roots = saved_roots(status)
    if roots:
        options = {str(i): domain for i, domain in enumerate(roots, 1)}
        new_choice, saved_choice = str(len(roots) + 1), str(len(roots) + 2)
        action = menu("What would you like to monitor?", {**options, new_choice: "Add a new target",
                      saved_choice: "Choose another saved target", "0": "Back"}, "1")
        if action == "0":
            return client
        if action == saved_choice:
            return setup_monitoring(select_project(client, preferences), preferences, store)
        if action == new_choice:
            client, target = add_scan_target(client, status, preferences)
        else:
            target = roots[int(action) - 1]
    else:
        client, target = add_scan_target(client, status, preferences)
    watches = [{"project": client.project, "token_file": str(client.token_file), "targets": [target], "label": target}]
    choice = menu("Which targets should be monitored?", {"1": "Only " + target + " (recommended)",
                  "2": "All authorized projects and every target in their scope", "0": "Back"}, "1")
    if choice == "0":
        raise Back()
    if choice == "2":
        watches = all_watches(client, preferences)
        if not watches:
            tell("No authorized project with a published scope was found for your token files.")
            raise Back()
        tell("Each interval would scan every target below:")
        for watch in watches:
            tell(f"  {watch['label']} (project {watch['project']})")
        if not yes_no("Monitor ALL of these projects and targets?", default=False):
            raise Back()
    interval = choose_interval()
    tell("\nMonitor:")
    for watch in watches:
        tell(f"  {watch['label']} (project {watch['project']})")
    tell("Every " + describe_interval(interval) + ". The first scan starts as soon as the monitoring window opens.")
    tell("A target that is already being scanned is not scanned twice; monitoring waits for that scan.")
    tell("Saved permissions, exclusions, request limits and detection-rule approvals apply to every scan.")
    tell(AWAKE)
    tell("Stopping monitoring later keeps a running scan unless you choose Stop and cancel.")
    if not yes_no("Start continuous monitoring?", default=False):
        raise Back()
    store.save_plan({"id": str(uuid4()), "state": "active", "interval": interval,
                     "created_at": datetime.now(timezone.utc).isoformat(), "watches": watches})
    launch_monitor(client)
    return client


def view_monitored_scan(monitor, views, running):
    current = [(view["watch"], run) for view in views for run in monitored_scans(view["runs"] or [], view["watch"])
               if run["status"] not in FINISHED]
    if not current:
        tell("No monitored scan is running right now.")
        return
    choice = "1"
    if len(current) > 1:
        options = {str(i): f"{watch['label']} ({run['run_id'][:8]})" for i, (watch, run) in enumerate(current, 1)}
        choice = menu("Which scan?", {**options, "0": "Back"}, "1")
        if choice == "0":
            return
    watch, run = current[int(choice) - 1]
    if not running:
        tell("The monitoring window is closed, so this scan only advances when monitoring resumes.")
    watch_run(monitor.client_for(watch), run["run_id"])


def monitoring_menu(client, preferences):
    store = MonitorStore(client.root, client.profile)
    while True:
        plan = store.plan()
        if not plan:
            if store.running():
                tell("The previous monitoring window is still stopping. Try again in a moment.")
                return client
            return setup_monitoring(client, preferences, store)
        running = store.running()
        monitor = Monitor(client, store)
        views = monitor.tick(plan, store.progress(plan), start=False)
        for line in monitoring_lines(plan, views, monitor.clock(), running):
            tell(line)
        if not running:
            toggle = "Resume monitoring (reopen the monitoring window)"
        elif plan["state"] == "paused":
            toggle = "Resume monitoring"
        else:
            toggle = "Pause monitoring (a running scan finishes; no new scans start)"
        action = menu("Continuous monitoring", {"1": "View current scan progress", "2": toggle, "3": "Change interval",
                      "4": "Stop monitoring (keep any running scan)", "5": "Stop monitoring and cancel running scans",
                      "0": "Back"})
        if action == "0":
            return client
        if action == "1":
            view_monitored_scan(monitor, views, running)
        elif action == "2":
            plan["state"] = "paused" if running and plan["state"] == "active" else "active"
            store.save_plan(plan)
            if not running:
                launch_monitor(client)
            else:
                tell("Monitoring " + ("paused. A running scan finishes; no new scans start." if plan["state"] == "paused"
                                      else "resumed. A scan starts now if one is due."))
        elif action == "3":
            plan["interval"] = choose_interval(plan["interval"])
            store.save_plan(plan)
            tell("Interval changed to every " + describe_interval(plan["interval"]) +
                 ". The next scan is counted from the start of the last one.")
        elif action == "4":
            if yes_no("Stop monitoring? Running scans are not cancelled and can be resumed from View scan progress.",
                      default=False):
                plan["state"] = "stopped"
                store.save_plan(plan)
                tell("Monitoring stopped. Running scans were kept.")
                return client
        elif yes_no("Stop monitoring and cancel every running scan of the monitored targets?", default=False):
            # Stop first, so the window starts nothing new while scans are cancelled.
            plan["state"] = "stopped"
            store.save_plan(plan)
            for view in views:
                for run in monitored_scans(view["runs"] or [], view["watch"]):
                    if run["status"] not in FINISHED:
                        monitor.client_for(view["watch"]).show("run", "cancel", run["run_id"],
                                                               "--reason", "continuous monitoring stopped")
            tell("Monitoring stopped and running scans were cancelled. Existing findings are not resolved.")
            return client


# -- AI security review -------------------------------------------------------
#
# Optional and local-only. Every action goes through `watchtower ai ...`, so the
# backend checks roles, scope and settings; this menu only explains and confirms.

MEMORY_SENTENCE = ("Approved examples can guide future reviews in this project. "
                   "This does not retrain the model.")
AI_CATEGORIES = {"1": "dom_xss_sink", "2": "open_redirect", "3": "sensitive_data_in_client", "4": "insecure_token_storage",
                 "5": "weak_csp", "6": "cors_misconfiguration", "7": "outdated_library", "8": "exposed_endpoint",
                 "9": "debug_artifact", "10": "other"}


def ai_status_lines(status):
    state = "ENABLED" if status["enabled"] else "DISABLED (pre-analysis only)"
    memory = status["memory"]
    waiting = f", {memory['awaiting_approval']} awaiting approval" if memory.get("awaiting_approval") is not None else ""
    lines = [f"AI review: {state} | model {status['model']} | {memory['approved']} approved example(s){waiting}"]
    latest = status.get("latest_analysis")
    if latest:
        lines.append(f"Latest review: {latest['status'].upper()} {latest['id'][:8]}"
                     + (" (may be outdated)" if latest.get("outdated") else ""))
    return lines


def ai_preview(client, args):
    plan = client.json("ai", "preview", *args)
    tell("\nPreview what will be sent to the local model")
    tell(plan["visible"])
    for item in plan["files"]:
        sent = "sent" if item["sent"] else "not sent"
        tell(f"  {item['kind']}: {item['url'][:90]} ({item['size_bytes']} bytes, {item['redactions']} redacted, {sent})")
        tell(f"    {item['origin']}")
    tell(f"{plan['chunks']} chunk(s), about {plan['token_estimate']} tokens, {plan['redactions']} redaction(s). "
         f"Model {plan['model']}, context {plan['num_ctx']} tokens. Nothing leaves this computer's model server.")
    for item in plan["skipped"][:5]:
        tell(f"  Left out: {item['url'] or 'scan evidence'} lines {item['lines']}: {item['reason']}")
    return plan


def ai_review(client, *, finding=None):
    """Review latest scan evidence and collected scripts (or one finding): preview, confirm, queue, open a window."""
    status = client.json("ai", "status")
    args = ["--finding", finding] if finding else []
    plan = ai_preview(client, args)
    if not plan["files"]:
        tell("Nothing to review yet. Run a scan or Collect scripts for review first.")
        return
    use_model = status["enabled"]
    if not use_model:
        tell("AI review is disabled, so no model is used. Pre-analysis (deterministic checks) still runs.")
        if not yes_no("Run pre-analysis only?", default=True):
            return
    elif not yes_no("Send this to the local model and start the review?", default=False):
        return
    result = client.json("ai", "review", *args, *([] if use_model else ["--no-model"]),
                         "--idempotency-key", str(uuid4()))
    tell("Queued review " + str(result["analysis_id"]) + ".")
    launch_scan(client, result["run"]["run_id"])


def ai_collect(client):
    status = client.json("ai", "status")
    if not status["enabled"]:
        tell("AI review is disabled; collection is not available. See Model status for how to enable it.")
        return
    roots = saved_roots(client.json("status"))
    if not roots:
        tell("No authorized target yet. Start a scan first so the scope is saved.")
        return
    tell("\nCollect scripts for review")
    tell("This fetches in-scope pages and the scripts they reference, within the saved scope, exclusions, ports, "
         "paths and request limits. Third-party or out-of-scope scripts are recorded, never fetched. "
         "Nothing downloaded is executed.")
    tell("Page HTML and inline scripts are kept only if the project owner turned on response-body retention "
         "(currently " + ("on" if status["project"]["retain_response_bodies"] else "off") + ").")
    options = {str(i): domain for i, domain in enumerate(roots, 1)}
    choice = menu("Which target?", {**options, "0": "Back"}, "1")
    if choice == "0":
        return
    target = roots[int(choice) - 1]
    page = field("Start page (Enter: https://" + target + "/)", "https://" + target + "/")
    review = yes_no("Review the collected scripts when collection finishes?", default=True)
    if not yes_no("Collect from " + page + " now?", default=False):
        return
    with session_lock(client, "ai-collect"):
        result = client.json("ai", "collect", "--target", target, "--url", page, *(["--review"] if review else []),
                             "--idempotency-key", str(uuid4()))
    tell("Queued collection run " + result["run"]["run_id"] + ".")
    launch_scan(client, result["run"]["run_id"])


def choose_review(client):
    rows = client.json("ai", "results", "--limit", "20")
    if not rows:
        tell("No AI reviews yet.")
        raise Back()
    options = {str(i): f"{r['id'][:8]} {r['status']} {r['mode']} - {r['candidates']['supported']} candidate(s)"
                       + (" - may be outdated" if r["outdated"] else "") for i, r in enumerate(rows, 1)}
    choice = menu("AI reviews", {**options, "0": "Back"}, "1")
    if choice == "0":
        raise Back()
    return rows[int(choice) - 1]["id"]


def ai_results(client):
    analysis = choose_review(client)
    while True:
        client.show("ai", "show", analysis)
        action = menu("Review " + analysis[:8], {"1": "Give feedback on a candidate", "2": "Request reanalysis",
                                                 "0": "Back"}, "0")
        if action == "0":
            return
        if action == "1":
            ai_feedback(client, analysis)
        elif yes_no("Review the same sources again? Earlier results are kept unchanged.", default=False):
            result = client.json("ai", "review", "--reanalysis-of", analysis, "--idempotency-key", str(uuid4()))
            launch_scan(client, result["run"]["run_id"])
            return


def ai_feedback(client, analysis=None):
    analysis = analysis or choose_review(client)
    detail = client.json("ai", "show", analysis)
    candidates = detail["candidates"]
    if not candidates:
        tell("This review has no candidates.")
        return
    options = {str(i): f"{'' if c['supported'] else '[unsupported] '}{c['title'][:70]} ({c['confidence']})"
               for i, c in enumerate(candidates, 1)}
    choice = menu("Which candidate?", {**options, "0": "Back"}, "1")
    if choice == "0":
        return
    candidate = candidates[int(choice) - 1]
    kind = menu("Your feedback", {"1": "Looks correct (your review, not a verification)",
                                  "2": "False positive (say why it does not apply here)",
                                  "3": "Edit analysis (corrected explanation, category or applicability)", "0": "Back"})
    if kind == "0":
        return
    args = ["ai", "feedback", candidate["id"], "--kind", {"1": "looks_correct", "2": "false_positive", "3": "edit"}[kind]]
    if kind == "2":
        args += ["--reason", field("Why does it not apply here?", validate=launcher.required_text)]
    elif kind == "3":
        explanation = field("Corrected explanation (Enter: unchanged)")
        if explanation:
            args += ["--explanation", explanation]
        if yes_no("Change the category?", default=False):
            category = menu("Category", {**{k: v.replace("_", " ") for k, v in AI_CATEGORIES.items()}, "0": "Back"})
            if category != "0":
                args += ["--category", AI_CATEGORIES[category]]
        applicability = field("When does this apply? (Enter: unchanged)")
        if applicability:
            args += ["--applicability", applicability]
        if len(args) == 5:
            tell("Nothing was changed; no feedback recorded.")
            return
    tell(MEMORY_SENTENCE)
    if yes_no("Submit as a project-memory example for approval?", default=False):
        args += ["--memory", "--context", field("When should this example apply? (Enter: derived automatically)")]
    client.show(*args)


def ai_memory_list(client, status):
    rows = client.json("ai", "memory", "list", "--status", status)
    tell(MEMORY_SENTENCE)
    if not rows:
        tell("No " + ("examples awaiting approval." if status == "submitted" else "approved examples."))
        raise Back()
    options = {str(i): f"{r['id'][:8]} r{r['current_revision']} {(r['content'] or {}).get('verdict', '')}: "
                       f"{(r['content'] or {}).get('title', '')[:60]}" for i, r in enumerate(rows, 1)}
    choice = menu("Memory examples", {**options, "0": "Back"}, "1")
    if choice == "0":
        raise Back()
    return rows[int(choice) - 1]


def ai_memory(client, status):
    example = ai_memory_list(client, status)
    client.show("ai", "memory", "show", example["id"])
    if status == "submitted":
        action = menu("Example " + example["id"][:8], {"1": "Approve", "2": "Approve my own submission (self-approve)",
                                                       "3": "Reject", "4": "Edit", "0": "Back"}, "0")
        if action == "1":
            client.show("ai", "memory", "approve", example["id"])
        elif action == "2":
            if yes_no("This is recorded as self-approved. Continue?", default=False):
                client.show("ai", "memory", "approve", example["id"], "--self-approve")
        elif action == "3":
            client.show("ai", "memory", "reject", example["id"], "--reason",
                        field("Why is it rejected?", validate=launcher.required_text))
        elif action == "4":
            ai_memory_edit(client, example["id"])
    else:
        action = menu("Example " + example["id"][:8], {"1": "Disable", "2": "Edit", "0": "Back"}, "0")
        if action == "1" and yes_no("Stop using this example in new reviews?", default=False):
            client.show("ai", "memory", "disable", example["id"], "--reason", field("Reason (optional)"))
        elif action == "2":
            ai_memory_edit(client, example["id"])


def ai_memory_edit(client, example_id):
    args = ["ai", "memory", "edit", example_id]
    explanation = field("Corrected explanation (Enter: unchanged)")
    if explanation:
        args += ["--explanation", explanation]
    pattern = field("Path pattern, e.g. /static/js/*.js (Enter: unchanged)")
    if pattern:
        args += ["--condition", "path_pattern=" + pattern]
    context = field("When it applies (Enter: unchanged)")
    if context:
        args += ["--condition", "context=" + context]
    if len(args) == 4:
        tell("Nothing was changed.")
        return
    args += ["--note", field("Note for the history (optional)")]
    client.show(*args)
    tell("Reviews that used this example are marked as possibly outdated; request a reanalysis to refresh them.")


def ai_model_status(client):
    report = client.json("ai", "check")
    tell(report["outcome"].upper().replace("_", " ") + ": " + report["message"])
    if report.get("endpoint"):
        tell("Endpoint: " + report["endpoint"] + (" (" + report["endpoint_kind"] + ")" if report.get("endpoint_kind") else ""))
    if report.get("installed_models"):
        tell("Installed models: " + ", ".join(report["installed_models"]))
    for line in report.get("guidance", []):
        tell(line)


def ai_advanced(client):
    status = client.json("ai", "status")
    tell("Technical AI settings (from the profile and .env; change them there):")
    for key, value in status["advanced"].items():
        tell(f"  {key}: {value}")
    tell("Project switches (owner only):")
    switches = {"1": ("retain_response_bodies", "retain-bodies", "Keep page HTML and inline scripts for review"),
                "2": ("allow_source_maps", "source-maps", "Fetch in-scope source maps"),
                "3": ("memory_require_second_reviewer", "second-reviewer", "Require a second reviewer for memory"),
                "4": ("review_changed_scripts", "review-changed", "Continuous monitoring: AI review changed scripts")}
    options = {key: f"{label}: {'on' if status['project'][name] else 'off'}" for key, (name, _, label) in switches.items()}
    choice = menu("Change a project switch", {**options, "0": "Back"}, "0")
    if choice == "0":
        return
    name, flag, label = switches[choice]
    new = "off" if status["project"][name] else "on"
    if yes_no(f"Turn {label.lower()} {new}?", default=False):
        client.show("ai", "settings", "--" + flag, new)


def ai_menu(client):
    while True:
        try:
            status = client.json("ai", "status")
        except UiError as exc:
            tell("AI review status is unavailable: " + str(exc))
            return
        for line in ai_status_lines(status):
            tell(line)
        action = menu("AI security review", {"1": "Review latest scan", "2": "Collect scripts for review (operator)",
                                             "3": "View results", "4": "Give feedback",
                                             "5": "Memory awaiting approval (owner)", "6": "Approved examples",
                                             "7": "Model status", "8": "Advanced", "0": "Back"}, "0")
        try:
            if action == "0":
                return
            if action == "1":
                ai_review(client)
            elif action == "2":
                ai_collect(client)
            elif action == "3":
                ai_results(client)
            elif action == "4":
                ai_feedback(client)
            elif action == "5":
                ai_memory(client, "submitted")
            elif action == "6":
                ai_memory(client, "approved")
            elif action == "7":
                ai_model_status(client)
            else:
                ai_advanced(client)
        except Back:
            continue


def home(root=ROOT):
    preferences = Preferences(root)
    profile = preferences.data.get("profile", "development")
    if profile not in PROFILES:
        profile = "development"
    token = preferences.data.get("token_file")
    client = Client(root, profile=profile, project=preferences.data.get("project", ""), token_file=token)
    if client.project:
        try:
            client.json("status")
        except UiError:
            tell("The remembered project is unavailable. Choose a project or another token.")
            client.project = ""
    if not client.project:
        tell("Platform home - setup is saved between launches. 0 or b returns; Ctrl+C returns home.")
        try:
            client = select_project(client, preferences)
        except Back:
            return 0
    while True:
        try:
            lines = ["DEVILS EYES | Platform", f"Project: {client.project} | Profile: {client.profile}"]
            try:
                status = client.json("status")
                lines.append("Database: Connected | Scope: " + scope_summary(status))
                runs = [r for r in client.json("run", "list", "--limit", "20") if not is_ai(r)][:1]
                if runs:
                    detail = client.json("run", "show", runs[0]["run_id"])
                    lines.append("Latest run: " + runs[0]["status"].upper() + " / " +
                                 ("finished" if runs[0]["status"] in FINISHED else current_phase(detail)))
                else:
                    lines.append("Latest run: none")
            except UiError as exc:
                lines.append("Connection / access unavailable: " + str(exc))
                lines.append("Retry after checking .env and PostgreSQL, or switch project through option 8.")
            monitoring = monitoring_status(client)
            if monitoring:
                lines.append(monitoring)
            SCREEN.show_status(lines)
            action = menu("Home", HOME)
            if action == "0":
                return 0
            if action == "1":
                kind = menu("How do you want to scan?", {"1": "Scan once", "2": "Continuous monitoring", "0": "Back"}, "1")
                if kind == "1":
                    client = start_scan(client, preferences)
                elif kind == "2":
                    client = monitoring_menu(client, preferences)
            elif action == "2":
                progress_menu(client)
            elif action == "3":
                search = field("Search assets (Enter: all)")
                client.show("assets", *(["--search", search] if search else []))
            elif action == "4":
                browse_findings(client)
            elif action == "5":
                manage_scope(client)
            elif action == "6":
                client.show("alerts")
            elif action == "7":
                open_dashboard(client)
            elif action == "8":
                client = select_project(client, preferences)
            elif action == "a":
                ai_menu(client)
            else:
                client = settings_menu(client, preferences)
        except (Back, KeyboardInterrupt):
            tell("\nBack to Home. No implicit scan cancellation.")
        except EOFError:
            return 0
        except (UiError, OSError, subprocess.TimeoutExpired) as exc:
            tell(str(exc) if isinstance(exc, UiError) else "Action could not finish. Check local files, tools and connection settings.")
            tell("Back to Home. Queued actions are not automatically repeated.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, default="development")
    parser.add_argument("--project", default="")
    parser.add_argument("--token-file")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--run", type=UUID)
    mode.add_argument("--dashboard", action="store_true")
    mode.add_argument("--monitor", action="store_true", help="Run continuous monitoring in this window")
    parser.add_argument("--open-browser", action="store_true", help="Open the dashboard after its server is ready")
    parser.add_argument("--hold", action="store_true")
    parser.add_argument("--no-clear", action="store_true", help="Print screens one after another instead of redrawing in place")
    args = parser.parse_args(argv)
    # The dashboard window streams server logs, so it is never redrawn.
    if not args.dashboard:
        SCREEN.start(no_clear=args.no_clear)
    # Terminal close and termination get the same cleanup path as Ctrl+C.
    def interrupted(signum, frame):
        raise KeyboardInterrupt()
    saved_handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGHUP)}
    code = 0
    try:
        if args.run or args.dashboard or args.monitor:
            prefs = Preferences().data if args.dashboard else {}
            client = Client(profile=args.profile or prefs.get("profile", "development"),
                            project=args.project or prefs.get("project", ""),
                            token_file=args.token_file or prefs.get("token_file"))
            os.environ.update(client.env)  # settings/worker read credentials privately from .env
            if sys.stdout.isatty():
                sys.stdout.write("\033]0;Devils Eyes - " + safe(client.project) + "\007")
                sys.stdout.flush()
            if args.dashboard:
                code = serve_dashboard(client, browse=args.open_browser)
            elif args.monitor:
                SCREEN.status = ["DEVILS EYES | Continuous monitoring", f"Profile: {client.profile}"]
                code = monitor_window(client)
            else:
                SCREEN.status = ["DEVILS EYES | Scan progress", f"Project: {safe(client.project)} | Profile: {client.profile}"]
                code = scan_window(client, args.run)
        else:
            code = home()
    except (Back, KeyboardInterrupt, EOFError):
        tell("\nDevils Eyes stopped. Runs were not implicitly cancelled.")
    except (UiError, OSError, subprocess.TimeoutExpired) as exc:
        tell(str(exc) if isinstance(exc, UiError) else "Could not continue. Check configuration and local tools.")
        code = 1
    finally:
        SCREEN.close()
        if args.hold:
            try:
                input("\nSession ended. Press Enter to close this window. ")
            except (EOFError, KeyboardInterrupt):
                pass
        for sig, handler in saved_handlers.items():
            signal.signal(sig, handler)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
