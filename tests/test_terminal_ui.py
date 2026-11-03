"""Terminal UX and process boundaries: never launch terminals or outbound scans."""
import io
import os
import base64
import re
import shlex
import subprocess
from unittest.mock import Mock
from uuid import uuid4

import pytest

import launcher
import terminal_ui as ui


@pytest.fixture
def client(tmp_path):
    return ui.Client(tmp_path, project="acme", token_file=tmp_path / "owner.token", env={})


def run_detail(status="running"):
    return {"run": {"run_id": str(uuid4()), "status": status, "created_at": "2026-10-30T10:00:00+00:00",
                    "finished_at": "2026-10-30T10:02:00+00:00" if status in ui.FINISHED else None},
            "jobs": [{"kind": "monitor.discovery", "status": "running"}], "snapshots": [], "checks_not_run": {}}


def test_preferences_store_paths_only_and_recover_from_corruption(tmp_path):
    prefs = ui.Preferences(tmp_path)
    token = tmp_path / "original.token"
    token.write_text("wt_private_secret")
    prefs.save("development", "acme", token)
    loaded = ui.Preferences(tmp_path)
    assert loaded.data["project"] == "acme"
    assert loaded.data["tokens"]["development:acme"] == str(token)
    assert "wt_private_secret" not in prefs.path.read_text()
    assert prefs.path.stat().st_mode & 0o777 == 0o600
    prefs.path.write_text('{"project": [], "profile": {}, "token_file": 1, "tokens": false}')
    assert ui.Preferences(tmp_path).data == {"tokens": {}}
    prefs.path.write_text("broken")
    assert ui.Preferences(tmp_path).data == {"tokens": {}}


def test_project_selection_is_numbered_and_preserves_token(client, tmp_path, monkeypatch):
    token = client.token_file
    token.write_text("existing-secret")
    prefs = ui.Preferences(tmp_path)
    monkeypatch.setattr(ui.Client, "json", lambda self, *args: [{"slug": "acme", "name": "Acme", "role": "owner", "archived": False}])
    monkeypatch.setattr("builtins.input", lambda prompt: "1")
    result = ui.select_project(client, prefs)
    assert result.project == "acme" and result.token_file == token
    assert token.read_text() == "existing-secret"
    assert prefs.data["project"] == "acme"


def test_new_project_gets_a_unique_token_path(client, tmp_path, monkeypatch):
    client.token_file.write_text("keep-me")
    prefs = ui.Preferences(tmp_path)
    monkeypatch.setattr(ui.Client, "json", lambda self, *args: [])
    show = Mock()
    monkeypatch.setattr(ui.Client, "show", show)
    answers = iter(["c", "new-project", "Ada", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    result = ui.select_project(client, prefs)
    assert result.token_file != client.token_file
    assert result.token_file.parent == prefs.directory / "tokens"
    assert client.token_file.read_text() == "keep-me"
    assert show.call_args.args[:2] == ("bootstrap", "new-project")


def test_remembered_project_skips_repeated_setup(client, tmp_path, monkeypatch, capsys):
    ui.Preferences(tmp_path).save("development", "acme", client.token_file)
    def data(self, *args):
        return {"scope": None} if args == ("status",) else []
    monkeypatch.setattr(ui.Client, "json", data)
    monkeypatch.setattr(ui.launcher, "runtime_environment", lambda *a: {})
    select = Mock()
    monkeypatch.setattr(ui, "select_project", select)
    answers = iter(["3", "", "6", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    show = Mock()
    monkeypatch.setattr(ui.Client, "show", show)
    assert ui.home(tmp_path) == 0
    select.assert_not_called()
    assert show.call_args_list[0].args == ("assets",)
    assert show.call_args_list[1].args == ("alerts",)
    assert capsys.readouterr().out.count("DEVILS EYES | Platform") == 3


def test_missing_remembered_project_returns_to_selection(client, tmp_path, monkeypatch, capsys):
    ui.Preferences(tmp_path).save("development", "deleted", client.token_file)
    monkeypatch.setattr(ui.Client, "json", Mock(side_effect=ui.UiError("not found")))
    monkeypatch.setattr(ui.launcher, "runtime_environment", lambda *a: {})
    select = Mock(side_effect=ui.Back)
    monkeypatch.setattr(ui, "select_project", select)
    assert ui.home(tmp_path) == 0
    select.assert_called_once()
    assert "remembered project is unavailable" in capsys.readouterr().out


def test_start_queues_once_and_passes_existing_id_to_window(client, monkeypatch):
    run = {"run_id": str(uuid4())}
    client.json = Mock(side_effect=[[], {"scope": {"rules": [{"effect": "include", "pattern": "acme.example"}]}}, [], run])
    monkeypatch.setattr("builtins.input", lambda prompt: "1")
    monkeypatch.setattr(launcher, "yes_no", lambda *a, **kw: True)
    launch = Mock()
    monkeypatch.setattr(ui, "launch_scan", launch)
    ui.start_scan(client)
    assert len([c for c in client.json.call_args_list if c.args[:2] == ("run", "start")]) == 1
    queued = client.json.call_args.args
    assert queued[queued.index("--target") + 1] == "acme.example"
    launch.assert_called_once_with(client, run["run_id"])


def test_existing_queued_run_can_continue_without_duplicate_queue(client, monkeypatch, capsys):
    run = {"run_id": str(uuid4()), "status": "queued", "targets": ["acme.example"]}
    client.json = Mock(return_value=[run])
    monkeypatch.setattr("builtins.input", lambda prompt: "1")
    launch = Mock()
    monkeypatch.setattr(ui, "launch_scan", launch)
    ui.start_scan(client)
    assert client.json.call_count == 1
    launch.assert_called_once_with(client, run["run_id"])
    output = capsys.readouterr().out
    assert "waiting to start" in output and "Continue acme.example" in output


def test_unfinished_scan_menu_can_go_back_without_starting(client, monkeypatch):
    client.json = Mock(return_value=[{"run_id": str(uuid4()), "status": "running"}])
    monkeypatch.setattr("builtins.input", lambda prompt: "0")
    launch = Mock()
    monkeypatch.setattr(ui, "launch_scan", launch)
    assert ui.start_scan(client) is client
    launch.assert_not_called()
    assert client.json.call_count == 1


def test_continue_selects_the_requested_unfinished_run(client, monkeypatch):
    runs = [{"run_id": str(uuid4()), "status": status} for status in ("running", "queued")]
    client.json = Mock(return_value=runs)
    monkeypatch.setattr("builtins.input", lambda prompt: "2")
    launch = Mock()
    monkeypatch.setattr(ui, "launch_scan", launch)
    ui.start_scan(client)
    launch.assert_called_once_with(client, runs[1]["run_id"])
    assert client.json.call_count == 1


def test_start_with_no_target_opens_setup_and_can_go_back(client, monkeypatch):
    launch = Mock()
    monkeypatch.setattr(ui, "launch_scan", launch)
    client.json = Mock(side_effect=[[], {"scope": None}])
    monkeypatch.setattr("builtins.input", lambda prompt: "b")
    with pytest.raises(ui.Back):
        ui.start_scan(client)
    launch.assert_not_called()


@pytest.mark.parametrize("value,expected", [
    ("Example.com", "example.com"),
    ("https://acme.example/about?q=1#team", "acme.example"),
    ("acme.example/contact", "acme.example"),
    ("https://www.acme.example/", "www.acme.example"),
    ("https://acme.example:443", "acme.example"),
    ("https://bücher.example", "xn--bcher-kva.example"),
])
def test_target_accepts_links_without_expanding_parent_domain(value, expected):
    assert ui.target_domain(value) == expected


@pytest.mark.parametrize("value", ["", "localhost", "127.0.0.1", "*.acme.example", "ftp://acme.example",
                                         "https://user:pass@acme.example", "https://acme.example:8080", "acme.example;id"])
def test_target_rejects_invalid_or_unsupported_links(value):
    with pytest.raises(ValueError):
        ui.target_domain(value)


def test_first_scan_adds_target_and_queues_in_one_flow(client, monkeypatch):
    run = {"run_id": str(uuid4())}
    client.json = Mock(side_effect=[[], {"scope": None}, [], run])
    client.show = Mock()
    answers = iter(["https://acme.example/about", "y", "old.acme.example", "4", "https://acme.example/security", "Acme", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    launch = Mock()
    monkeypatch.setattr(ui, "launch_scan", launch)
    assert ui.start_scan(client) is client
    args = client.show.call_args.args
    assert args[:2] == ("scope", "publish")
    assert "*.acme.example" in args and "old.acme.example" in args and "bug_bounty_program" in args
    assert "--i-am-authorized" in args
    assert client.json.call_args.args[:4] == ("run", "start", "--target", "acme.example")
    launch.assert_called_once_with(client, run["run_id"])
    assert ui.Preferences(client.root).data["project"] == "acme"


def test_setup_does_not_expand_subdomains_by_default(client, monkeypatch):
    client.show = Mock()
    answers = iter(["acme.example", "", "", "1", "Ada", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    _, target = ui.add_scan_target(client, {"scope": None}, ui.Preferences(client.root))
    assert target == "acme.example"
    args = client.show.call_args.args
    assert "*.acme.example" not in args and "asset_owner" in args


@pytest.mark.parametrize("ending", [["0"], ["1", "Ada", "n"]])
def test_new_target_cancel_does_not_publish_create_or_queue(client, monkeypatch, ending):
    client.json = Mock(side_effect=[[], {"scope": None}])
    client.show = Mock()
    answers = iter(["acme.example", "y", "-", *ending])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    with pytest.raises(ui.Back):
        ui.start_scan(client)
    client.show.assert_not_called()
    assert client.json.call_count == 2
    assert not ui.Preferences(client.root).path.exists()


def test_new_target_preserves_existing_project_scope_and_token(client, monkeypatch):
    client.token_file.write_text("keep-existing-token")
    new = ui.Client(client.root, project="new", token_file=client.root / "new.token", env={})
    client.json = Mock(side_effect=[[], {"scope": {"rules": [{"effect": "include", "pattern": "old.example"}]}}])
    client.show, new.show = Mock(), Mock()
    run = {"run_id": str(uuid4())}
    new.json = Mock(side_effect=[[], run])
    constructor = Mock(return_value=new)
    monkeypatch.setattr(ui, "Client", constructor)
    answers = iter(["2", "https://new.example/", "y", "-", "1", "Ada", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    monkeypatch.setattr(ui, "launch_scan", Mock())
    assert ui.start_scan(client) is new
    assert client.show.call_args.args[0] == "bootstrap"
    assert client.token_file.read_text() == "keep-existing-token"
    assert new.show.call_args.args[:2] == ("scope", "publish")
    assert "old.example" not in new.show.call_args.args
    assert ui.Preferences(client.root).data["project"] == "new"


def test_scope_save_failure_never_queues(client, monkeypatch):
    client.json = Mock(side_effect=[[], {"scope": None}])
    client.show = Mock(side_effect=ui.UiError("Permission denied"))
    answers = iter(["acme.example", "y", "-", "1", "Ada", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    with pytest.raises(ui.UiError):
        ui.start_scan(client)
    assert client.json.call_count == 2


def test_concurrent_run_started_during_setup_is_not_duplicated(client, monkeypatch):
    run = {"run_id": str(uuid4()), "status": "queued", "kind": "scan", "targets": ["acme.example"]}
    client.json = Mock(side_effect=[[], {"scope": {"rules": [{"effect": "include", "pattern": "acme.example"}]}},
                                  [run]])
    answers = iter(["1", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    launch = Mock()
    monkeypatch.setattr(ui, "launch_scan", launch)
    assert ui.start_scan(client) is client
    launch.assert_called_once_with(client, run["run_id"])
    assert all(c.args[:2] != ("run", "start") for c in client.json.call_args_list)


def test_pending_scan_does_not_block_adding_a_new_target(client, monkeypatch):
    old = {"run_id": str(uuid4()), "status": "queued", "kind": "scan", "targets": ["old.example"]}
    status = {"scope": {"rules": [{"effect": "include", "pattern": "old.example"}]}}
    client.json = Mock(side_effect=[[old], status])
    new = ui.Client(client.root, project="new", token_file=client.root / "new.token", env={})
    run = {"run_id": str(uuid4())}
    new.json = Mock(side_effect=[[], run])
    add = Mock(return_value=(new, "new.example"))
    monkeypatch.setattr(ui, "add_scan_target", add)
    monkeypatch.setattr("builtins.input", lambda prompt: "2")
    launch = Mock()
    monkeypatch.setattr(ui, "launch_scan", launch)
    assert ui.start_scan(client) is new
    assert add.call_args.kwargs == {"separate": True}
    assert new.json.call_args.args[:4] == ("run", "start", "--target", "new.example")
    launch.assert_called_once_with(new, run["run_id"])


def test_pending_menu_can_switch_saved_targets(client, monkeypatch):
    client.json = Mock(return_value=[{"run_id": str(uuid4()), "status": "queued"}])
    other = ui.Client(client.root, project="other", token_file=client.root / "other.token", env={})
    other.json = Mock(side_effect=[[], {"scope": {"rules": [{"effect": "include", "pattern": "other.example"}]}}])
    select = Mock(return_value=other)
    monkeypatch.setattr(ui, "select_project", select)
    answers = iter(["3", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert ui.start_scan(client) is other
    select.assert_called_once()


def test_wsl_scan_opens_separate_window_and_keeps_home(client, monkeypatch):
    client.env["WSL_DISTRO_NAME"] = "Ubuntu-24.04"
    process, window = Mock(), Mock()
    monkeypatch.setattr(ui, "process_here", process)
    monkeypatch.setattr(ui, "open_window", window)
    run_id = str(uuid4())
    ui.launch_scan(client, run_id)
    window.assert_called_once_with(client, run=run_id)
    process.assert_not_called()


def test_wsl_launch_encodes_paths_as_data_without_shell_secrets(client, monkeypatch):
    client.env.update(WSL_DISTRO_NAME="Ubuntu-24.04", SECRET="not-in-launch-command")
    client.root = client.root / "space ' quote $(touch NEVER) `echo nope`"
    monkeypatch.setattr(ui.sys, "platform", "linux")
    monkeypatch.setattr(ui.shutil, "which", lambda *a, **kw: "powershell.exe")
    invoke = Mock(return_value=Mock(returncode=0))
    monkeypatch.setattr(ui.subprocess, "run", invoke)
    run_id = str(uuid4())
    ui.open_window(client, run=run_id)
    argv = invoke.call_args.args[0]
    assert argv[:4] == ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand"]
    script = base64.b64decode(argv[-1]).decode("utf-16-le")
    assert "-WindowStyle Normal" in script
    payload = script.split("FromBase64String('")[1].split("')")[0]
    arguments = base64.b64decode(payload).decode()
    assert str(client.root) in arguments and run_id in arguments and "--hold" in arguments
    assert "not-in-launch-command" not in script + arguments
    assert "shell" not in invoke.call_args.kwargs


def test_wsl_window_launch_failure_offers_existing_fallback(client, monkeypatch):
    client.env["WSL_DISTRO_NAME"] = "Ubuntu-24.04"
    monkeypatch.setattr(ui.sys, "platform", "linux")
    monkeypatch.setattr(ui.shutil, "which", lambda *a, **kw: "powershell.exe")
    monkeypatch.setattr(ui.subprocess, "run", Mock(return_value=Mock(returncode=1)))
    with pytest.raises(ui.UiError, match="could not open"):
        ui.open_window(client, run=str(uuid4()))


def test_separate_window_environment_finds_installed_tools(client):
    assert client.env["PATH"].split(os.pathsep)[0] == str(ui.Path(client.python).parent)


def test_dashboard_waits_for_readiness_before_opening_browser(client, monkeypatch):
    monkeypatch.setattr(ui, "dashboard_state", Mock(side_effect=["unavailable", "unavailable", "unavailable", "ready"]))
    server = Mock()
    server.poll.side_effect = [None, None, 0]
    server.wait.return_value = 0
    monkeypatch.setattr(ui.subprocess, "Popen", Mock(return_value=server))
    sleep = Mock()
    monkeypatch.setattr(ui.time, "sleep", sleep)
    browse = Mock()
    monkeypatch.setattr(ui, "open_dashboard_browser", browse)
    assert ui.serve_dashboard(client, browse=True) == 0
    browse.assert_called_once_with(client)
    sleep.assert_called_once()
    server.terminate.assert_not_called()


def test_dashboard_startup_failure_does_not_open_browser(client, monkeypatch):
    monkeypatch.setattr(ui, "dashboard_state", lambda: "unavailable")
    server = Mock()
    server.poll.return_value = 1
    monkeypatch.setattr(ui.subprocess, "Popen", Mock(return_value=server))
    browse = Mock()
    monkeypatch.setattr(ui, "open_dashboard_browser", browse)
    with pytest.raises(ui.UiError, match="exited"):
        ui.serve_dashboard(client, browse=True)
    browse.assert_not_called()


def test_dashboard_interrupt_reaps_owned_server(client, monkeypatch):
    monkeypatch.setattr(ui, "dashboard_state", lambda: "unavailable")
    server = Mock()
    server.poll.return_value = None
    monkeypatch.setattr(ui.subprocess, "Popen", Mock(return_value=server))
    monkeypatch.setattr(ui.time, "sleep", Mock(side_effect=KeyboardInterrupt))
    with pytest.raises(KeyboardInterrupt):
        ui.serve_dashboard(client)
    server.terminate.assert_called_once()
    server.wait.assert_called_once_with(timeout=10)


def test_start_lock_blocks_a_second_home(client):
    with ui.session_lock(client, "start"):
        with pytest.raises(ui.UiError, match="already performing"):
            with ui.session_lock(client, "start"):
                pytest.fail("second launch entered")


def test_macos_command_is_quoted_and_contains_no_secrets(tmp_path, monkeypatch):
    root = tmp_path / "space ' quote $(touch NEVER) `echo nope`"
    root.mkdir()
    client = ui.Client(root, profile="lab", project="acme", token_file=root / "owner token", env={"SECRET": "never-in-arguments"})
    monkeypatch.setattr(ui.sys, "platform", "darwin")
    invoke = Mock(return_value=Mock(returncode=0))
    monkeypatch.setattr(ui.subprocess, "run", invoke)
    run_id = str(uuid4())
    ui.open_window(client, run=run_id)
    argv = invoke.call_args.args[0]
    assert argv[0] == "osascript"
    assert "NEVER" not in argv[2]  # fixed AppleScript, data only via argv
    assert "never-in-arguments" not in " ".join(argv)
    parsed = shlex.split(argv[-1])
    assert parsed[:4] == ["cd", str(root), "&&", "exec"]
    command = parsed[4:]
    assert command == ui.window_arguments(client, run=run_id)
    assert "--run" in command and "start" not in command
    assert command[command.index("--profile") + 1] == "lab"
    assert command[command.index("--project") + 1] == "acme"
    assert command[command.index("--run") + 1] == run_id


def test_linux_launch_uses_argument_array(client, monkeypatch):
    monkeypatch.setattr(ui.sys, "platform", "linux")
    monkeypatch.setattr(ui.shutil, "which", lambda name: name if name == "xterm" else None)
    process = Mock()
    process.wait.side_effect = subprocess.TimeoutExpired("xterm", 0.5)
    invoke = Mock(return_value=process)
    monkeypatch.setattr(ui.subprocess, "Popen", invoke)
    ui.open_window(client, run=str(uuid4()))
    assert invoke.call_args.args[0][:4] == ["xterm", "-T", "Devils Eyes - acme", "-e"]
    assert "shell" not in invoke.call_args.kwargs


@pytest.mark.parametrize("action", ["0", "2"])
def test_launch_failure_retains_same_run_and_offers_fallback(client, monkeypatch, action):
    run_id = str(uuid4())
    client.json = Mock()
    monkeypatch.setattr(ui, "open_window", Mock(side_effect=ui.UiError("blocked")))
    monkeypatch.setattr("builtins.input", lambda prompt: action)
    fallback = Mock()
    monkeypatch.setattr(ui, "process_here", fallback)
    ui.launch_scan(client, run_id)
    client.json.assert_not_called()  # no second queue
    if action == "2":
        fallback.assert_called_once_with(client, run_id)
    else:
        fallback.assert_not_called()


def test_retry_reuses_the_run(client, monkeypatch):
    run_id = str(uuid4())
    launch = Mock(side_effect=[ui.UiError("blocked"), None])
    monkeypatch.setattr(ui, "open_window", launch)
    monkeypatch.setattr("builtins.input", lambda prompt: "1")
    ui.launch_scan(client, run_id)
    assert launch.call_count == 2
    assert all(c.kwargs["run"] == run_id for c in launch.call_args_list)


def test_progress_renders_real_phases_counts_errors_and_pending_checks(capsys):
    detail = run_detail("partial")
    detail["checks_not_run"] = {"exposed-env-file": "pending approval"}
    detail["snapshots"] = [{"phase": "discovery", "target": "acme.example", "status": "succeeded", "comparison": "baseline", "stats": {"hosts": 7}}]
    ui.render_progress(detail, "acme\x1b[2J")
    out = capsys.readouterr().out
    assert "PARTIAL" in out and "NOT RUN" in out and '"hosts": 7' in out
    assert "2m 0s" in out and "not a complete successful scan" in " ".join(out.split())
    assert "\x1b" not in out and "\\x1b" in out and "%" not in out
    detail = run_detail("failed")
    detail["run"]["last_error"] = "discovery tool missing"
    ui.render_progress(detail, "acme")
    assert "discovery tool missing" in capsys.readouterr().out


def test_watcher_shows_updates_before_completion_without_queueing(client, monkeypatch, capsys):
    running, done = run_detail(), run_detail("succeeded")
    client.json = Mock(side_effect=[running, running, done])
    monkeypatch.setattr(ui.time, "sleep", lambda *a: None)
    assert ui.watch_run(client, running["run"]["run_id"]) == 0
    out = capsys.readouterr().out
    assert "RUNNING" in out and "SUCCEEDED" in out and "discovery" in out
    assert all(c.args[:2] == ("run", "show") for c in client.json.call_args_list)


def test_interrupt_closes_processor_without_cancelling_run(client, monkeypatch, capsys):
    detail = run_detail()
    client.json = Mock(side_effect=[detail, KeyboardInterrupt])
    processor = Mock(error=None)
    monkeypatch.setattr(ui, "LocalProcessor", Mock(return_value=processor))
    assert ui.watch_run(client, detail["run"]["run_id"], work=True) == 0
    processor.close.assert_called_once()
    assert "not cancelled" in capsys.readouterr().out
    assert all(c.args[:2] == ("run", "show") for c in client.json.call_args_list)


def test_cancel_is_explicit_and_uses_cli(client, monkeypatch):
    run_id = str(uuid4())
    monkeypatch.setattr(ui, "select_run", lambda c: {"run_id": run_id})
    answers = iter(["4", "y", "stop test run", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    client.show = Mock()
    ui.progress_menu(client)
    client.show.assert_called_once_with("run", "cancel", run_id, "--reason", "stop test run")


def test_scope_decline_never_publishes_and_wildcard_is_opt_in(client, monkeypatch):
    answers = iter(["2", "acme.example", "n", "-", "1", "SOW-1", "Acme", "n", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    client.show = Mock()
    ui.manage_scope(client)
    client.show.assert_not_called()


def test_scope_publish_validates_and_requires_explicit_authorization(client, monkeypatch):
    answers = iter(["2", "https://bad.example/x", "acme.example", "y", "old.acme.example", "2", "SOW-1", "Acme", "y", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    client.show = Mock()
    ui.manage_scope(client)
    args = client.show.call_args.args
    assert "*.acme.example" in args and "--i-am-authorized" in args
    assert "old.acme.example" in args and "contract" in args


def test_dashboard_reuses_existing_server(client, monkeypatch):
    monkeypatch.setattr(ui, "dashboard_state", lambda: "ready")
    launch, browse = Mock(), Mock()
    monkeypatch.setattr(ui, "open_window", launch)
    monkeypatch.setattr(ui.webbrowser, "open", browse)
    ui.open_dashboard(client)
    launch.assert_not_called()
    browse.assert_called_once_with("http://127.0.0.1:8080")


def test_client_filters_secret_bearing_driver_errors(client, monkeypatch):
    monkeypatch.setattr(ui.subprocess, "run", Mock(return_value=Mock(returncode=1, stderr="watchtower: postgresql://user:password@host/db", stdout="")))
    with pytest.raises(ui.UiError) as err:
        client.json("status")
    assert "password" not in str(err.value)


def test_narrow_plain_terminal_output_escapes_control_characters(monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(ui.shutil, "get_terminal_size", lambda *a: os.terminal_size((25, 20)))
    ui.tell("untrusted\x1b[2J" + "x" * 100)
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert all(len(line) <= 25 for line in out.splitlines())


def test_local_processor_uses_existing_worker_and_shuts_it_down(client, monkeypatch):
    # No outbound work: mock runtime objects at the public boundary.
    database, worker, notifier = Mock(), Mock(), Mock()
    monkeypatch.setattr("watchtower.config.load_settings", lambda profile: Mock())
    monkeypatch.setattr("watchtower.persistence.database.Database.from_settings", lambda settings: database)
    monkeypatch.setattr("watchtower.workers.egress.install", lambda settings: None)
    monkeypatch.setattr("watchtower.workers.runtime.Worker", lambda *a, **kw: worker)
    monkeypatch.setattr("watchtower.workers.runtime.Notifier", lambda *a, **kw: notifier)
    processor = ui.LocalProcessor(client)
    notifier.deliver_once.side_effect = processor.stop_event.set
    worker.run_once.return_value = True
    processor.start()
    processor.thread.join(timeout=2)
    processor.close()
    worker.run_once.assert_called_once()
    notifier.deliver_once.assert_called_once()
    database.dispose.assert_called_once()


def test_local_processor_requests_graceful_shutdown(client, monkeypatch):
    # Exercise the stop path with an active fake thread without touching a DB.
    processor = object.__new__(ui.LocalProcessor)
    import threading
    processor.stop_event = threading.Event()
    processor.worker, processor.database, processor.thread = Mock(), Mock(), Mock()
    processor.thread.is_alive.side_effect = [True, False, False]
    processor.close()
    assert processor.stop_event.is_set()
    processor.worker.shutdown.assert_called_once()
    processor.database.dispose.assert_called_once()


def test_finished_run_does_not_start_an_unnecessary_worker(client, monkeypatch):
    detail = run_detail("failed")
    client.json = Mock(return_value=detail)
    processor = Mock()
    monkeypatch.setattr(ui, "LocalProcessor", processor)
    # Completed failures still return a failing exit status.
    assert ui.watch_run(client, detail["run"]["run_id"], work=True) == 4
    processor.assert_not_called()


def test_unsupported_terminal_never_queues_a_run(client, monkeypatch):
    monkeypatch.setattr(ui.sys, "platform", "unsupported")
    client.json = Mock()
    with pytest.raises(ui.UiError, match="No supported"):
        ui.open_window(client, run=str(uuid4()))
    client.json.assert_not_called()


def test_scope_defaults_do_not_expand_to_wildcards(client, monkeypatch):
    answers = iter(["2", "acme.example", "", "-", "1", "SOW-1", "Acme", "y", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    client.show = Mock()
    ui.manage_scope(client)
    args = client.show.call_args.args
    assert "acme.example" in args and "*.acme.example" not in args


class Terminal(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def live(monkeypatch):
    """A redrawn terminal; returns the plain text of each frame drawn so far."""
    terminal = Terminal()
    size = {"value": os.terminal_size((100, 60))}
    monkeypatch.setattr(ui.shutil, "get_terminal_size", lambda *a, **kw: size["value"])
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("DEVILS_EYES_TAGLINE", "See what changes.")
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(ui, "SCREEN", ui.Screen())
    ui.SCREEN.start(stream=terminal)

    def frames():
        raw = terminal.getvalue().split("\033[H\033[3J")[1:]
        return [re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", frame) for frame in raw]
    frames.size = size
    frames.terminal = terminal
    return frames


def home_data(tmp_path, client, monkeypatch):
    ui.Preferences(tmp_path).save("development", "acme", client.token_file)
    run = {"run_id": str(uuid4()), "status": "queued", "targets": ["acme.example"]}

    def data(self, *args):
        if args == ("status",):
            return {"scope": {"rules": [{"effect": "include", "pattern": "acme.example"}]}}
        return run_detail("queued") if args[:2] == ("run", "show") else [run]
    monkeypatch.setattr(ui.Client, "json", data)
    monkeypatch.setattr(ui.launcher, "runtime_environment", lambda *a: {})


def test_live_home_submenu_and_back_replace_the_content_under_a_fixed_header(client, tmp_path, monkeypatch, live):
    home_data(tmp_path, client, monkeypatch)
    answers = iter(["1", "0", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert ui.home(tmp_path) == 0
    # A message drawn before its menu adds an in-place frame; compare the menu screens.
    home, start, back = [frame for frame in live() if "0) " in frame]
    for frame in (home, start, back):
        assert frame.count("DEVILS EYES | Platform") == 1 and frame.count("See what changes.") == 1
        assert frame.index("Discover. Track. Monitor.") < frame.index("Latest run: QUEUED")
    assert "Browse inventory" not in start and "Continue acme.example" in start
    assert start.index("You have an unfinished scan") < start.index("Start scan\n")
    assert back.count("1) Start scan") == 1 and "Continue acme.example" not in back


def test_live_invalid_choice_redraws_the_same_menu_with_an_error(live, monkeypatch):
    answers = iter(["9", "1"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    ui.tell("Profile changes apply to new windows.")
    assert ui.menu("Profile", {"1": "Development", "0": "Back"}) == "1"
    first, second = live()[-2:]
    assert "Please choose" not in first
    assert second.count("1) Development") == 1 and second.count("Profile changes apply") == 1
    assert second.index("Please choose one of the listed numbers.") < second.index("Profile\n")


def test_live_text_field_error_redraws_instead_of_scrolling(live, monkeypatch):
    answers = iter(["ftp://acme.example", "acme.example"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    ui.tell("Add a target")
    assert ui.field("Domain or website link", validate=ui.target_domain) == "acme.example"
    frames = live()
    assert len(frames) == 2 and "http/https" in frames[1] and frames[1].count("Add a target") == 1


def test_live_progress_refreshes_in_place(client, monkeypatch, live):
    running, done = run_detail(), run_detail("succeeded")
    client.json = Mock(side_effect=[running, running, done])
    monkeypatch.setattr(ui.time, "sleep", lambda *a: None)
    assert ui.watch_run(client, running["run"]["run_id"]) == 0
    frames = live()[1:]
    assert len(frames) == 2
    for frame in frames:
        assert frame.count("Discovery > DNS") == 1 and "Ctrl+C stops this viewer" in frame
    assert "SUCCEEDED" in frames[-1] and "RUNNING" not in frames[-1]


def test_short_terminal_uses_a_compact_header(live, monkeypatch):
    live.size["value"] = os.terminal_size((100, 20))
    ui.SCREEN.show_status(["DEVILS EYES | Platform", "Project: acme | Profile: development"])
    monkeypatch.setattr("builtins.input", lambda prompt: "0")
    ui.menu("Home", ui.HOME)
    frame = live()[-1]
    assert frame.startswith("DEVILS EYES | Platform | Project: acme") and "%%%" not in frame
    assert frame.count("0) Exit") == 1


def test_exit_from_a_prompt_restores_colour_on_a_fresh_line(live, monkeypatch):
    monkeypatch.setattr("builtins.input", Mock(side_effect=EOFError))
    with pytest.raises(EOFError):
        ui.menu("Home", ui.HOME)
    ui.SCREEN.close()
    assert live.terminal.getvalue().endswith("\033[0m\n")


@pytest.mark.parametrize("terminal, no_clear, term", [
    (io.StringIO, False, "xterm"), (Terminal, True, "xterm"), (Terminal, False, "dumb")])
def test_pipes_no_clear_and_dumb_terminals_keep_sequential_output(client, tmp_path, monkeypatch, terminal, no_clear, term):
    home_data(tmp_path, client, monkeypatch)
    output = terminal()
    monkeypatch.setattr(ui.sys, "stdout", output)
    monkeypatch.setenv("TERM", term)
    monkeypatch.setattr(ui, "SCREEN", ui.Screen())
    ui.SCREEN.start(no_clear=no_clear)
    answers = iter(["1", "0", "0"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert ui.home(tmp_path) == 0
    text = output.getvalue()
    assert "\033[H" not in text and "\033[3J" not in text
    assert text.count("DEVILS EYES | Platform") == 2 and text.count("1) Start scan") == 2
    assert text.index("Continue acme.example") < text.rindex("1) Start scan")
