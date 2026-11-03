"""Terminal animation stays readable, optional, and safe to interrupt."""
import io
import os
import re
from unittest.mock import patch

import pytest

import launcher


class Terminal(io.StringIO):
    def isatty(self):
        return True


def render(stream, environment=None, width=80):
    with patch.dict(os.environ, {"TERM": "xterm-256color", **(environment or {})}, clear=True), \
            patch.object(launcher.shutil, "get_terminal_size", return_value=os.terminal_size((width, 24))), \
            patch.object(launcher.random, "choice", return_value="Always watching."), \
            patch.object(launcher.time, "sleep") as sleep:
        launcher.banner(stream)
    return stream.getvalue(), sleep


def test_live_terminal_reveals_eye_then_brand_and_restores_cursor():
    output, sleep = render(Terminal())
    plain = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", output)
    assert "DEVILS EYES" in plain and "WATCHTOWER" not in plain
    assert plain.index("DEVILS EYES") < plain.index("Always watching.")
    assert output.startswith("\033[?25l") and output.endswith("\033[0m\033[?25h")
    assert 2 <= sum(call.args[0] for call in sleep.call_args_list) <= 3.5
    captured, _ = render(io.StringIO())
    assert plain == captured


@pytest.mark.parametrize("environment", [{"NO_ANIMATION": "1"}, {"REDUCE_MOTION": "1"}, {"NO_COLOR": "1"}, {"TERM": "dumb"}, {"DEVILS_EYES_BANNER_SPEED": "0"}])
def test_accessibility_options_skip_animation(environment):
    output, sleep = render(Terminal(), environment)
    sleep.assert_not_called()
    assert "\033[?25l" not in output and "DEVILS EYES" in output


def test_banner_speed_scales_all_delays():
    _, normal = render(Terminal())
    _, fast = render(Terminal(), {"DEVILS_EYES_BANNER_SPEED": "4"})
    assert [call.args[0] for call in fast.call_args_list] == [call.args[0] / 2 for call in normal.call_args_list]


@pytest.mark.parametrize("value", ["invalid", "-1", "nan", "inf"])
def test_invalid_banner_speed_uses_default(value):
    _, normal = render(Terminal())
    _, invalid = render(Terminal(), {"DEVILS_EYES_BANNER_SPEED": value})
    assert invalid.call_args_list == normal.call_args_list


def test_redirected_output_is_instant_plain_and_narrow_terminal_is_compact():
    output, sleep = render(io.StringIO(), width=24)
    sleep.assert_not_called()
    assert "\033" not in output
    assert "DEVILS EYES" in output and "<((@))>" in output
    assert max(map(len, output.splitlines())) <= 24


def test_interruption_restores_cursor_and_colour():
    stream = Terminal()
    with patch.dict(os.environ, {"TERM": "xterm"}, clear=True), \
            patch.object(launcher.time, "sleep", side_effect=KeyboardInterrupt), \
            pytest.raises(KeyboardInterrupt):
        launcher.banner(stream)
    assert stream.getvalue().endswith("\033[0m\033[?25h")
