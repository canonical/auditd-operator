from subprocess import CalledProcessError
from unittest.mock import MagicMock, patch

import pytest

import utils


def test_read_file(tmp_path):
    file = tmp_path / "test.txt"
    file.write_text("hello", encoding="utf-8")
    assert utils.read_file(file) == "hello"


@patch("utils.os.chmod")
@patch("utils.pwd.getpwnam")
@patch("utils.os.chown")
def test_write_file(mock_chown, mock_getpwnam, mock_chmod, tmp_path):
    file = tmp_path / "test.txt"
    mock_getpwnam.return_value = MagicMock(pw_uid=1000, pw_gid=1000)
    utils.write_file(file, "data", "root", 0o600)
    assert file.read_text(encoding="utf-8") == "data"
    mock_chmod.assert_called_once()
    mock_getpwnam.assert_called_once_with("root")
    mock_chown.assert_called_once()


@patch("utils.Environment")
def test_render_jinja2_template(mock_env):
    mock_template = MagicMock()
    mock_template.render.return_value = "rendered"
    mock_env.return_value.get_template.return_value = mock_template
    result = utils.render_jinja2_template({"foo": "bar"}, "template", "/path")
    assert result == "rendered"
    mock_env.return_value.get_template.assert_called_once_with("template")
    mock_template.render.assert_called_once_with({"foo": "bar"})


@patch("utils.subprocess.check_output", return_value=b"qemu")
def test_get_machine_virt_type_success(mock_check_output):
    assert utils.get_machine_virt_type() == "qemu"
    mock_check_output.assert_called_once_with(["systemd-detect-virt"])


@patch("utils.subprocess.check_output", side_effect=CalledProcessError(1, "systemd-detect-virt"))
def test_get_machine_virt_type_failure(_):
    with pytest.raises(CalledProcessError):
        utils.get_machine_virt_type()
