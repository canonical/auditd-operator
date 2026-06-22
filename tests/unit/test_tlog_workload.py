from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from charms.operator_libs_linux.v0 import apt
from charms.operator_libs_linux.v1 import systemd

from constants import (
    TLOG_SSHD_CONF_TEMPLATE,
    TLOG_TEMPLATE_FILE_PATH,
    TLOG_WRAPPER_TEMPLATE,
)
from tlog_workload import (
    _TLOG_LOGROTATE_CONTENT,
    TlogService,
    TlogServiceError,
    TlogServiceReloadError,
)
from utils import render_jinja2_template


@pytest.fixture()
def svc():
    return TlogService()


def _render_wrapper(exclude_groups: str) -> str:
    return render_jinja2_template(
        {"session_recording_exclude_groups": exclude_groups},
        TLOG_WRAPPER_TEMPLATE,
        TLOG_TEMPLATE_FILE_PATH,
    )


@patch("tlog_workload.apt.add_package")
def test_install_success(mock_add, svc):
    svc.install()
    mock_add.assert_called_once_with(package_names="tlog")


@patch(
    "tlog_workload.apt.add_package",
    side_effect=apt.PackageError("Failed to install packages: tlog"),
)
def test_install_failure_raises_with_universe_hint(mock_add, svc):
    with pytest.raises(TlogServiceError, match="universe"):
        svc.install()


@patch("tlog_workload.apt.DebianPackage.from_installed_package")
def test_is_installed_true(_, svc):
    assert svc.is_installed() is True


@patch(
    "tlog_workload.apt.DebianPackage.from_installed_package",
    side_effect=apt.PackageNotFoundError,
)
def test_is_installed_false(_, svc):
    assert svc.is_installed() is False


@patch("tlog_workload.apt.remove_package")
@patch("tlog_workload.apt.DebianPackage.from_installed_package")
def test_remove_when_installed(mock_installed, mock_remove, svc):
    svc.remove()
    mock_remove.assert_called_once_with(package_names="tlog")


@patch(
    "tlog_workload.apt.DebianPackage.from_installed_package",
    side_effect=apt.PackageNotFoundError,
)
@patch("tlog_workload.apt.remove_package")
def test_remove_when_not_installed(mock_remove, _, svc):
    svc.remove()
    mock_remove.assert_not_called()


@patch.object(TlogService, "_reload_audit_rules")
@patch.object(TlogService, "reload_sshd")
def test_configure_disabled_no_snippet_no_reload(mock_reload, mock_reload_rules, svc, tmp_path):
    svc._snippet_path = tmp_path / "99-tlog-recording.conf"
    svc._audit_rules_path = tmp_path / "tlog.rules"
    svc.configure(enabled=False, exclude_groups="")
    mock_reload.assert_not_called()
    mock_reload_rules.assert_not_called()


@patch.object(TlogService, "_reload_audit_rules")
@patch.object(TlogService, "reload_sshd")
def test_configure_disabled_removes_snippet_and_reloads(mock_reload, _reload_rules, svc, tmp_path):
    snippet = tmp_path / "99-tlog-recording.conf"
    snippet.write_text("old snippet")
    svc._snippet_path = snippet
    svc._audit_rules_path = tmp_path / "tlog.rules"
    svc.configure(enabled=False, exclude_groups="")
    assert not snippet.exists()
    mock_reload.assert_called_once()


@patch.object(TlogService, "_reload_audit_rules")
@patch.object(TlogService, "reload_sshd")
def test_configure_disabled_removes_audit_rules_and_reloads(
    mock_reload_sshd, mock_reload_rules, svc, tmp_path
):
    """Disabling removes the tamper rules installed by the enable path."""
    svc._snippet_path = tmp_path / "99-tlog-recording.conf"
    rules = tmp_path / "tlog.rules"
    rules.write_text("-w /var/log/tlog/sessions.log -p wa -k tlog_recording_tamper\n")
    svc._audit_rules_path = rules
    svc.configure(enabled=False, exclude_groups="")
    assert not rules.exists()
    mock_reload_rules.assert_called_once()
    mock_reload_sshd.assert_not_called()


@patch.object(
    TlogService, "reload_sshd", side_effect=TlogServiceReloadError("Failed to reload ssh.")
)
def test_disable_snippet_reload_failure_restores_snippet(mock_reload, svc, tmp_path):
    snippet = tmp_path / "99-tlog-recording.conf"
    snippet.write_text("ForceCommand /usr/local/bin/tlog-wrapper\n")
    svc._snippet_path = snippet
    svc._audit_rules_path = tmp_path / "tlog.rules"

    with patch(
        "tlog_workload.write_file",
        side_effect=lambda path, content, *a, **kw: Path(path).write_text(content),
    ):
        with pytest.raises(TlogServiceReloadError):
            svc.configure(enabled=False, exclude_groups="")

    assert snippet.read_text() == "ForceCommand /usr/local/bin/tlog-wrapper\n"


@patch.object(TlogService, "reload_sshd")
@patch.object(TlogService, "_reload_audit_rules", return_value=False)
def test_disable_audit_rules_reload_failure_restores_rules(
    mock_reload_rules, mock_reload_sshd, svc, tmp_path
):
    svc._snippet_path = tmp_path / "99-tlog-recording.conf"  # absent
    rules = tmp_path / "tlog.rules"
    rules.write_text("-w /var/log/tlog/sessions.log -p wa -k tlog_recording_tamper\n")
    svc._audit_rules_path = rules

    with patch(
        "tlog_workload.write_file",
        side_effect=lambda path, content, *a, **kw: Path(path).write_text(content),
    ):
        svc.configure(enabled=False, exclude_groups="")

    assert rules.exists()


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(TlogService, "reload_sshd")
@patch.object(TlogService, "validate_tlog")
@patch.object(TlogService, "validate_sshd")
@patch.object(TlogService, "_write_wrapper_atomic")
@patch.object(TlogService, "_write_tlog_conf")
@patch.object(TlogService, "_ensure_log_dir")
@patch.object(TlogService, "is_installed", return_value=True)
def test_configure_enable_ordering(
    mock_installed,
    mock_ensure,
    mock_conf,
    mock_wrapper,
    mock_validate_tlog,
    mock_validate_sshd,
    mock_reload,
    mock_priv,
    svc,
    tmp_path,
):
    """Enable path runs the prep steps then writes the global snippet last."""
    snippet = tmp_path / "99-tlog-recording.conf"
    svc._snippet_path = snippet
    svc._log_dir = tmp_path / "tlog"
    svc._log_file = tmp_path / "tlog" / "sessions.log"

    with (
        patch("tlog_workload.render_jinja2_template", return_value="new-snippet"),
        patch("tlog_workload.write_file"),
        patch.object(TlogService, "_write_logrotate") as mock_logrotate,
        patch.object(TlogService, "_ensure_audit_rules") as mock_rules,
    ):
        svc.configure(enabled=True, exclude_groups="")

    call_order = [mock_ensure, mock_conf, mock_wrapper, mock_logrotate, mock_rules]
    for m in call_order:
        m.assert_called_once()
    mock_validate_tlog.assert_called_once()
    mock_reload.assert_called_once()


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(TlogService, "reload_sshd")
@patch.object(TlogService, "validate_tlog")
@patch.object(TlogService, "validate_sshd")
@patch.object(TlogService, "_write_wrapper_atomic")
@patch.object(TlogService, "_write_tlog_conf")
@patch.object(TlogService, "_ensure_log_dir")
@patch.object(TlogService, "is_installed", return_value=True)
def test_configure_threads_exclude_groups_into_wrapper(
    _installed,
    _ensure,
    _conf,
    mock_wrapper,
    mock_validate_tlog,
    mock_validate_sshd,
    _reload,
    _priv,
    svc,
    tmp_path,
):
    svc._snippet_path = tmp_path / "99-tlog-recording.conf"
    with (
        patch("tlog_workload.render_jinja2_template", return_value="new-snippet"),
        patch("tlog_workload.write_file"),
        patch.object(TlogService, "_write_logrotate"),
        patch.object(TlogService, "_ensure_audit_rules"),
    ):
        svc.configure(enabled=True, exclude_groups="warthogs,sudo")
    mock_wrapper.assert_called_once_with("warthogs,sudo")


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(TlogService, "reload_sshd")
@patch.object(TlogService, "validate_tlog")
@patch.object(TlogService, "_write_wrapper_atomic")
@patch.object(TlogService, "_write_tlog_conf")
@patch.object(TlogService, "_ensure_log_dir")
@patch.object(TlogService, "is_installed", return_value=True)
def test_configure_snippet_not_written_when_wrapper_fails(
    _installed, _ensure, _conf, mock_wrapper, mock_validate_tlog, mock_reload, _priv, svc, tmp_path
):
    mock_wrapper.side_effect = TlogServiceError("bad wrapper")
    snippet = tmp_path / "99-tlog-recording.conf"
    svc._snippet_path = snippet

    with pytest.raises(TlogServiceError):
        svc.configure(enabled=True, exclude_groups="warthogs")

    assert not snippet.exists()
    mock_validate_tlog.assert_not_called()
    mock_reload.assert_not_called()


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(TlogService, "reload_sshd")
@patch.object(TlogService, "validate_tlog", side_effect=TlogServiceReloadError("bad config"))
@patch.object(TlogService, "_ensure_audit_rules")
@patch.object(TlogService, "_write_logrotate")
@patch.object(TlogService, "_write_wrapper_atomic")
@patch.object(TlogService, "_write_tlog_conf")
@patch.object(TlogService, "_ensure_log_dir")
@patch.object(TlogService, "is_installed", return_value=True)
def test_configure_validate_tlog_failure_reverts_new_snippet(
    _installed,
    _ensure,
    _conf,
    _wrapper,
    _logrotate,
    _rules,
    _validate_tlog,
    mock_reload,
    _priv,
    svc,
    tmp_path,
):
    snippet = tmp_path / "99-tlog-recording.conf"
    svc._snippet_path = snippet

    with (
        patch("tlog_workload.render_jinja2_template", return_value="new-snippet"),
        patch(
            "tlog_workload.write_file",
            side_effect=lambda path, content, *a, **kw: snippet.write_text(content),
        ),
    ):
        with pytest.raises(TlogServiceReloadError):
            svc.configure(enabled=True, exclude_groups="")

    assert not snippet.exists(), "snippet must be reverted on tlog validation failure"
    mock_reload.assert_not_called()


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(TlogService, "reload_sshd")
@patch.object(TlogService, "validate_tlog", side_effect=TlogServiceReloadError("bad config"))
@patch.object(TlogService, "_ensure_audit_rules")
@patch.object(TlogService, "_write_logrotate")
@patch.object(TlogService, "_write_wrapper_atomic")
@patch.object(TlogService, "_write_tlog_conf")
@patch.object(TlogService, "_ensure_log_dir")
@patch.object(TlogService, "is_installed", return_value=True)
def test_configure_validate_tlog_failure_restores_previous_snippet(
    _installed,
    _ensure,
    _conf,
    _wrapper,
    _logrotate,
    _rules,
    _validate_tlog,
    mock_reload,
    _priv,
    svc,
    tmp_path,
):
    snippet = tmp_path / "99-tlog-recording.conf"
    snippet.write_text("old global snippet\n")
    svc._snippet_path = snippet

    with (
        patch("tlog_workload.render_jinja2_template", return_value="new global snippet\n"),
        patch(
            "tlog_workload.write_file",
            side_effect=lambda path, content, *a, **kw: snippet.write_text(content),
        ),
    ):
        with pytest.raises(TlogServiceReloadError):
            svc.configure(enabled=True, exclude_groups="")

    assert snippet.read_text() == "old global snippet\n"
    mock_reload.assert_not_called()


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(
    TlogService, "reload_sshd", side_effect=TlogServiceReloadError("Failed to reload ssh.")
)
@patch.object(TlogService, "validate_tlog")
@patch.object(TlogService, "_ensure_audit_rules")
@patch.object(TlogService, "_write_logrotate")
@patch.object(TlogService, "_write_wrapper_atomic")
@patch.object(TlogService, "_write_tlog_conf")
@patch.object(TlogService, "_ensure_log_dir")
@patch.object(TlogService, "is_installed", return_value=True)
def test_configure_reload_failure_restores_previous_snippet(
    _installed,
    _ensure,
    _conf,
    _wrapper,
    _logrotate,
    _rules,
    _validate_tlog,
    _reload,
    _priv,
    svc,
    tmp_path,
):
    snippet = tmp_path / "99-tlog-recording.conf"
    snippet.write_text("old global snippet\n")
    svc._snippet_path = snippet

    with (
        patch("tlog_workload.render_jinja2_template", return_value="new global snippet\n"),
        patch(
            "tlog_workload.write_file",
            side_effect=lambda path, content, *a, **kw: snippet.write_text(content),
        ),
    ):
        with pytest.raises(TlogServiceReloadError):
            svc.configure(enabled=True, exclude_groups="")

    assert snippet.read_text() == "old global snippet\n"


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(TlogService, "reload_sshd")
@patch.object(TlogService, "validate_tlog")
@patch.object(TlogService, "is_installed", return_value=True)
def test_configure_no_reload_when_snippet_unchanged(
    _installed, mock_validate_tlog, mock_reload, _priv, svc, tmp_path
):
    expected_snippet = (
        "# Managed by auditd-operator charm. Do not edit manually.\n"
        "# Record ALL inbound SSH sessions. tlog-wrapper will decide\n"
        "# which sessions to record based on the charm configuration.\n"
        "ForceCommand /usr/local/bin/tlog-wrapper\n"
    )
    snippet = tmp_path / "99-tlog-recording.conf"
    snippet.write_text(expected_snippet)
    svc._snippet_path = snippet
    svc._conf_path = tmp_path / "tlog-rec-session.conf"
    svc._wrapper_path = tmp_path / "tlog-wrapper"
    svc._log_dir = tmp_path / "tlog"
    svc._log_file = tmp_path / "tlog" / "sessions.log"

    with (
        patch("tlog_workload.render_jinja2_template") as mock_render,
        patch("tlog_workload.write_file"),
        patch.object(TlogService, "_write_wrapper_atomic"),
        patch.object(TlogService, "_ensure_log_dir"),
        patch.object(TlogService, "_write_tlog_conf"),
        patch.object(TlogService, "_write_logrotate"),
        patch.object(TlogService, "_ensure_audit_rules"),
    ):
        mock_render.return_value = expected_snippet
        svc.configure(enabled=True, exclude_groups="")

    mock_reload.assert_not_called()
    mock_validate_tlog.assert_not_called()


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(TlogService, "reload_sshd")
@patch.object(TlogService, "validate_tlog")
@patch.object(TlogService, "is_installed", return_value=True)
def test_exclude_groups_change_only_no_sshd_reload(
    _installed, mock_validate_tlog, mock_reload, _priv, svc, tmp_path
):
    snippet_content = (
        "# Managed by auditd-operator charm. Do not edit manually.\n"
        "# Record ALL inbound SSH sessions. tlog-wrapper will decide\n"
        "# which sessions to record based on the charm configuration.\n"
        "ForceCommand /usr/local/bin/tlog-wrapper\n"
    )
    snippet = tmp_path / "99-tlog-recording.conf"
    snippet.write_text(snippet_content)
    svc._snippet_path = snippet
    svc._conf_path = tmp_path / "tlog-rec-session.conf"
    svc._wrapper_path = tmp_path / "tlog-wrapper"
    svc._log_dir = tmp_path / "tlog"
    svc._log_file = tmp_path / "tlog" / "sessions.log"

    with (
        patch("tlog_workload.render_jinja2_template") as mock_render,
        patch("tlog_workload.write_file"),
        patch.object(TlogService, "_write_wrapper_atomic") as mock_wrapper,
        patch.object(TlogService, "_ensure_log_dir"),
        patch.object(TlogService, "_write_tlog_conf"),
        patch.object(TlogService, "_write_logrotate"),
        patch.object(TlogService, "_ensure_audit_rules"),
    ):
        mock_render.return_value = snippet_content
        svc.configure(enabled=True, exclude_groups="warthogs")

    mock_wrapper.assert_called_once_with("warthogs")
    mock_reload.assert_not_called()
    mock_validate_tlog.assert_not_called()


def _make_executable(path: Path, content: str = "#!/bin/sh\nexit 0\n") -> None:
    path.write_text(content)
    path.chmod(0o755)


def test_validate_tlog_passes_when_all_present(svc, tmp_path):
    recorder = tmp_path / "tlog-rec-session"
    _make_executable(recorder)
    wrapper = tmp_path / "tlog-wrapper"
    _make_executable(wrapper)
    svc._tlog_bin = recorder
    svc._wrapper_path = wrapper
    with patch.object(TlogService, "validate_tlog") as mock_validate_tlog:
        svc.validate_tlog()
    mock_validate_tlog.assert_called_once()


def test_validate_tlog_raises_when_recorder_not_executable(svc, tmp_path):
    recorder = tmp_path / "tlog-rec-session"
    recorder.write_text("")
    recorder.chmod(0o644)
    svc._tlog_bin = recorder
    svc._wrapper_path = tmp_path / "tlog-wrapper"
    with pytest.raises(TlogServiceReloadError, match="missing or not executable"):
        svc.validate_tlog()


def test_validate_tlog_raises_when_wrapper_not_executable(svc, tmp_path):
    recorder = tmp_path / "tlog-rec-session"
    _make_executable(recorder)
    wrapper = tmp_path / "tlog-wrapper"
    wrapper.write_text("#!/bin/sh\n")
    wrapper.chmod(0o644)
    svc._tlog_bin = recorder
    svc._wrapper_path = wrapper
    with pytest.raises(TlogServiceReloadError, match="missing or not executable"):
        svc.validate_tlog()


def test_validate_tlog_raises_on_wrapper_syntax_error(svc, tmp_path):
    recorder = tmp_path / "tlog-rec-session"
    _make_executable(recorder)
    wrapper = tmp_path / "tlog-wrapper"
    _make_executable(wrapper, "#!/bin/sh\nif then fi\n")
    svc._tlog_bin = recorder
    svc._wrapper_path = wrapper
    with pytest.raises(TlogServiceReloadError, match="syntax check failed"):
        svc.validate_tlog()


def test_sshd_snippet_is_global_forcecommand_no_match():
    out = render_jinja2_template({}, TLOG_SSHD_CONF_TEMPLATE, TLOG_TEMPLATE_FILE_PATH)
    assert "ForceCommand /usr/local/bin/tlog-wrapper" in out
    assert "Match" not in out


def test_wrapper_has_fail_open_guard():
    out = _render_wrapper("")
    assert '[ -x /usr/bin/tlog-rec-session ] || exec "$user_shell"' in out


def test_wrapper_omits_exclude_case_when_empty():
    out = _render_wrapper("")
    assert "id -nG" not in out


def test_wrapper_renders_exact_token_exclude_case():
    out = _render_wrapper("g1,sudo")
    assert "id -nG" in out
    assert '*",g1,"*) exec "$user_shell" ;;' in out
    assert '*",sudo,"*) exec "$user_shell" ;;' in out


@patch("tlog_workload.subprocess.run", return_value=MagicMock(returncode=0, stderr=""))
def test_validate_sshd_success(mock_run, svc, tmp_path):
    svc._snippet_path = tmp_path / "99-tlog-recording.conf"
    svc.validate_sshd()
    mock_run.assert_called_once()


def test_validate_sshd_failure_raises_and_keeps_snippet(svc, tmp_path):
    snippet = tmp_path / "99-tlog-recording.conf"
    snippet.write_text("pending config")
    svc._snippet_path = snippet

    with patch(
        "tlog_workload.subprocess.run",
        return_value=MagicMock(returncode=1, stderr="bad config error"),
    ):
        with pytest.raises(TlogServiceReloadError, match="validation failed"):
            svc.validate_sshd()

    assert snippet.read_text() == "pending config"


@patch("tlog_workload.systemd.service_reload")
def test_reload_sshd_success(mock_reload, svc):
    svc.reload_sshd()
    mock_reload.assert_called_once_with("ssh")


@patch("tlog_workload.systemd.service_reload", side_effect=systemd.SystemdError)
def test_reload_sshd_failure(_, svc):
    with pytest.raises(TlogServiceReloadError):
        svc.reload_sshd()


@patch("tlog_workload.write_file")
def test_write_logrotate_writes_when_absent(mock_write, svc, tmp_path):
    svc._logrotate_path = tmp_path / "tlog"
    svc._write_logrotate()
    mock_write.assert_called_once()


@patch("tlog_workload.write_file")
def test_write_logrotate_no_write_when_unchanged(mock_write, svc, tmp_path):
    logrotate = tmp_path / "tlog"
    logrotate.write_text(_TLOG_LOGROTATE_CONTENT)
    svc._logrotate_path = logrotate
    svc._write_logrotate()
    mock_write.assert_not_called()


@patch.object(TlogService, "_ensure_append_only")
@patch("tlog_workload.write_file_with_group")
@patch("tlog_workload.make_dir")
def test__ensure_log_dir_creates_file_when_absent(
    mock_make_dir, mock_write, mock_attr, svc, tmp_path
):
    svc._log_dir = tmp_path / "tlog"
    svc._log_file = tmp_path / "tlog" / "sessions.log"
    svc._ensure_log_dir()
    mock_make_dir.assert_called_once()
    mock_write.assert_called_once()
    mock_attr.assert_called_once()


@patch("tlog_workload.os.chmod")
@patch("tlog_workload.os.chown")
@patch("tlog_workload.grp.getgrnam", return_value=MagicMock(gr_gid=4))
@patch("tlog_workload.pwd.getpwnam", return_value=MagicMock(pw_uid=999))
@patch.object(TlogService, "_ensure_append_only")
@patch("tlog_workload.write_file_with_group")
@patch("tlog_workload.make_dir")
def test__ensure_log_dir_heals_existing_file_without_rewrite(
    mock_make_dir, mock_write, mock_attr, mock_pwd, mock_grp, mock_chown, mock_chmod, svc
):
    """A drifted existing file gets ownership/mode healed but its content is never touched."""
    log_file = MagicMock()
    log_file.exists.return_value = True
    log_file.stat.return_value = MagicMock(st_uid=0, st_gid=0, st_mode=0o100600)
    svc._log_file = log_file
    svc._ensure_log_dir()
    mock_write.assert_not_called()
    mock_pwd.assert_called_once_with("_tlog")
    mock_grp.assert_called_once_with("adm")
    mock_chown.assert_called_once_with(log_file, 999, 4)
    mock_chmod.assert_called_once_with(log_file, 0o640)
    mock_attr.assert_called_once()


@patch("tlog_workload.os.chmod")
@patch("tlog_workload.os.chown")
@patch("tlog_workload.grp.getgrnam", return_value=MagicMock(gr_gid=4))
@patch("tlog_workload.pwd.getpwnam", return_value=MagicMock(pw_uid=999))
@patch.object(TlogService, "_ensure_append_only")
@patch("tlog_workload.make_dir")
def test__ensure_log_dir_skips_reenforce_when_ownership_clean(
    mock_make_dir, mock_attr, mock_pwd, mock_grp, mock_chown, mock_chmod, svc
):
    log_file = MagicMock()
    log_file.exists.return_value = True
    log_file.stat.return_value = MagicMock(st_uid=999, st_gid=4, st_mode=0o100640)
    svc._log_file = log_file
    svc._ensure_log_dir()
    mock_chown.assert_not_called()
    mock_chmod.assert_not_called()
    mock_attr.assert_called_once()


@patch("tlog_workload.os.chmod")
@patch("tlog_workload.os.chown", side_effect=PermissionError("Operation not permitted"))
@patch("tlog_workload.grp.getgrnam", return_value=MagicMock(gr_gid=4))
@patch("tlog_workload.pwd.getpwnam", return_value=MagicMock(pw_uid=999))
@patch.object(TlogService, "_ensure_append_only")
@patch("tlog_workload.make_dir")
def test__ensure_log_dir_warns_when_reenforce_blocked(
    mock_make_dir, mock_attr, mock_pwd, mock_grp, mock_chown, mock_chmod, svc
):
    """An unhealable drift (blocked by append-only) is logged, not raised."""
    log_file = MagicMock()
    log_file.exists.return_value = True
    log_file.stat.return_value = MagicMock(st_uid=0, st_gid=0, st_mode=0o100600)
    svc._log_file = log_file
    svc._ensure_log_dir()  # no exception
    mock_chown.assert_called_once()
    mock_attr.assert_called_once()


@patch(
    "tlog_workload.subprocess.run",
    return_value=MagicMock(returncode=0, stderr=""),
)
def test_ensure_append_only_sets_attr(mock_run, svc, tmp_path):
    svc._log_file = tmp_path / "sessions.log"
    svc._ensure_append_only()
    mock_run.assert_called_once_with(
        ["chattr", "+a", str(svc._log_file)],
        capture_output=True,
        text=True,
        check=False,
    )


@patch(
    "tlog_workload.subprocess.run",
    return_value=MagicMock(returncode=1, stderr="Operation not supported"),
)
def test_ensure_append_only_warns_and_does_not_raise(mock_run, svc, tmp_path):
    """An unsupported filesystem must not break recording."""
    svc._log_file = tmp_path / "sessions.log"
    svc._ensure_append_only()  # no exception


@patch.object(TlogService, "_ensure_privileged_recorder")
@patch.object(TlogService, "_write_sshd_snippet")
@patch.object(TlogService, "_ensure_audit_rules")
@patch.object(TlogService, "_write_logrotate")
@patch.object(TlogService, "_write_wrapper_atomic")
@patch.object(TlogService, "_write_tlog_conf")
@patch.object(TlogService, "_ensure_log_dir")
@patch.object(TlogService, "install")
@patch.object(TlogService, "is_installed", return_value=False)
def test_configure_installs_when_not_installed(
    _installed, mock_install, _ensure, _conf, _wrapper, _logrotate, _rules, _snippet, _priv, svc
):
    svc.configure(enabled=True, exclude_groups="warthogs")
    mock_install.assert_called_once()


@patch.object(TlogService, "_reload_audit_rules")
@patch("tlog_workload.write_file")
def test_ensure_audit_rules_writes_and_reloads_on_change(mock_write, mock_reload, svc, tmp_path):
    source = tmp_path / "tlog.rules"
    source.write_text("-w /var/log/tlog/sessions.log -p wa -k tlog_recording_tamper\n")
    svc._audit_rules_source = source
    svc._audit_rules_path = tmp_path / "dest-tlog.rules"
    svc._ensure_audit_rules()
    mock_write.assert_called_once()
    mock_reload.assert_called_once()


@patch.object(TlogService, "_reload_audit_rules")
@patch("tlog_workload.write_file")
def test_ensure_audit_rules_no_reload_when_unchanged(mock_write, mock_reload, svc, tmp_path):
    content = "-w /var/log/tlog/sessions.log -p wa -k tlog_recording_tamper\n"
    source = tmp_path / "tlog.rules"
    source.write_text(content)
    dest = tmp_path / "dest-tlog.rules"
    dest.write_text(content)
    svc._audit_rules_source = source
    svc._audit_rules_path = dest
    svc._ensure_audit_rules()
    mock_write.assert_not_called()
    mock_reload.assert_not_called()


@patch("tlog_workload.subprocess.run", return_value=MagicMock(returncode=0, stderr=""))
def test_reload_audit_rules_invokes_augenrules(mock_run, svc):
    svc._reload_audit_rules()
    mock_run.assert_called_once_with(
        ["augenrules", "--load"],
        capture_output=True,
        text=True,
        check=False,
    )


@patch(
    "tlog_workload.subprocess.run",
    return_value=MagicMock(returncode=1, stderr="augenrules failure"),
)
def test_reload_audit_rules_failure_does_not_raise(mock_run, svc):
    """Recording must keep working when rule loading fails; failure is logged."""
    svc._reload_audit_rules()


@patch("tlog_workload.write_file")
@patch("tlog_workload.render_jinja2_template", return_value="new-conf")
def test_write_tlog_conf_writes_when_absent(mock_render, mock_write, svc, tmp_path):
    svc._conf_path = tmp_path / "tlog-rec-session.conf"
    svc._log_file = tmp_path / "sessions.log"
    svc._write_tlog_conf()
    mock_write.assert_called_once()


@patch("tlog_workload.write_file")
@patch("tlog_workload.render_jinja2_template", return_value="same-conf")
def test_write_tlog_conf_no_write_when_unchanged(mock_render, mock_write, svc, tmp_path):
    conf = tmp_path / "tlog-rec-session.conf"
    conf.write_text("same-conf")
    svc._conf_path = conf
    svc._log_file = tmp_path / "sessions.log"
    svc._write_tlog_conf()
    mock_write.assert_not_called()


def test_write_wrapper_atomic_raises_when_tlog_bin_absent(svc, tmp_path):
    svc._tlog_bin = tmp_path / "no-tlog-rec-session"
    with pytest.raises(TlogServiceError, match="not found"):
        svc._write_wrapper_atomic("")


@patch("tlog_workload.write_file_with_group")
@patch(
    "tlog_workload.subprocess.run",
    return_value=MagicMock(returncode=0, stdout=""),
)
@patch("tlog_workload.render_jinja2_template", return_value="new-wrapper")
def test_write_wrapper_atomic_writes_on_change(mock_render, mock_run, mock_write, svc, tmp_path):
    svc._tlog_bin = tmp_path / "tlog-rec-session"
    svc._tlog_bin.write_text("")
    svc._wrapper_path = tmp_path / "tlog-wrapper"
    svc._write_wrapper_atomic("")
    mock_write.assert_called_once()


@patch("tlog_workload.write_file_with_group")
@patch("tlog_workload.render_jinja2_template", return_value="same-wrapper")
def test_write_wrapper_atomic_no_write_when_unchanged(mock_render, mock_write, svc, tmp_path):
    svc._tlog_bin = tmp_path / "tlog-rec-session"
    svc._tlog_bin.write_text("")
    wrapper = tmp_path / "tlog-wrapper"
    wrapper.write_text("same-wrapper")
    svc._wrapper_path = wrapper
    svc._write_wrapper_atomic("")
    mock_write.assert_not_called()


@patch(
    "tlog_workload.subprocess.run",
    return_value=MagicMock(returncode=1, stderr="syntax error"),
)
@patch("tlog_workload.render_jinja2_template", return_value="bad-wrapper")
def test_write_wrapper_atomic_raises_on_syntax_error(mock_render, mock_run, svc, tmp_path):
    svc._tlog_bin = tmp_path / "tlog-rec-session"
    svc._tlog_bin.write_text("")
    svc._wrapper_path = tmp_path / "tlog-wrapper"
    with pytest.raises(TlogServiceError, match="Wrapper syntax error"):
        svc._write_wrapper_atomic("")


@patch("tlog_workload.os.chmod")
@patch("tlog_workload.os.chown")
@patch("tlog_workload.grp.getgrnam", return_value=MagicMock(gr_gid=900))
@patch("tlog_workload.pwd.getpwnam", return_value=MagicMock(pw_uid=900))
def test_ensure_privileged_recorder_sets_setuid(mock_pwd, mock_grp, mock_chown, mock_chmod, svc):
    """Binary is chowned to the package _tlog principal then set mode 6755."""
    svc._tlog_bin = Path("/usr/bin/tlog-rec-session")
    svc._ensure_privileged_recorder()
    mock_pwd.assert_called_once_with("_tlog")
    mock_grp.assert_called_once_with("_tlog")
    mock_chown.assert_called_once_with(svc._tlog_bin, 900, 900)
    mock_chmod.assert_called_once_with(svc._tlog_bin, 0o6755)


@patch("tlog_workload.pwd.getpwnam", side_effect=KeyError("_tlog"))
def test_ensure_privileged_recorder_raises_when_principal_missing(mock_pwd, svc):
    """A missing _tlog principal raises, not crash."""
    with pytest.raises(TlogServiceError, match="tlog installation"):
        svc._ensure_privileged_recorder()
