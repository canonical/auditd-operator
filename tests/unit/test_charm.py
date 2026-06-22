from unittest.mock import patch

import pytest
from ops import testing

import charm
from charm import AuditdOperatorCharm


@patch("charm.AuditdService.remove")
@patch("charm.TlogService.remove")
@patch("charm.get_machine_virt_type", return_value="lxc")
def test_on_remove_lxc(mock_virt, mock_tlog_remove, mock_auditd_remove):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State()
    ctx.run(ctx.on.remove(), state)
    mock_auditd_remove.assert_not_called()
    mock_tlog_remove.assert_not_called()


@patch("charm.AuditdService.remove")
@patch("charm.TlogService.remove")
@patch("charm.get_machine_virt_type", return_value="kvm")
def test_on_remove_non_lxc(mock_virt, mock_tlog_remove, mock_auditd_remove):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State()
    ctx.run(ctx.on.remove(), state)
    mock_tlog_remove.assert_called_once()
    mock_auditd_remove.assert_called_once()


@patch("charm.AuditdService.install")
@patch("charm.get_machine_virt_type", return_value="lxc")
def test_on_install_lxc(mock_virt, mock_auditd_install):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State()
    with pytest.raises(testing.errors.UncaughtCharmError) as e:
        ctx.run(ctx.on.install(), state)
        mock_auditd_install.assert_not_called()
    assert isinstance(e.value.__cause__, charm.PlatformUnsupportedError)


@patch("charm.AuditdService.install")
@patch("charm.get_machine_virt_type", return_value="kvm")
def test_on_install_non_lxc(mock_virt, mock_auditd_install):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State()
    ctx.run(ctx.on.install(), state)
    mock_auditd_install.assert_called_once()


@patch("charm.AuditdService.install")
@patch("charm.get_machine_virt_type", return_value="lxc")
def test_on_upgrade_lxc(mock_virt, mock_auditd_install):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State()
    with pytest.raises(testing.errors.UncaughtCharmError) as e:
        ctx.run(ctx.on.install(), state)
        mock_auditd_install.assert_not_called()
    assert isinstance(e.value.__cause__, charm.PlatformUnsupportedError)


@patch("charm.AuditdService.install")
@patch("charm.get_machine_virt_type", return_value="kvm")
def test_on_upgrade_non_lxc(mock_virt, mock_auditd_install):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State()
    ctx.run(ctx.on.install(), state)
    mock_auditd_install.assert_called_once()


@patch("charm.get_machine_virt_type", return_value="lxc")
def test_configure_charm_lxc_returns_blocked(mock_virt):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config={"num_logs": 2, "max_log_file": 512})
    out = ctx.run(ctx.on.config_changed(), state)
    assert out.unit_status == testing.BlockedStatus("Platform not supported (LXC).")


@pytest.mark.parametrize(
    "config",
    [
        {"num_logs": -1, "max_log_file": 512},
        {"num_logs": 1000, "max_log_file": 512},
    ],
)
@patch("charm.get_machine_virt_type", return_value="kvm")
@patch.object(charm.AuditdOperatorCharm, "_configure_auditd")
def test_configure_charm_invalid_config(_, mock_virt, config):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config=config)
    out = ctx.run(ctx.on.config_changed(), state)
    assert out.unit_status == testing.BlockedStatus(
        "Invalid config. Please check `juju debug-log`."
    )


@patch("charm.get_machine_virt_type", return_value="kvm")
@patch.object(
    charm.AuditdOperatorCharm,
    "_get_validated_config",
    return_value={
        "num_logs": 2,
        "max_log_file": 512,
        "enable_session_recording": True,
        "session_recording_exclude_groups": "",
    },
)
@patch.object(charm.AuditdOperatorCharm, "_configure_tlog", return_value=True)
@patch.object(charm.AuditdOperatorCharm, "_configure_auditd", return_value=False)
def test_configure_charm_failed_auditd(mock_auditd, mock_tlog, mock_config, mock_virt):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State()
    out = ctx.run(ctx.on.config_changed(), state)
    assert out.unit_status == testing.BlockedStatus("Failed to configure and restart auditd.")
    mock_auditd.assert_called_once()
    mock_tlog.assert_called_once()


@patch("charm.get_machine_virt_type", return_value="kvm")
@patch.object(
    charm.AuditdOperatorCharm,
    "_get_validated_config",
    return_value={
        "num_logs": 2,
        "max_log_file": 512,
        "enable_session_recording": True,
        "session_recording_exclude_groups": "",
    },
)
@patch.object(charm.AuditdOperatorCharm, "_configure_tlog", return_value=False)
@patch.object(charm.AuditdOperatorCharm, "_configure_auditd", return_value=True)
def test_configure_charm_failed_tlog(mock_auditd, mock_tlog, mock_config, mock_virt):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State()
    out = ctx.run(ctx.on.config_changed(), state)
    assert out.unit_status == testing.BlockedStatus("Failed to configure tlog recording.")


@patch("charm.get_machine_virt_type", return_value="kvm")
@patch.object(
    charm.AuditdOperatorCharm,
    "_get_validated_config",
    return_value={
        "num_logs": 2,
        "max_log_file": 512,
        "enable_session_recording": True,
        "session_recording_exclude_groups": "",
    },
)
@patch.object(charm.AuditdOperatorCharm, "_configure_tlog", return_value=False)
@patch.object(charm.AuditdOperatorCharm, "_configure_auditd", return_value=False)
def test_configure_charm_auditd_failure_dominates_tlog(
    mock_auditd, mock_tlog, mock_config, mock_virt
):
    """Auditd failure must dominate status even when tlog also fails."""
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State()
    out = ctx.run(ctx.on.config_changed(), state)
    assert out.unit_status == testing.BlockedStatus("Failed to configure and restart auditd.")


@patch("charm.get_machine_virt_type", return_value="kvm")
@patch.object(charm.AuditdOperatorCharm, "_configure_tlog", return_value=True)
@patch.object(charm.AuditdOperatorCharm, "_configure_auditd", return_value=True)
def test_configure_charm_success(mock_auditd, mock_tlog, mock_virt):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config={"num_logs": 2, "max_log_file": 512})
    out = ctx.run(ctx.on.config_changed(), state)
    assert out.unit_status == testing.ActiveStatus()


@patch("charm.get_machine_virt_type", return_value="kvm")
@patch.object(charm.AuditdOperatorCharm, "_configure_tlog", return_value=True)
@patch.object(charm.AuditdService, "ensure_audit_rules")
@patch.object(charm.AuditdService, "render_config", return_value="new")
@patch("charm.read_file", return_value="old")
@patch.object(charm.AuditdService, "configure")
@patch.object(charm.AuditdService, "is_active", return_value=True)
def test_configure_auditd_changes_config(
    mock_is_active,
    mock_configure,
    mock_read_file,
    mock_render_config,
    mock_ensure,
    mock_tlog,
    mock_virt,
):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config={"num_logs": 2, "max_log_file": 512})
    out = ctx.run(ctx.on.config_changed(), state)
    mock_configure.assert_called_once()
    mock_ensure.assert_called_once()
    assert out.unit_status == testing.ActiveStatus()


@patch("charm.get_machine_virt_type", return_value="kvm")
@patch.object(charm.AuditdOperatorCharm, "_configure_tlog", return_value=True)
@patch.object(charm.AuditdService, "ensure_audit_rules")
@patch.object(charm.AuditdService, "render_config", return_value="same")
@patch("charm.read_file", return_value="same")
@patch.object(charm.AuditdService, "configure")
@patch.object(charm.AuditdService, "is_active", return_value=True)
def test_configure_auditd_no_change(
    mock_is_active,
    mock_configure,
    mock_read_file,
    mock_render_config,
    mock_ensure,
    mock_tlog,
    mock_virt,
):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config={"num_logs": 2, "max_log_file": 512})
    out = ctx.run(ctx.on.config_changed(), state)
    mock_configure.assert_not_called()
    assert out.unit_status == testing.ActiveStatus()


@patch("charm.get_machine_virt_type", return_value="kvm")
@patch.object(charm.AuditdOperatorCharm, "_configure_tlog", return_value=True)
@patch.object(charm.AuditdService, "ensure_audit_rules")
@patch.object(charm.AuditdService, "render_config", return_value="new")
@patch("charm.read_file", return_value="old")
@patch.object(
    charm.AuditdService, "configure", side_effect=charm.AuditdServiceRestartError("fail")
)
@patch.object(charm.AuditdService, "is_active", return_value=True)
def test_configure_auditd_configure_error(
    mock_is_active,
    mock_configure,
    mock_read_file,
    mock_render_config,
    mock_ensure,
    mock_tlog,
    mock_virt,
):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config={"num_logs": 2, "max_log_file": 512})
    out = ctx.run(ctx.on.config_changed(), state)
    mock_configure.assert_called_once()
    assert out.unit_status == testing.BlockedStatus("Failed to configure and restart auditd.")


@patch("charm.get_machine_virt_type", return_value="kvm")
@patch.object(charm.AuditdOperatorCharm, "_configure_tlog", return_value=True)
@patch.object(charm.AuditdService, "ensure_audit_rules")
@patch.object(charm.AuditdService, "render_config", return_value="same")
@patch("charm.read_file", return_value="same")
@patch.object(charm.AuditdService, "is_active", return_value=False)
@patch.object(charm.AuditdService, "restart")
def test_configure_auditd_restart_success(
    mock_restart,
    mock_is_active,
    mock_read_file,
    mock_render_config,
    mock_ensure,
    mock_tlog,
    mock_virt,
):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config={"num_logs": 2, "max_log_file": 512})
    out = ctx.run(ctx.on.config_changed(), state)
    mock_restart.assert_called_once()
    assert out.unit_status == testing.ActiveStatus()


@patch("charm.get_machine_virt_type", return_value="kvm")
@patch.object(charm.AuditdOperatorCharm, "_configure_tlog", return_value=True)
@patch.object(charm.AuditdService, "ensure_audit_rules")
@patch.object(charm.AuditdService, "render_config", return_value="same")
@patch("charm.read_file", return_value="same")
@patch.object(charm.AuditdService, "is_active", return_value=False)
@patch.object(charm.AuditdService, "restart", side_effect=charm.AuditdServiceRestartError("fail"))
def test_configure_auditd_restart_error(
    mock_restart,
    mock_is_active,
    mock_read_file,
    mock_render_config,
    mock_ensure,
    mock_tlog,
    mock_virt,
):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config={"num_logs": 2, "max_log_file": 512})
    out = ctx.run(ctx.on.config_changed(), state)
    assert out.unit_status == testing.BlockedStatus("Failed to configure and restart auditd.")


@patch("charm.get_machine_virt_type", return_value="kvm")
@patch.object(charm.AuditdOperatorCharm, "_configure_auditd", return_value=True)
@patch.object(charm.TlogService, "configure")
def test_configure_tlog_calls_configure_with_exclude_groups(mock_tlog_conf, _, mock_virt):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(
        config={
            "num_logs": 2,
            "max_log_file": 512,
            "session_recording_exclude_groups": "warthogs",
        }
    )
    out = ctx.run(ctx.on.config_changed(), state)
    mock_tlog_conf.assert_called_once_with(enabled=True, exclude_groups="warthogs")
    assert out.unit_status == testing.ActiveStatus()


@patch("charm.get_machine_virt_type", return_value="kvm")
@patch.object(charm.AuditdOperatorCharm, "_configure_auditd", return_value=True)
@patch.object(charm.TlogService, "configure")
def test_configure_tlog_disabled_passes_enabled_false(mock_tlog_conf, _, mock_virt):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(
        config={"num_logs": 2, "max_log_file": 512, "enable_session_recording": False}
    )
    out = ctx.run(ctx.on.config_changed(), state)
    mock_tlog_conf.assert_called_once_with(enabled=False, exclude_groups="")
    assert out.unit_status == testing.ActiveStatus()


@patch("charm.get_machine_virt_type", return_value="kvm")
@patch.object(charm.AuditdOperatorCharm, "_configure_auditd", return_value=True)
@patch.object(charm.TlogService, "configure", side_effect=charm.TlogServiceError("fail"))
def test_configure_tlog_error_returns_blocked(mock_tlog_conf, _, mock_virt):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config={"num_logs": 2, "max_log_file": 512})
    out = ctx.run(ctx.on.config_changed(), state)
    assert out.unit_status == testing.BlockedStatus("Failed to configure tlog recording.")
