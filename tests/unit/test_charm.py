from unittest.mock import patch

import pytest
from ops import testing

import charm
from charm import AuditdOperatorCharm


@patch("charm.AuditdService.remove")
@patch("charm.get_machine_virt_type", return_value="lxc")
def test_on_remove_lxc(mock_virt, mock_auditd_remove):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State()
    ctx.run(ctx.on.remove(), state)
    mock_auditd_remove.assert_not_called()


@patch("charm.AuditdService.remove")
@patch("charm.get_machine_virt_type", return_value="kvm")
def test_on_remove_non_lxc(mock_virt, mock_auditd_remove):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State()
    ctx.run(ctx.on.remove(), state)
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


@pytest.mark.parametrize(
    "config",
    [
        {"num_logs": -1, "max_log_file": 512},
        {"num_logs": 1000, "max_log_file": 512},
    ],
)
@patch.object(charm.AuditdOperatorCharm, "_configure_auditd")
def test_configure_charm_invalid_config(_, config):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config=config)
    out = ctx.run(ctx.on.config_changed(), state)
    assert out.unit_status == testing.BlockedStatus(
        "Invalid config. Please check `juju debug-log`."
    )


@patch.object(
    charm.AuditdOperatorCharm,
    "_get_validated_config",
    return_value={"num_logs": 2, "max_log_file": 512},
)
@patch.object(charm.AuditdOperatorCharm, "_configure_auditd", return_value=False)
def test_configure_charm_failed_configure(_, config):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config=config)
    out = ctx.run(ctx.on.config_changed(), state)
    assert out.unit_status == testing.BlockedStatus("Failed to configure and restart auditd.")


@patch.object(charm.AuditdOperatorCharm, "_configure_auditd", return_value=True)
def test_configure_charm_success(_):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config={"num_logs": 2, "max_log_file": 512})
    out = ctx.run(ctx.on.config_changed(), state)
    assert out.unit_status == testing.ActiveStatus()


@patch.object(charm.AuditdService, "render_config", return_value="new")
@patch("charm.read_file", return_value="old")
@patch.object(charm.AuditdService, "configure")
@patch.object(charm.AuditdService, "is_active", return_value=True)
def test_configure_auditd_changes_config(
    mock_is_active, mock_configure, mock_read_file, mock_render_config
):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config={"num_logs": 2, "max_log_file": 512})
    out = ctx.run(ctx.on.config_changed(), state)
    mock_configure.assert_called_once()
    assert out.unit_status == testing.ActiveStatus()


@patch.object(charm.AuditdService, "render_config", return_value="same")
@patch("charm.read_file", return_value="same")
@patch.object(charm.AuditdService, "configure")
@patch.object(charm.AuditdService, "is_active", return_value=True)
def test_configure_auditd_no_change(
    mock_is_active, mock_configure, mock_read_file, mock_render_config
):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config={"num_logs": 2, "max_log_file": 512})
    out = ctx.run(ctx.on.config_changed(), state)
    mock_configure.assert_not_called()
    assert out.unit_status == testing.ActiveStatus()


@patch.object(charm.AuditdService, "render_config", return_value="new")
@patch("charm.read_file", return_value="old")
@patch.object(
    charm.AuditdService, "configure", side_effect=charm.AuditdServiceRestartError("fail")
)
@patch.object(charm.AuditdService, "is_active", return_value=True)
def test_configure_auditd_configure_error(
    mock_is_active, mock_configure, mock_read_file, mock_render_config
):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config={"num_logs": 2, "max_log_file": 512})
    out = ctx.run(ctx.on.config_changed(), state)
    mock_configure.assert_called_once()
    assert out.unit_status == testing.BlockedStatus("Failed to configure and restart auditd.")


@patch.object(charm.AuditdService, "render_config", return_value="same")
@patch("charm.read_file", return_value="same")
@patch.object(charm.AuditdService, "is_active", return_value=False)
@patch.object(charm.AuditdService, "restart")
def test_configure_auditd_restart_success(
    mock_restart, mock_is_active, mock_read_file, mock_render_config
):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config={"num_logs": 2, "max_log_file": 512})
    out = ctx.run(ctx.on.config_changed(), state)
    mock_restart.assert_called_once()
    assert out.unit_status == testing.ActiveStatus()


@patch.object(charm.AuditdService, "render_config", return_value="same")
@patch("charm.read_file", return_value="same")
@patch.object(charm.AuditdService, "is_active", return_value=False)
@patch.object(charm.AuditdService, "restart", side_effect=charm.AuditdServiceRestartError("fail"))
def test_configure_auditd_restart_error(
    mock_restart, mock_is_active, mock_read_file, mock_render_config
):
    ctx = testing.Context(AuditdOperatorCharm)
    state = testing.State(config={"num_logs": 2, "max_log_file": 512})
    out = ctx.run(ctx.on.config_changed(), state)
    assert out.unit_status == testing.BlockedStatus("Failed to configure and restart auditd.")
