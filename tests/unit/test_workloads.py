from subprocess import CalledProcessError
from unittest.mock import MagicMock, patch

import pytest
from charms.operator_libs_linux.v0 import apt
from charms.operator_libs_linux.v1 import systemd

from workloads import (
    AuditdConfig,
    AuditdService,
    AuditdServiceRestartError,
)


def test_auditd_config_valid_num_logs():
    num_logs = 10
    max_log_file = 512
    config = AuditdConfig(num_logs=num_logs, max_log_file=max_log_file)
    assert config.num_logs == num_logs
    assert config.max_log_file == max_log_file


def test_auditd_config_invalid_num_logs_low():
    with pytest.raises(ValueError):
        AuditdConfig(num_logs=-1, max_log_file=512)


def test_auditd_config_invalid_num_logs_high():
    with pytest.raises(ValueError):
        AuditdConfig(num_logs=1000, max_log_file=512)


@patch("workloads.apt.add_package")
@patch("workloads.AuditdService._add_audit_rules")
@patch("workloads.AuditdService._merge_audit_rules")
def test_install_calls_add_package_and_rules(mock_merge, mock_add_rules, mock_add_package):
    service = AuditdService()
    service.install()
    mock_add_package.assert_called_once()
    mock_add_rules.assert_called_once()
    mock_merge.assert_called_once()


@patch("workloads.apt.remove_package")
def test_remove_calls_remove_package(mock_remove_package):
    service = AuditdService()
    service.remove()
    mock_remove_package.assert_called_once()


@patch("workloads.systemd.service_restart")
def test_restart_success(mock_restart):
    service = AuditdService()
    service.restart()
    mock_restart.assert_called_once_with(service.name)


@patch("workloads.systemd.service_restart", side_effect=systemd.SystemdError)
def test_restart_failure(_):
    service = AuditdService()
    with pytest.raises(AuditdServiceRestartError):
        service.restart()


@patch("workloads.write_file")
@patch("workloads.AuditdService.restart")
def test_configure_writes_file_and_restarts(mock_restart, mock_write_file):
    service = AuditdService()
    service.configure("content")
    mock_write_file.assert_called_once()
    mock_restart.assert_called_once()


@patch("workloads.render_jinja2_template", return_value="rendered")
def test_render_config_returns_rendered(mock_render):
    service = AuditdService()
    result = service.render_config({"foo": "bar"})
    assert result == "rendered"
    mock_render.assert_called_once()


@patch("workloads.apt.DebianPackage.from_installed_package")
def test_is_installed_true(_):
    service = AuditdService()
    assert service.is_installed() is True


@patch("workloads.apt.DebianPackage.from_installed_package", side_effect=apt.PackageNotFoundError)
def test_is_installed_false(_):
    service = AuditdService()
    assert service.is_installed() is False


@patch("workloads.systemd.service_running", return_value=True)
def test_is_active_true(_):
    service = AuditdService()
    assert service.is_active() is True


@patch("workloads.systemd.service_running", return_value=False)
def test_is_active_false(_):
    service = AuditdService()
    assert service.is_active() is False


@patch("workloads.read_file", return_value="rule-content")
@patch("workloads.write_file")
@patch("workloads.Path.glob", return_value=[MagicMock(name="rule1", spec=["name"])])
def test_add_audit_rules(mock_glob, mock_write_file, mock_read_file):
    service = AuditdService()
    # Patch rule_file.name for the MagicMock
    rule_file = mock_glob.return_value[0]
    rule_file.name = "rule1"
    service._add_audit_rules("/some/path")
    mock_read_file.assert_called_once()
    mock_write_file.assert_called_once()


@patch("workloads.subprocess.run")
def test_merge_audit_rules_success(mock_run):
    service = AuditdService()
    service._merge_audit_rules()
    mock_run.assert_called_once_with(["augenrules", "--load"], check=False)


@patch("workloads.subprocess.run", side_effect=CalledProcessError(1, "augenrules --load"))
def test_merge_audit_rules_failure(_):
    service = AuditdService()
    with pytest.raises(CalledProcessError):
        service._merge_audit_rules()
