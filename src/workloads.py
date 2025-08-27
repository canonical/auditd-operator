# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""The auditd service module."""

import logging
import subprocess
from pathlib import Path

import pydantic
from charms.operator_libs_linux.v0 import apt
from charms.operator_libs_linux.v1 import systemd

from literals import (
    AUDIT_RULE_PATH,
    AUDITD_CONFIG_TEMPLATE,
    AUDITD_MAX_NUM_LOGS,
    AUDITD_MIN_NUM_LOGS,
    TEMPLATE_FILE_PATH,
)
from utils import read_file, render_jinja2_template, write_file

logger = logging.getLogger()


class AuditRuleReloadError(Exception):
    """Error when reloading the audit rules."""


class AuditdServiceRestartError(Exception):
    """Error when restarting the auditd service."""


class AuditdServiceNotActiveError(Exception):
    """Error when the auditd service is not active."""


class AuditdConfig(pydantic.BaseModel):
    """Auditd charm configuration."""

    num_logs: int = pydantic.Field(10)
    max_log_file: int = pydantic.Field(512)

    @pydantic.field_validator("num_logs")
    @classmethod
    def validate_num_logs(cls, value: int) -> int:
        """Validate 'num_logs' charm config option."""
        if value < AUDITD_MIN_NUM_LOGS:
            raise ValueError(f"'num_logs' cannot be less than {AUDITD_MIN_NUM_LOGS}.")
        if value > AUDITD_MAX_NUM_LOGS:
            raise ValueError(f"'num_logs' cannot be larger than {AUDITD_MAX_NUM_LOGS}.")
        return value


class AuditdService:
    """Auditd service class."""

    pkg = "auditd"
    name = "auditd"
    rule_path = Path("/etc/audit/rules.d/")
    config_file = Path("/etc/audit/auditd.conf")

    def install(self) -> None:
        """Install the auditd package."""
        apt.add_package(package_names=self.pkg, update_cache=True)
        self._add_audit_rules(AUDIT_RULE_PATH)
        self._merge_audit_rules()

    def remove(self) -> None:
        """Remove the auditd package."""
        apt.remove_package(package_names=self.pkg)

    def restart(self) -> None:
        """Restart the auditd service.

        Raises:
            AuditdServiceRestartError: When the auditd service fails to restart.

        """
        try:
            systemd.service_restart(self.name)
        except systemd.SystemdError as exc:
            raise AuditdServiceRestartError(f"Failed to restart {self.name}.") from exc

    def configure(self, content: str) -> None:
        """Configure auditd service.

        Args:
            content (str): The content of auditd configuration.

        Raises:
            AuditdServiceRestartError: When the auditd service fails to restart.

        """
        write_file(self.config_file, content, "root", 0o640)
        self.restart()

    def render_config(self, context: dict) -> str:
        """Render auditd config file given the context.

        Args:
            context (dict): The context pass to the template file.

        """
        return render_jinja2_template(context, AUDITD_CONFIG_TEMPLATE, TEMPLATE_FILE_PATH)

    def is_installed(self) -> bool:
        """Indicate if auditd is installed.

        Returns:
            True if the auditd is installed.

        """
        try:
            apt.DebianPackage.from_installed_package(self.pkg)
        except apt.PackageNotFoundError:
            return False
        return True

    def is_active(self) -> bool:
        """Indicate if the auditd service is active.

        Returns:
            True if the auditd is running.

        """
        return systemd.service_running(self.name)

    def _add_audit_rules(self, path: str) -> None:
        """Add audit rule files.

        Args:
            path (str): The path to find the rule files.

        """
        for rule_file in Path(path).glob("*"):
            content = read_file(rule_file)
            destination = self.rule_path / rule_file.name
            logger.info("Writing audit rule to '%s'", destination)
            write_file(self.rule_path / rule_file.name, content, "root", 0o640)

    def _merge_audit_rules(self) -> None:
        """Merge all audit rule files."""
        try:
            logger.info("Installing audit rules.")
            subprocess.run(["augenrules", "--load"], check=False)
        except subprocess.CalledProcessError as e:
            logger.error("Failed to reload audit rules: %s", e.stderr)
            raise e
