#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""The entrypoint for auditd operator."""

import logging
import typing

import ops
import pydantic
from charms.grafana_agent.v0.cos_agent import COSAgentProvider

from tlog_workload import TlogService, TlogServiceError, TlogServiceReloadError
from utils import get_machine_virt_type, read_file
from workloads import AuditdConfig, AuditdService, AuditdServiceRestartError

logger = logging.getLogger(__name__)


class AuditdOperatorCharm(ops.CharmBase):
    """Auditd service."""

    def __init__(self, *args: typing.Any) -> None:
        """Initialize the instance.

        Args:
            args: passthrough to CharmBase.

        """
        super().__init__(*args)

        self.auditd = AuditdService()
        self.tlog = TlogService()

        # Forward auditd logs
        self.cos_agent_provider = COSAgentProvider(
            self,
            refresh_events=[self.on.install, self.on.upgrade_charm],
        )

        self.framework.observe(self.on.remove, self._on_remove)
        self.framework.observe(self.on.install, self._on_install_or_upgrade)
        self.framework.observe(self.on.update_status, self._configure_charm)
        self.framework.observe(self.on.upgrade_charm, self._configure_charm)
        self.framework.observe(self.on.config_changed, self._configure_charm)

    def _on_remove(self, _: ops.RemoveEvent) -> None:
        """Handle remove charm event."""
        self.unit.status = ops.MaintenanceStatus("Removing packages.")
        self.tlog.remove()
        if self._supports_auditd():
            self.auditd.remove()

    def _on_install_or_upgrade(self, _: tuple[ops.InstallEvent | ops.UpgradeCharmEvent]) -> None:
        """Handle install or upgrade charm event."""
        if not self._supports_auditd():
            logger.info(
                "Skipping auditd install: auditd cannot run on a linux container; "
                "continuing in session-recording-only mode."
            )
            return

        self.unit.status = ops.MaintenanceStatus("Installing or upgrading auditd package.")
        self.auditd.install()

    def _configure_charm(self, _: ops.HookEvent) -> None:
        """Configure the charm idempotently.

        On VM/metal, configures auditd and (optionally) tlog. On lxc containers, auditd is
        skipped: tlog recording runs when enabled (degraded mode, no tamper detection),
        otherwise the unit blocks since there is nothing to manage.
        """
        if not (config := self._get_validated_config()):
            self.unit.status = ops.BlockedStatus("Invalid config. Please check `juju debug-log`.")
            return

        if not self._supports_auditd():
            self._configure_charm_container(config)
            return

        ok_auditd = self._configure_auditd(config)
        ok_tlog = self._configure_tlog(config)

        if not ok_auditd:
            self.unit.status = ops.BlockedStatus("Failed to configure and restart auditd.")
        elif not ok_tlog:
            self.unit.status = ops.BlockedStatus("Failed to configure tlog recording.")
        else:
            self.unit.status = ops.ActiveStatus()

    def _configure_charm_container(self, config: dict) -> None:
        """Configure the charm on a container (session-recording-only mode).

        auditd is unavailable, so tlog runs without tamper-detection audit rules.
        Session recording enables recording when on, and clears leftover sshd snippet
        when off.

        Args:
            config (dict): The validated charm config.

        """
        if not self._configure_tlog(config, manage_audit_rules=False):
            if config.get("enable_session_recording", False):
                self.unit.status = ops.BlockedStatus("Failed to configure tlog recording.")
            else:
                self.unit.status = ops.BlockedStatus("Failed to disable tlog recording.")
            return

        if config.get("enable_session_recording", False):
            self.unit.status = ops.ActiveStatus(
                "Session recording only; auditd unsupported on LXC."
            )
        else:
            self.unit.status = ops.BlockedStatus(
                "auditd unsupported on LXC and session recording disabled."
            )

    def _supports_auditd(self) -> bool:
        """Check whether auditd can run on the current platform.

        auditd cannot run inside a linux container.

        Returns:
            True if the platform supports auditd, otherwise False.

        """
        if get_machine_virt_type() == "lxc":
            logger.info(
                "auditd cannot run on a linux container; continuing in "
                "session-recording-only mode."
            )
            return False
        return True

    def _get_validated_config(self) -> dict:
        """Get validated charm configs.

        Returns:
            The validated config (dict), or an empty dict if not validated.

        """
        try:
            config = self.load_config(AuditdConfig)
        except pydantic.ValidationError as e:
            logger.error("Failed to configure auditd service: %s", str(e))
            return {}
        return config.model_dump()

    def _configure_auditd(self, config: dict) -> bool:
        """Configure auditd.

        Args:
            config (dict): The validated charm config.

        Returns:
            True if the auditd service is properly configured, otherwise False.

        """
        new_content = self.auditd.render_config(config).strip()
        current_content = read_file(AuditdService.config_file).strip()

        if new_content != current_content:
            logging.info("Configuring auditd service.")
            try:
                self.auditd.configure(new_content)
            except AuditdServiceRestartError as e:
                logger.error("Failed to apply new config: %s", str(e))
                return False

        if not self.auditd.is_active():
            logger.error("Auditd is not active.")
            try:
                logger.info("Trying to restart auditd.")
                self.auditd.restart()
            except AuditdServiceRestartError as e:
                logger.error("Failed to restart auditd: %s", str(e))
                return False
            else:
                logger.info("Auditd restart successfully.")

        self.auditd.ensure_audit_rules()
        return True

    def _configure_tlog(self, config: dict, manage_audit_rules: bool = True) -> bool:
        """Configure tlog session recording.

        Args:
            config (dict): The validated charm config.
            manage_audit_rules (bool): Whether tlog should install the auditd
                tamper-detection rules. Passed False on containers where auditd is
                unavailable. Defaults to True (VM/metal).

        Returns:
            True if tlog recording configured successfully, otherwise False.

        """
        enabled = config.get("enable_session_recording", False)
        exclude_groups = config.get("session_recording_exclude_groups", "")
        try:
            self.tlog.configure(
                enabled=enabled,
                exclude_groups=exclude_groups,
                manage_audit_rules=manage_audit_rules,
            )
        except (TlogServiceError, TlogServiceReloadError) as e:
            logger.error("Failed to configure tlog recording: %s", str(e))
            return False
        return True


if __name__ == "__main__":  # pragma: nocover
    ops.main(AuditdOperatorCharm)
