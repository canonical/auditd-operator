#!/usr/bin/env python3
# Copyright 2025 Canoincal Ltd.
# See LICENSE file for licensing details.

"""The entrypoint for auditd operator."""

import logging
import typing

import ops
import pydantic
from charms.grafana_agent.v0.cos_agent import COSAgentProvider

from utils import get_machine_virt_type, read_file
from workloads import AuditdConfig, AuditdService, AuditdServiceRestartError

logger = logging.getLogger(__name__)


class PlatformUnsupportedError(Exception):
    """Error when the platform is not supported."""


class AuditdOperatorCharm(ops.CharmBase):
    """Auditd service."""

    def __init__(self, *args: typing.Any) -> None:
        """Initialize the instance.

        Args:
            args: passthrough to CharmBase.

        """
        super().__init__(*args)

        self.auditd = AuditdService()

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
        if get_machine_virt_type() == "lxc":
            logger.warning("Not removing package: auditd cannot be run on a linux container.")
            return

        self.unit.status = ops.MaintenanceStatus("Removing auditd package.")
        self.auditd.remove()

    def _on_install_or_upgrade(self, _: tuple[ops.InstallEvent | ops.UpgradeCharmEvent]) -> None:
        """Handle install or upgrade charm event."""
        if get_machine_virt_type() == "lxc":
            logger.error("Not installing package: auditd cannot be run on a linux container.")
            raise PlatformUnsupportedError("Auditd cannot be run on a linux container.")

        self.unit.status = ops.MaintenanceStatus("Installing or upgrading auditd package.")
        self.auditd.install()

    def _configure_charm(self, _: ops.HookEvent) -> None:
        """Configure the charm idempotently."""
        if not (config := self._get_validated_config()):
            self.unit.status = ops.BlockedStatus("Invalid config. Please check `juju debug-log`.")
            return

        if not self._configure_auditd(config):
            self.unit.status = ops.BlockedStatus("Failed to configure and restart auditd.")
            return

        self.unit.status = ops.ActiveStatus()

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

        return True


if __name__ == "__main__":
    ops.main(AuditdOperatorCharm)
