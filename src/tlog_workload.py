# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The tlog session-recording service module."""

import grp
import logging
import os
import pwd
import stat
import subprocess
from pathlib import Path

from charms.operator_libs_linux.v0 import apt
from charms.operator_libs_linux.v1 import systemd

from constants import (
    TLOG_AUDIT_RULES_FILE,
    TLOG_AUDIT_RULES_SOURCE,
    TLOG_BIN,
    TLOG_BIN_MODE,
    TLOG_CONF_FILE,
    TLOG_LOG_DIR,
    TLOG_LOG_DIR_GROUP,
    TLOG_LOG_DIR_MODE,
    TLOG_LOG_DIR_OWNER,
    TLOG_LOG_FILE,
    TLOG_LOG_FILE_GROUP,
    TLOG_LOG_FILE_MODE,
    TLOG_LOG_FILE_OWNER,
    TLOG_LOGROTATE_FILE,
    TLOG_REC_SESSION_CONF_TEMPLATE,
    TLOG_SSHD_CONF_TEMPLATE,
    TLOG_SSHD_SNIPPET,
    TLOG_SYSTEM_GROUP,
    TLOG_SYSTEM_USER,
    TLOG_TEMPLATE_FILE_PATH,
    TLOG_WRAPPER_FILE,
    TLOG_WRAPPER_TEMPLATE,
)
from utils import make_dir, read_file, render_jinja2_template, write_file, write_file_with_group

# logrotate config for /var/log/tlog/sessions.log.
# prerotate/postrotate chattr dance: +a forbids rename+truncate so default rotate fails.
# tlog reopens the file per session, so new sessions pick up the rotated path automatically.
_TLOG_LOGROTATE_CONTENT = f"""\
{TLOG_LOG_FILE} {{
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 _tlog adm
    prerotate
        chattr -a {TLOG_LOG_FILE} 2>/dev/null || true
    endscript
    postrotate
        chattr +a {TLOG_LOG_FILE} 2>/dev/null || true
    endscript
}}
"""

logger = logging.getLogger(__name__)


class TlogServiceError(Exception):
    """Base error for TlogService failures."""


class TlogServiceReloadError(TlogServiceError):
    """sshd reload or sshd -t validation failure."""


class TlogService:
    """Manages tlog installation, configuration, and sshd wiring."""

    pkg = "tlog"
    sshd_service = "ssh"

    _conf_path = Path(TLOG_CONF_FILE)
    _wrapper_path = Path(TLOG_WRAPPER_FILE)
    _snippet_path = Path(TLOG_SSHD_SNIPPET)
    _log_dir = Path(TLOG_LOG_DIR)
    _log_file = Path(TLOG_LOG_FILE)
    _tlog_bin = Path(TLOG_BIN)
    _logrotate_path = Path(TLOG_LOGROTATE_FILE)
    _audit_rules_source = Path(TLOG_AUDIT_RULES_SOURCE)
    _audit_rules_path = Path(TLOG_AUDIT_RULES_FILE)

    def install(self) -> None:
        """Install the tlog package; raise TlogServiceError on failure.

        Raises:
            TlogServiceError: installation failed.

        """
        try:
            apt.add_package(package_names=self.pkg)
        except apt.PackageError as exc:
            raise TlogServiceError(
                f"Failed to install '{self.pkg}'. If the package was not found, "
                "ensure the 'universe' apt pocket is enabled."
            ) from exc

    def remove(self) -> None:
        """Remove tlog package."""
        if self.is_installed():
            apt.remove_package(package_names=self.pkg)

    def is_installed(self) -> bool:
        """Return True if tlog is installed."""
        try:
            apt.DebianPackage.from_installed_package(self.pkg)
        except apt.PackageNotFoundError:
            return False
        return True

    def _ensure_log_dir(self) -> None:
        """Ensure /var/log/tlog/ and the log file exist with privileged ownership.

        On an existing file, ownership/mode are re-applied only when they have drifted.
        Failure to re-apply is due to the expected append-only attribute of the log file,
        so it is logged as a warning but not raised.

        """
        make_dir(self._log_dir, TLOG_LOG_DIR_OWNER, TLOG_LOG_DIR_GROUP, TLOG_LOG_DIR_MODE)
        if not self._log_file.exists():
            write_file_with_group(
                self._log_file, "", TLOG_LOG_FILE_OWNER, TLOG_LOG_FILE_GROUP, TLOG_LOG_FILE_MODE
            )
        else:
            self._reenforce_log_file_ownership()
        self._ensure_append_only()

    def _reenforce_log_file_ownership(self) -> None:
        """Try to re-apply log-file ownership/mode only when it has drifted."""
        uid = pwd.getpwnam(TLOG_LOG_FILE_OWNER).pw_uid
        gid = grp.getgrnam(TLOG_LOG_FILE_GROUP).gr_gid
        info = self._log_file.stat()
        needs_chown = info.st_uid != uid or info.st_gid != gid
        needs_chmod = stat.S_IMODE(info.st_mode) != TLOG_LOG_FILE_MODE
        if not (needs_chown or needs_chmod):
            return
        try:
            if needs_chown:
                os.chown(self._log_file, uid, gid)
            if needs_chmod:
                os.chmod(self._log_file, TLOG_LOG_FILE_MODE)
        except OSError as exc:
            logger.warning(
                "Could not re-enforce ownership/mode on %s (recording continues; "
                "auditd watch still detects tampering): %s",
                self._log_file,
                exc,
            )

    def _ensure_append_only(self) -> None:
        """Set append-only (chattr +a) on sessions.log as tamper hardening.

        Runs every reconcile so it self-heals on already-created files.

        A failure is logged, not raised to not block the recording,
        the auditd watch rule on sessions.log is the detection backstop.

        """
        result = subprocess.run(
            ["chattr", "+a", str(self._log_file)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logger.warning(
                "Could not set append-only on %s (recording continues; auditd watch "
                "still detects tampering): %s",
                self._log_file,
                result.stderr.strip(),
            )

    def _ensure_privileged_recorder(self) -> None:
        """Reproduce the upstream setuid configuration.

        The Ubuntu tlog package already creates the `_tlog` system user/group but it ships
        tlog-rec-session as a plain root:root executable. Upstream ships the same binary mode
        6755 owned by tlog user:
        (https://github.com/Scribery/tlog/blob/006f58ab1af0cb55247f1baf4fcfba08e9870b16/tlog.spec#L124).

        The file writer relies on that setuid privilege-drop: the binary saves the
        privileged `_tlog` euid/egid, drops to the connecting user for the recorded
        shell, then opens the shared sessions.log and the /run/tlog session lock
        with the saved `_tlog` privilege. Without it the unprivileged recorded user
        cannot write the tamper-protected (_tlog:adm 0640) log and recording fails
        with EACCES.

        Sets the binary to `_tlog:_tlog` mode 6755. Runs on every reconcile because a package
        upgrade reverts the binary to root:root non-setuid.

        Raises:
            TlogServiceError: the `_tlog` principal is missing or the binary mode
                change failed.

        """
        try:
            uid = pwd.getpwnam(TLOG_SYSTEM_USER).pw_uid
            gid = grp.getgrnam(TLOG_SYSTEM_GROUP).gr_gid
            os.chown(self._tlog_bin, uid, gid)
            os.chmod(self._tlog_bin, TLOG_BIN_MODE)
        except (KeyError, OSError) as exc:
            raise TlogServiceError(
                f"Failed to set up the privileged tlog recorder "
                f"(Check tlog installation so '{TLOG_SYSTEM_USER}' exists?): {exc}"
            ) from exc

    def configure(self, enabled: bool, exclude_groups: str) -> None:
        """Enable or disable tlog recording.

        Args:
            enabled (bool): Globally toggle the session recording. False removes
                the sshd drop-in and tamper rules (recording off).
            exclude_groups (str): Comma-joined group names. Members of these groups are
                dropped into their real shell unrecorded. Empty string records everyone.

        Raises:
            TlogServiceError: wrapper validation failed (no snippet written).
            TlogServiceReloadError: sshd -t, self-test, or reload failed (previous snippet
                state restored).

        """
        if not enabled:
            self._disable()
            return

        if not self.is_installed():
            self.install()

        self._ensure_privileged_recorder()
        self._ensure_log_dir()
        self._write_tlog_conf()
        self._write_wrapper_atomic(exclude_groups)
        self._write_logrotate()
        self._ensure_audit_rules()
        self._write_sshd_snippet()

    def _disable(self) -> None:
        """Remove the sshd snippet and tamper rules; reload only what existed.

        Raises:
            TlogServiceReloadError: sshd reload failed on snippet removal (snippet restored).

        """
        if self._snippet_path.exists():
            previous = self._snippet_path.read_text(encoding="utf-8")
            self._snippet_path.unlink()
            try:
                self.reload_sshd()
            except TlogServiceReloadError:
                write_file(self._snippet_path, previous, "root", 0o644)
                raise
        if self._audit_rules_path.exists():
            previous_rules = self._audit_rules_path.read_text(encoding="utf-8")
            self._audit_rules_path.unlink()
            if not self._reload_audit_rules():
                write_file(self._audit_rules_path, previous_rules, "root", 0o640)

    def _ensure_audit_rules(self) -> None:
        """Install the tamper-detection audit rules and load them if changed."""
        content = read_file(self._audit_rules_source)
        current = (
            self._audit_rules_path.read_text(encoding="utf-8")
            if self._audit_rules_path.exists()
            else ""
        )
        if content != current:
            write_file(self._audit_rules_path, content, "root", 0o640)
            self._reload_audit_rules()

    def _reload_audit_rules(self) -> bool:
        """Reload the merged audit rules.

        A failure is logged, not raised, so recording still works without the
        tamper-detection rules, and the rules retry on the next reconcile that
        changes them.

        Returns:
            True if the reload succeeded, False otherwise.

        """
        result = subprocess.run(
            ["augenrules", "--load"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logger.warning("Failed to load audit rules: %s", result.stderr.strip())
            return False
        return True

    def _write_tlog_conf(self) -> None:
        """Write tlog-rec-session.conf if content changed."""
        new_content = render_jinja2_template(
            {"log_file": str(self._log_file)},
            TLOG_REC_SESSION_CONF_TEMPLATE,
            TLOG_TEMPLATE_FILE_PATH,
        )
        current = self._conf_path.read_text(encoding="utf-8") if self._conf_path.exists() else ""
        if new_content.strip() != current.strip():
            self._conf_path.parent.mkdir(parents=True, exist_ok=True)
            write_file(self._conf_path, new_content, "root", 0o644)

    def _write_wrapper_atomic(self, exclude_groups: str) -> None:
        """Atomically write and validate tlog-wrapper.

        Args:
            exclude_groups (str): Comma-joined group names rendered into the wrapper's
                exemption case. Members of these groups exec their real shell unrecorded.

        Raises:
            TlogServiceError: if the wrapper fails sh -n, is non-executable after write,
                              or tlog-rec-session binary is absent.

        """
        if not self._tlog_bin.exists():
            raise TlogServiceError(f"{TLOG_BIN} not found; is tlog installed?")

        new_wrapper = render_jinja2_template(
            {"session_recording_exclude_groups": exclude_groups},
            TLOG_WRAPPER_TEMPLATE,
            TLOG_TEMPLATE_FILE_PATH,
        )
        current = (
            self._wrapper_path.read_text(encoding="utf-8") if self._wrapper_path.exists() else ""
        )
        if new_wrapper == current:
            return

        # Validate content before writing (syntax check)
        result = subprocess.run(
            ["sh", "-n"],
            input=new_wrapper,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise TlogServiceError(f"Wrapper syntax error: {result.stderr.strip()}")

        write_file_with_group(self._wrapper_path, new_wrapper, "root", "root", 0o755)

    def _write_logrotate(self) -> None:
        """Write /etc/logrotate.d/tlog if content changed (chattr +a aware)."""
        current = (
            self._logrotate_path.read_text(encoding="utf-8")
            if self._logrotate_path.exists()
            else ""
        )
        if _TLOG_LOGROTATE_CONTENT != current:
            write_file(self._logrotate_path, _TLOG_LOGROTATE_CONTENT, "root", 0o644)

    def _write_sshd_snippet(self) -> None:
        """Write the (static) sshd drop-in, validate, then reload sshd.

        On validation or reload failure the previous snippet (or its absence)
        is restored, so the on-disk state stays last-known-good and the next
        reconcile sees a content difference and retries the full
        write/validate/reload sequence.

        Raises:
            TlogServiceReloadError: pre-reload validation or reload itself failed (previous snippet
                state restored).

        """
        new_snippet = render_jinja2_template({}, TLOG_SSHD_CONF_TEMPLATE, TLOG_TEMPLATE_FILE_PATH)
        current = (
            self._snippet_path.read_text(encoding="utf-8") if self._snippet_path.exists() else ""
        )
        if new_snippet == current:
            return

        self._snippet_path.parent.mkdir(parents=True, exist_ok=True)
        write_file(self._snippet_path, new_snippet, "root", 0o644)
        try:
            self.validate_tlog()
            self.validate_sshd()
            self.reload_sshd()
        except TlogServiceReloadError:
            if current:
                write_file(self._snippet_path, current, "root", 0o644)
            else:
                self._snippet_path.unlink(missing_ok=True)
            raise

    def validate_tlog(self) -> None:
        """Validate the tlog binary and wrapper.

        Verify that the recorder binary and wrapper script exist and are executable and the wrapper
        is syntactically valid.
        Run before every sshd reload to catch issues that would cause reload failures.

        Raises:
            TlogServiceReloadError: any static check failed.

        """
        if not (self._tlog_bin.exists() and os.access(self._tlog_bin, os.X_OK)):
            raise TlogServiceReloadError(f"{TLOG_BIN} is missing or not executable.")
        if not (self._wrapper_path.exists() and os.access(self._wrapper_path, os.X_OK)):
            raise TlogServiceReloadError(f"{TLOG_WRAPPER_FILE} is missing or not executable.")
        result = subprocess.run(
            ["sh", "-n", str(self._wrapper_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise TlogServiceReloadError(f"Wrapper syntax check failed: {result.stderr.strip()}")

    def validate_sshd(self) -> None:
        """Run sshd -t and raise if the sshd configuration is invalid.

        Run before every sshd reload to catch issues that would cause reload failures.

        Raises:
            TlogServiceReloadError: sshd config is invalid.

        """
        result = subprocess.run(
            ["sshd", "-t"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logger.error("sshd -t failed: %s", result.stderr.strip())
            raise TlogServiceReloadError(f"sshd config validation failed: {result.stderr.strip()}")

    def reload_sshd(self) -> None:
        """Reload sshd without dropping live sessions.

        Raises:
            TlogServiceReloadError: reload failed.

        """
        try:
            systemd.service_reload(self.sshd_service)
        except systemd.SystemdError as exc:
            raise TlogServiceReloadError(f"Failed to reload {self.sshd_service}.") from exc
