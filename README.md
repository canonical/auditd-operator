# Overview

A Juju charm that deploys and manages [`auditd`][1] on machine. [`auditd`][1] is  the  userspace
component to the  Linux Auditing System. It's responsible for writing audit records to the disk.

## Platform Requirements

This charm can only be deployed on **bare metal machines or virtual machines**. It **cannot** be
deployed on Linux containers (LXC).

[`auditd`][1] performs kernel-level auditing and requires direct access to the kernel's audit
subsystem, which is not available within containers. The charm will automatically prevent
deployment on unsupported platforms (LXC containers) and raise an error during installation.

[1]: https://manpages.ubuntu.com/manpages/noble/man8/auditd.8.html

## Session Recording

The charm records SSH sessions using [`tlog`][2] on a **best-effort, default-on** basis.
A global `ForceCommand` in the sshd drop-in wraps every inbound SSH login; `tlog-rec-session`
records interactive sessions and remote commands to `/var/log/tlog/sessions.log`.

Requires `tlog` from the Ubuntu `universe` pocket. Ensure it is enabled before enabling session recording.

### Configuration

**Default-on** - recording is active immediately after install.

```
# exempt members of "handover-squad" and "deploy-bots" groups from recording
juju config auditd session_recording_exclude_groups="handover-squad,deploy-bots"

# turn recording off entirely
juju config auditd enable_session_recording=false
```

- `enable_session_recording` (boolean, default `true`) - master switch; set to `false` to
  remove the sshd drop-in and disable recording entirely.
- `session_recording_exclude_groups` (string, default `""`) - comma-separated Unix group names
  whose members are dropped into their real shell unrecorded. Membership is matched on primary
  **or** supplementary groups. Empty string (default) means record everyone.

### Security caveats

- **Root can evade recording.** Root-equivalent users can bypass the `ForceCommand` wrapper
  (e.g. by running a second sshd with custom config). This is covered by auditd
  tamper-detection rules installed alongside session recording.
- **Recordings contain secrets.** Recording captures everything *displayed* in the terminal:
  commands as typed (echoed by the shell) and full program output (e.g. `cat admin.conf`,
  kubeconfigs, tokens). Passwords entered at non-echoing prompts (sudo, SSH) are not captured -
  terminal input recording is disabled. Before enabling, ensure that Loki has appropriate RBAC
  and data-retention policies so that tlog records are accessible only to authorised operators
  and are retained no longer than required.
- **File transfers are not recorded.** `scp`, `rsync`, and sftp sessions are passed through
  unrecorded (the tlog pty layer would corrupt binary framing). They are still covered by auditd
  path-watch rules.

### Tamper detection & alerting

auditd watches these session-recording assets:
- recording file and its rotated copies
- tlog and sshd config
- sshd drop-in for tlog-wrapper ForceCommand
- tlog wrapper
- setuid recorder binary
- logrotate config,
- the audit rules themselves
and records all writes/attribute changes.

Loki alert rules turn the audit logs into pages, but the alerts are paging only on **interactive**
tampering, which is distinguished by the audit `auid` (login uid). The charm's own legitimate
activities run in daemon context (`auid` unset) and should be suppressed at the pager while still
being recorded in the audit log.


### Replay

All sessions share one file; each recording is identified by its `rec` field. List the
recordings, then replay one:

```
# list recordings
sudo jq -r 'select(.id==1) | "\(.rec)  \(.user)  \(.time | todate)"' /var/log/tlog/sessions.log

# replay a specific recording
sudo tlog-play -r file -i /var/log/tlog/sessions.log -m "<rec-id>"
```

[2]: https://github.com/Scribery/tlog
