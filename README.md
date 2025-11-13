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
