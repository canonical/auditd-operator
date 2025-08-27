# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Common of globals variables to the charm."""

# Auditd rules
AUDIT_RULE_PATH = "./src/audit_rules"

# Template files
TEMPLATE_FILE_PATH = "./src/auditd_templates"
AUDITD_CONFIG_TEMPLATE = "auditd.conf.j2"

# Common constants
AUDITD_MIN_NUM_LOGS = 0
AUDITD_MAX_NUM_LOGS = 999
