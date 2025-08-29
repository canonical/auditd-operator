# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""The charm utilities module."""

import logging
import os
import pwd
import subprocess
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

logger = logging.getLogger(__name__)


def read_file(path: Path) -> str:
    """Read the content of a file.

    Args:
        path: Path object to the file.

    Returns:
        str: The content of the file.

    """
    return path.read_text(encoding="utf-8")


def write_file(path: Path, content: str, owner: str, mode: int = 0o600) -> None:
    """Write a content rendered from a template to a file.

    Args:
        path: Path object to the file.
        content: the data to be written to the file.
        owner: the owner of the file.
        mode: access permission mask applied to the file using chmod (default=0o600)

    """
    path.write_text(content, encoding="utf-8")
    os.chmod(path, mode)
    u = pwd.getpwnam(owner)
    os.chown(path, uid=u.pw_uid, gid=u.pw_gid)


def render_jinja2_template(context: dict, template_name: str, template_file_path: str) -> str:
    """Render the jinja2 template file with context.

    Args:
        context: dictionary of context pass to the template.
        template_name: the name of the template.
        template_file_path: the path to find the template files.

    Returns:
        str: the rendered content.

    """
    env = Environment(
        loader=FileSystemLoader(template_file_path),
        autoescape=select_autoescape(),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(template_name)
    rendered_content = template.render(context)
    return rendered_content


def get_machine_virt_type() -> str:
    """Get the machine_virt_type."""
    try:
        virt_type = subprocess.check_output(["systemd-detect-virt"]).decode().strip()
    except subprocess.CalledProcessError as e:
        logger.error("Failed to detect virtualization type: %s", e.stderr)
        raise e
    return virt_type
