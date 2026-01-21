#!/usr/bin/env python3
"""
BisonTitan Security Suite - Setup Script

This setup.py exists for backwards compatibility with older pip versions
and editable installs. Configuration is in pyproject.toml.

Version is managed by setuptools_scm from git tags:
    git tag v1.0.0
    git tag v1.0.1

The version is auto-generated to src/bisontitan/_version.py on install.
"""

from setuptools import setup

# setuptools_scm will handle versioning from git tags
# Configuration is in pyproject.toml [tool.setuptools_scm]

if __name__ == "__main__":
    setup()
