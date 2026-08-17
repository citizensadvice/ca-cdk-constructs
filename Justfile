# Show the list of available commands
@help:
    just --list

# Run mypy type checker
[group("code quality")]
mypy +files='.':
    uv run mypy {{ files }}

# Run pytest tests
[group("code quality")]
pytest *files:
    uv run pytest {{ files }}

# Check code quality using Ruff
[group("code quality")]
lint *files:
    uv run ruff check {{ files }}
    uv run ruff format --check {{ files }}

# Run all tests: typechecking, pytest, and linting
[group("code quality")]
all-tests: lint mypy pytest

# Autoformat and fix code with ruff
[group("code quality")]
format *files:
    uv run ruff format {{ files }}
    uv run ruff check --fix {{ files }}
    just --fmt --unstable

# Update the cdk8s imports
[group("updates")]
import-cdk8s:
    cdk8s import --output ca_cdk_constructs/eks/imports

# Bump version, push and create draft release
[confirm("Are you sure you want to draft a release? [y/N]")]
[group("release")]
draft-release bump='patch': (_bump_version bump) _push_version _create_draft_release

_bump_version bump:
    git checkout main
    git pull origin main
    git reset
    uv version --bump {{ bump }}
    git add pyproject.toml uv.lock

[confirm("Are you sure you want to push the version change? [y/N]")]
_push_version:
    git commit -m "Bumped version to v$(uv version --short)"
    git push origin main

_create_draft_release:
    gh release create v$(uv version --short) --draft --generate-notes
    echo "> Follow the link to review and publish the release"

# CI-only: Get the current version
[group("release")]
get-version:
    @uv version --short

# CI-only: Configure git for automated commits
[group("release")]
ci-configure-git:
    git config user.name "github-actions[bot]"
    git config user.email "github-actions[bot]@users.noreply.github.com"

# CI-only: Create and checkout release branch
[group("release")]
ci-create-release-branch:
    #!/usr/bin/env bash
    branch_name="automated-release-$(date +%Y%m%d)"
    git checkout -b "$branch_name"
    echo "$branch_name"
