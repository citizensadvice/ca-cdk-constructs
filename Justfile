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

# CI-only: Check if main dependencies have changed since a git ref (e.g., tag)
# Outputs "true" if dependencies changed, "false" if no changes. Always exits 0.
[group("release")]
ci-check-deps-changed ref:
    #!/usr/bin/env bash
    set -euo pipefail

    # Create a temporary directory and ensure cleanup
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    # Extract [project.dependencies] section from the ref version
    git show "{{ ref }}:pyproject.toml" > "$tmpdir/pyproject.old.toml" || exit 1
    # Extract the dependencies array (everything between 'dependencies = [' and the closing ']')
    awk '/^dependencies = \[/,/^\]/' "$tmpdir/pyproject.old.toml" | sort > "$tmpdir/deps.old"

    # Extract [project.dependencies] section from current HEAD
    awk '/^dependencies = \[/,/^\]/' pyproject.toml | sort > "$tmpdir/deps.new"

    # Compare the dependency constraint lists
    if ! diff -q "$tmpdir/deps.old" "$tmpdir/deps.new" > /dev/null 2>&1; then
        echo "Dependency constraints have changed since {{ ref }}:" >&2
        diff "$tmpdir/deps.old" "$tmpdir/deps.new" >&2 || true
        echo "true"
    else
        echo "No changes to dependency constraints since {{ ref }}" >&2
        echo "false"
    fi

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

# CI-only: Bump version and commit (for automated workflows)
[group("release")]
ci-bump-and-commit bump='patch':
    uv version --bump {{ bump }}
    git add pyproject.toml uv.lock
    git commit -m "Bumped version to v$(uv version --short)"

# CI-only: Push current branch to origin
[group("release")]
ci-push-branch branch:
    git push origin {{ branch }}

# CI-only: Create PR for version bump
[group("release")]
ci-create-pr version branch:
    #!/usr/bin/env bash
    gh pr create \
      --title "Release v{{ version }}" \
      --body "Automated release bump to version v{{ version }}

    This PR includes dependency updates from dependabot that have been merged since the last release.

    **Next steps:**
    1. Review and merge this PR
    2. A draft release will be automatically created
    3. Review and publish the draft release" \
      --base main \
      --head {{ branch }}

# CI-only: Create draft release for a version
[group("release")]
ci-create-draft-release version:
    gh release create v{{ version }} --draft --generate-notes --title "v{{ version }}" --notes "Automated release - please review and publish"
