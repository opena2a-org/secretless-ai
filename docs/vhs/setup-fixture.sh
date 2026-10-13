#!/bin/sh
# The fixture of the recorded walkthrough: a new project directory holding an empty .claude/
# directory, and a new empty home directory. Nothing else is created.
#
#   sh docs/vhs/setup-fixture.sh <project-dir> <home-dir>
#
# Both directories must not exist yet: mkdir without -p refuses one that does, so a recording
# never starts from a directory an earlier run already set up.
set -eu
PROJECT="${1:?project directory to create}"
NEW_HOME="${2:?home directory to create}"
mkdir "$PROJECT" "$PROJECT/.claude" "$NEW_HOME"
