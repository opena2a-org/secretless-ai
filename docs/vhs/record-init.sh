#!/usr/bin/env bash
# Renders docs/vhs/init.tape inside the recording container and writes the provenance sidecar.
#
#   docs/vhs/record-init.sh
#   DOCKER=<path to the docker binary> docs/vhs/record-init.sh
#   docs/vhs/record-init.sh --dry-run
#
# --dry-run prints the image, its base images, the build, the tape, the fixture, the files a
# render writes and the docker configuration, then exits 0. It runs npm view, git status, node
# and, when it would pack, git rev-parse: no docker, no build, no pack, and no file is written.
#
# The container (docs/vhs/docker/Dockerfile) carries VHS 0.12.0 with its encode regression patched,
# ffmpeg, ttyd, Chromium, JetBrains Mono, gifsicle, Node 22 and secretless-ai installed globally, so
# the typed `npx secretless-ai init` runs that build with no download on screen. The build is the
# published one when the version in package.json is on npm (the sidecar records npmIntegrity);
# when the registry answers that it is not (E404), it is `npm pack` of the committed tree at HEAD
# (the sidecar records packedFromCommit), built with the dependencies `npm ci` installed here. When
# npm view fails any other way, as when the registry cannot be reached, the script and its dry run
# stop with exit 1 and npm's error code. For either build the sidecar records commit, the commit
# HEAD names when the render starts; a packed build is packed from that commit.
#
# The hostname is `laptop`. The tape's hidden setup creates the fixture with setup-fixture.sh, a new
# project directory and a new empty home directory, and the tool runs in them. The image carries no
# OS credential store CLI, so the tool reaches no keychain. The container receives no variable of
# the calling environment other than the ones this script names. After the tape, the same container
# creates the fixture again, runs the typed commands once more with NO_COLOR=1 into init-capture.txt
# (the text version of the recording), optimises the GIF, and writes init.json. The MP4 goes to
# docs/vhs/out/, which is not committed.
#
# docker build and docker run use a configuration directory of this script's own, removed when the
# script ends, which names no credential helper and holds no registry credentials; the base images
# are public. The caller's docker configuration can name a helper,
# and Docker Desktop's helper keeps registry credentials in the OS keychain. The endpoint of the
# docker context in use is carried over as DOCKER_HOST, and the plugin directory of the caller's
# configuration as cliPluginsExtraDirs, so buildx is still found. A render ends with one line that
# names the sidecar's sha256, the version, meteredCostUsd and wallClockSeconds.
#
# Nothing metered is called: the script refuses to start with a model API key in its environment.
# A render over the budgets below writes no sidecar.
set -euo pipefail

TOOL="secretless-ai"
TAPE="docs/vhs/init.tape"
OUTPUTS="docs/vhs/init.gif docs/vhs/init-capture.txt docs/vhs/init.json docs/vhs/out/init.mp4"
FIXTURE_PROJECT="/work/project"
FIXTURE_HOME="/work/new-home"
MAX_WALL_CLOCK_SECONDS=60
MAX_GIF_BYTES=3000000
MAX_MP4_BYTES=1500000

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d" " -f1; else shasum -a 256 "$1" | cut -d" " -f1; fi
}

# The lines the tape types on screen: every Type line outside a Hide..Show block.
typed_commands() {
  node -e '
    let hidden = false;
    for (const line of require("fs").readFileSync(process.argv[1], "utf8").split("\n")) {
      if (/^Hide\b/.test(line)) hidden = true;
      else if (/^Show\b/.test(line)) hidden = false;
      else if (!hidden) {
        const typed = line.match(/^Type(?:@\S+)?\s+(["\x27`])(.*)\1\s*$/);
        if (typed) console.log(typed[2]);
      }
    }' "$1"
}

render_in_container() {
  cd /work
  if command -v security >/dev/null 2>&1 || command -v secret-tool >/dev/null 2>&1; then
    echo "record-init.sh: the image carries an OS credential store CLI; not recording." >&2
    exit 1
  fi
  if [ "$(sha256_of docs/vhs/setup-fixture.sh)" != "$FIXTURE_SHA" ]; then
    echo "record-init.sh: setup-fixture.sh changed after its hash was taken; not recording." >&2
    exit 1
  fi
  if [ "${FIXTURE_UNCOMMITTED_CHANGES:-}" != "0" ]; then
    echo "record-init.sh: FIXTURE_UNCOMMITTED_CHANGES is '${FIXTURE_UNCOMMITTED_CHANGES:-}', not the 0 that git status gives a committed setup-fixture.sh; not recording." >&2
    exit 1
  fi
  if ! [[ "${COMMIT:-}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "record-init.sh: COMMIT is '${COMMIT:-}', not the commit git rev-parse HEAD names on the host; not recording." >&2
    exit 1
  fi
  if ! grep -qF "setup-fixture.sh $FIXTURE_PROJECT $FIXTURE_HOME && cd $FIXTURE_PROJECT && export HOME=$FIXTURE_HOME" "$TAPE"; then
    echo "record-init.sh: the hidden setup of $TAPE does not create and enter $FIXTURE_PROJECT with HOME=$FIXTURE_HOME." >&2
    exit 1
  fi
  # A render that stops part way leaves no output and no sidecar from an earlier one.
  # shellcheck disable=SC2086
  rm -f $OUTPUTS
  mkdir -p docs/vhs/out

  RAN_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  STARTED_NS="$(date +%s%N)"
  vhs "$TAPE"
  WALL_CLOCK_TENTHS="$(( ($(date +%s%N) - STARTED_NS) / 100000000 ))"
  if [ ! -f "$FIXTURE_PROJECT/.claude/settings.json" ]; then
    echo "record-init.sh: the tape did not run init in $FIXTURE_PROJECT." >&2
    exit 1
  fi
  gifsicle -O3 --lossy=40 --batch docs/vhs/init.gif

  FRAMES_DIR="$(mktemp -d)"
  (cd "$FRAMES_DIR" && gifsicle --explode /work/docs/vhs/init.gif -o f >/dev/null 2>&1)
  FRAME_CENSUS="$(node docs/vhs/frame-census.mjs "$FRAMES_DIR")"
  rm -rf "$FRAMES_DIR"

  # The text version: the same commands, in the same fixture created again.
  COMMANDS="$(typed_commands "$TAPE")"
  rm -rf "$FIXTURE_PROJECT" "$FIXTURE_HOME"
  sh docs/vhs/setup-fixture.sh "$FIXTURE_PROJECT" "$FIXTURE_HOME"
  EXIT_CODES=""
  {
    while IFS= read -r typed; do
      if [ -n "$EXIT_CODES" ]; then echo; fi
      echo "\$ $typed"
      (cd "$FIXTURE_PROJECT" && HOME="$FIXTURE_HOME" NO_COLOR=1 bash -c "$typed" </dev/null) && code=0 || code=$?
      echo "[exit $code]"
      EXIT_CODES="${EXIT_CODES:+$EXIT_CODES,}$code"
    done <<< "$COMMANDS"
  } > docs/vhs/init-capture.txt 2>&1

  export RAN_AT WALL_CLOCK_TENTHS FRAME_CENSUS COMMANDS EXIT_CODES FIXTURE_PROJECT FIXTURE_HOME TAPE TOOL
  export MAX_WALL_CLOCK_SECONDS MAX_GIF_BYTES MAX_MP4_BYTES
  VERSION="$("$TOOL" --version | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)"
  VHS_VERSION="$(vhs --version 2>/dev/null | head -1 | sed "s/^vhs version //")"
  OS_NAME="$(. /etc/os-release && echo "$PRETTY_NAME")"
  GIF_PX="$(ffprobe -v error -select_streams v:0 -show_entries stream=width,height -of csv=p=0 docs/vhs/init.gif)"
  DURATION="$(ffprobe -v error -show_entries format=duration -of csv=p=0 docs/vhs/out/init.mp4)"
  export VERSION VHS_VERSION OS_NAME GIF_PX DURATION
  node - <<'NODE'
const fs = require("fs"), os = require("os"), crypto = require("crypto");
const env = process.env;
const sha = f => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
const size = f => fs.statSync(f).size;
const refuse = message => { console.error(`record-init.sh: ${message}; no sidecar written.`); process.exit(3); };

const tape = fs.readFileSync(env.TAPE, "utf8");
const setting = name => Number(tape.match(new RegExp(`^Set ${name} (\\d+)$`, "m"))[1]);
const census = JSON.parse(env.FRAME_CENSUS);
const [width, height] = env.GIF_PX.split(",").map(Number);
const gif = "docs/vhs/init.gif", mp4 = "docs/vhs/out/init.mp4", patch = "docs/vhs/docker/vhs-0.12.0-render-context.patch";
const wallClockSeconds = Number(env.WALL_CLOCK_TENTHS) / 10;

if (os.hostname() !== "laptop") refuse(`the hostname is ${os.hostname()}, not laptop`);
if (wallClockSeconds > Number(env.MAX_WALL_CLOCK_SECONDS)) refuse(`the render took ${wallClockSeconds} s, over the ${env.MAX_WALL_CLOCK_SECONDS} s budget`);
if (size(gif) > Number(env.MAX_GIF_BYTES)) refuse(`${gif} is ${size(gif)} bytes, over the ${env.MAX_GIF_BYTES} byte budget`);
if (size(mp4) > Number(env.MAX_MP4_BYTES)) refuse(`${mp4} is ${size(mp4)} bytes, over the ${env.MAX_MP4_BYTES} byte budget`);

const build = env.NPM_INTEGRITY
  ? { npmIntegrity: env.NPM_INTEGRITY }
  : { packedFromCommit: env.PACKED_FROM_COMMIT, packedTarballSha256: env.PACKED_TARBALL_SHA256 };
const out = {
  tape: env.TAPE,
  tapeSha256: sha(env.TAPE),
  commands: env.COMMANDS.split("\n"),
  tool: env.TOOL,
  version: env.VERSION,
  // The commit HEAD named on the host when the render started, whichever build the recording shows.
  commit: env.COMMIT,
  ...build,
  ranAtUtc: env.RAN_AT,
  fixture: "a new project directory holding an empty .claude/ directory, and a new empty home directory",
  fixtureScript: "docs/vhs/setup-fixture.sh",
  // The sha256 of the fixture script as the tape ran it; the render refuses a script that differs from it.
  fixtureSha: env.FIXTURE_SHA,
  // The number of lines `git status --porcelain` printed for the fixture script on the host, after its hash was taken.
  fixtureUncommittedChanges: Number(env.FIXTURE_UNCOMMITTED_CHANGES),
  fixturePath: env.FIXTURE_PROJECT,
  fixtureHome: env.FIXTURE_HOME,
  keychain: "none",
  hostname: os.hostname(),
  columns: setting("Columns"),
  rows: setting("Rows"),
  framerate: setting("Framerate"),
  gifsicle: "-O3 --lossy=40 --batch",
  gifFrames: census.frames,
  gifFullScreenFrames: census.fullScreenFrames,
  gifScrollInSpan: census.scrollInSpan,
  renderedPixelSize: { width, height },
  outputs: {
    gif: { path: gif, bytes: size(gif) },
    mp4: { path: mp4, bytes: size(mp4), sha256: sha(mp4), committed: false },
    frames: [],
    capture: "docs/vhs/init-capture.txt"
  },
  durationSeconds: Number(Number(env.DURATION).toFixed(1)),
  wallClockSeconds,
  meteredCostUsd: 0,
  exitCodes: env.EXIT_CODES.split(",").map(Number),
  frames: {},
  vhsPatchSha256: sha(patch),
  edits: ["setup not shown"],
  environment: {
    container: `docs/vhs/docker/Dockerfile (${env.OS_NAME}, Node ${process.versions.node}, ${env.TOOL} installed globally)`,
    vhs: { version: env.VHS_VERSION, patch, patchSha256: sha(patch) },
    telemetry: "off"
  }
};
fs.writeFileSync("docs/vhs/init.json", JSON.stringify(out, null, 2) + "\n");
NODE
}

if [ "${1:-}" = "--in-container" ]; then
  render_in_container
  exit 0
fi

if [ -n "${ANTHROPIC_API_KEY+set}" ] || [ -n "${OPENAI_API_KEY+set}" ]; then
  echo "record-init.sh: ANTHROPIC_API_KEY or OPENAI_API_KEY is set; a recording runs with no model API key in its environment. Unset it and run again." >&2
  exit 2
fi

DRY_RUN=0
case "$#:${1:-}" in
  0:) ;;
  1:--dry-run) DRY_RUN=1 ;;
  *)
    echo "usage: docs/vhs/record-init.sh [--dry-run]" >&2
    exit 1
    ;;
esac

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# The tape runs the fixture script from the working tree. Its hash is taken first and git's count of
# uncommitted changes to it second, so an edit made between the two is counted, and the container
# refuses a script that no longer matches the hash. A render with any uncommitted change is refused.
FIXTURE_SCRIPT="docs/vhs/setup-fixture.sh"
FIXTURE_SHA="$(sha256_of "$REPO_ROOT/$FIXTURE_SCRIPT")"
FIXTURE_STATUS="$(git -C "$REPO_ROOT" status --porcelain -- "$FIXTURE_SCRIPT")"
FIXTURE_UNCOMMITTED_CHANGES="$(printf '%s' "$FIXTURE_STATUS" | grep -c . || true)"
if [ "$FIXTURE_UNCOMMITTED_CHANGES" != "0" ]; then
  echo "record-init.sh: git status reports uncommitted changes to $FIXTURE_SCRIPT ($FIXTURE_STATUS); commit them and run again." >&2
  exit 1
fi

DOCKER="${DOCKER:-docker}"
VERSION="$(node -p "require(process.argv[1]).version" "$REPO_ROOT/package.json")"
IMAGE="${SECRETLESS_VHS_IMAGE:-secretless-vhs:$VERSION}"

# npm answers a published version with its integrity and an unpublished one with error code E404.
# Any other answer, such as a registry npm cannot reach, leaves that unknown, and the script stops
# rather than pack HEAD under a version that may be published.
NPM_VIEW_STATUS=0
NPM_VIEW="$(npm view "$TOOL@$VERSION" dist.integrity --json 2>/dev/null)" || NPM_VIEW_STATUS=$?
# shellcheck disable=SC2016
NPM_INTEGRITY="$(node -e '
  const [status, output, spec] = process.argv.slice(1);
  let answer;
  try { answer = JSON.parse(output); } catch {}
  if (status === "0" && typeof answer === "string" && answer) console.log(answer);
  else if (status !== "0" && answer?.error?.code === "E404") console.log("");
  else {
    const error = answer?.error ? `${answer.error.code}: ${answer.error.summary}`
      : status === "0" ? "exit 0 with no integrity in its output" : `exit ${status} with no error code in its output`;
    console.error(`record-init.sh: npm view ${spec} failed (${error}), so it is not known whether ${spec} is published. Nothing was built or packed; resolve the npm error and run again.`);
    process.exit(1);
  }' "$NPM_VIEW_STATUS" "$NPM_VIEW" "$TOOL@$VERSION")" || exit 1
if [ -z "$NPM_INTEGRITY" ] && [ ! -d "$REPO_ROOT/node_modules" ]; then
  echo "record-init.sh: $TOOL@$VERSION is not on npm and node_modules is missing; run npm ci first." >&2
  exit 1
fi

if [ "$DRY_RUN" = 1 ]; then
  if [ -n "$NPM_INTEGRITY" ]; then
    BUILD="$TOOL@$VERSION from npm ($NPM_INTEGRITY)"
  else
    BUILD="npm pack of commit $(git -C "$REPO_ROOT" rev-parse HEAD) ($TOOL@$VERSION is not on npm)"
  fi
  echo "record-init.sh --dry-run: runs npm view, git status, node and, when it would pack, git rev-parse; no docker, no build, no pack, and no file is written."
  echo "  image     $IMAGE, built with $DOCKER from docs/vhs/docker/Dockerfile"
  echo "  bases     $(sed -n -E 's/^FROM ([^ ]+).*/\1/p' "$REPO_ROOT/docs/vhs/docker/Dockerfile" | paste -s -d ' ' -)"
  echo "  build     $BUILD"
  echo "  tape      $TAPE"
  echo "  fixture   docs/vhs/setup-fixture.sh"
  echo "  writes    $OUTPUTS"
  echo "  docker    a configuration of the script's own, with no credential helper and no registry credentials"
  exit 0
fi

CONTEXT="$(mktemp -d)"
OWN_DOCKER_CONFIG="$(mktemp -d)"
cleanup_context() { rm -rf "$CONTEXT" "$OWN_DOCKER_CONFIG"; }
trap cleanup_context EXIT
cp "$REPO_ROOT/docs/vhs/docker/Dockerfile" "$REPO_ROOT/docs/vhs/docker/vhs-0.12.0-render-context.patch" "$CONTEXT/"

# The docker configuration of this script's own (see the header). The endpoint and the plugin
# directory are read with the caller's configuration, before it is replaced.
CALLER_PLUGINS="${DOCKER_CONFIG:-$HOME/.docker}/cli-plugins"
if [ -z "${DOCKER_HOST:-}" ]; then
  DOCKER_HOST="$("$DOCKER" context inspect --format '{{.Endpoints.docker.Host}}')" || DOCKER_HOST=""
  if [ -z "$DOCKER_HOST" ]; then
    echo "record-init.sh: $DOCKER context inspect named no endpoint for the docker context in use; set DOCKER_HOST and run again." >&2
    exit 1
  fi
fi
node -e 'require("fs").writeFileSync(process.argv[1], JSON.stringify({ cliPluginsExtraDirs: [process.argv[2]] }, null, 2) + "\n")' \
  "$OWN_DOCKER_CONFIG/config.json" "$CALLER_PLUGINS"
export DOCKER_HOST
export DOCKER_CONFIG="$OWN_DOCKER_CONFIG"

# The sidecar names this commit for either build; a packed build is packed from it.
COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
TARBALL=""
PACKED_FROM_COMMIT=""
PACKED_TARBALL_SHA256=""
if [ -z "$NPM_INTEGRITY" ]; then
  # Not on npm: pack the committed tree, so an edit not yet committed is never in the recorded build.
  PACKED_FROM_COMMIT="$COMMIT"
  mkdir "$CONTEXT/tree"
  git -C "$REPO_ROOT" archive "$COMMIT" | tar -x -C "$CONTEXT/tree"
  ln -s "$REPO_ROOT/node_modules" "$CONTEXT/tree/node_modules"
  (cd "$CONTEXT/tree" && npm run build >/dev/null && npm pack --pack-destination "$CONTEXT" >/dev/null 2>&1)
  rm -rf "$CONTEXT/tree"
  TARBALL="$TOOL-$VERSION.tgz"
  PACKED_TARBALL_SHA256="$(sha256_of "$CONTEXT/$TARBALL")"
fi

"$DOCKER" build -t "$IMAGE" \
  --build-arg TOOL="$TOOL" --build-arg VERSION="$VERSION" --build-arg TARBALL="$TARBALL" "$CONTEXT"
"$DOCKER" run --rm --hostname laptop --shm-size=1g \
  -e FIXTURE_SHA="$FIXTURE_SHA" \
  -e FIXTURE_UNCOMMITTED_CHANGES="$FIXTURE_UNCOMMITTED_CHANGES" \
  -e COMMIT="$COMMIT" \
  -e NPM_INTEGRITY="$NPM_INTEGRITY" \
  -e PACKED_FROM_COMMIT="$PACKED_FROM_COMMIT" \
  -e PACKED_TARBALL_SHA256="$PACKED_TARBALL_SHA256" \
  -v "$REPO_ROOT/docs/vhs":/work/docs/vhs \
  --entrypoint bash "$IMAGE" docs/vhs/record-init.sh --in-container
echo "rendered: $(cd "$REPO_ROOT" && ls -la docs/vhs/init.* docs/vhs/out/init.mp4 | awk '{print $5, $9}' | tr '\n' ';')"

# The line a release record or a task log keeps: which sidecar this render wrote, by its hash.
SIDECAR="$REPO_ROOT/docs/vhs/init.json"
if [ ! -f "$SIDECAR" ]; then
  echo "record-init.sh: the render wrote no docs/vhs/init.json." >&2
  exit 1
fi
# shellcheck disable=SC2016
node -e '
  const [file, digest] = process.argv.slice(1);
  const s = JSON.parse(require("fs").readFileSync(file, "utf8"));
  console.log(`sidecar: docs/vhs/init.json sha256 ${digest}, version ${s.version}, meteredCostUsd ${s.meteredCostUsd}, wallClockSeconds ${s.wallClockSeconds}`);
' "$SIDECAR" "$(sha256_of "$SIDECAR")"
