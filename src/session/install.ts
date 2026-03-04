/**
 * Install command — set up Secretless as a launchd daemon on macOS.
 *
 * Creates a LaunchAgent plist that starts the broker daemon on login.
 * On non-macOS platforms, provides instructions for equivalent setup.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';

const LAUNCH_AGENTS_DIR = path.join(os.homedir(), 'Library', 'LaunchAgents');
const PLIST_LABEL = 'com.opena2a.secretless';
const PLIST_FILENAME = `${PLIST_LABEL}.plist`;
const SECRETLESS_DIR = path.join(os.homedir(), '.secretless-ai');

export interface InstallResult {
  /** Whether the installation succeeded. */
  installed: boolean;
  /** Path to the installed plist file (macOS) or empty string. */
  plistPath: string;
  /** Whether the daemon was loaded (started). */
  loaded: boolean;
  /** Human-readable message about the installation. */
  message: string;
  /** Platform that was detected. */
  platform: string;
}

export interface UninstallResult {
  /** Whether the uninstallation succeeded. */
  removed: boolean;
  /** Human-readable message about the uninstallation. */
  message: string;
}

/**
 * Find the path to the secretless-ai CLI entry point.
 * Searches common locations in order of preference.
 */
function findCliPath(): string | null {
  // Check if we're running from a global install
  const candidates = [
    // npm global install
    path.join(path.dirname(process.execPath), 'secretless-ai'),
    // npx / local node_modules
    path.resolve(__dirname, '..', 'cli.js'),
    // Compiled dist
    path.resolve(__dirname, '..', '..', 'dist', 'cli.js'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return null;
}

/**
 * Generate the launchd plist XML content.
 */
function generatePlist(cliPath: string): string {
  // Determine how to invoke the CLI
  const isJsFile = cliPath.endsWith('.js');
  const programArgs = isJsFile
    ? [process.execPath, cliPath, 'broker', 'start']
    : [cliPath, 'broker', 'start'];

  const argsXml = programArgs
    .map(arg => `      <string>${escapeXml(arg)}</string>`)
    .join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${PLIST_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${argsXml}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>${escapeXml(path.join(SECRETLESS_DIR, 'broker.log'))}</string>
  <key>StandardErrorPath</key>
  <string>${escapeXml(path.join(SECRETLESS_DIR, 'broker.error.log'))}</string>
  <key>WorkingDirectory</key>
  <string>${escapeXml(os.homedir())}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin</string>
  </dict>
</dict>
</plist>`;
}

/**
 * Install the Secretless broker as a macOS LaunchAgent.
 */
export function installDaemon(): InstallResult {
  const platform = os.platform();

  if (platform !== 'darwin') {
    return {
      installed: false,
      plistPath: '',
      loaded: false,
      message: `Automatic daemon install is only supported on macOS. On ${platform}, run "secretless-ai broker start" manually or add it to your init system.`,
      platform,
    };
  }

  // Find CLI path
  const cliPath = findCliPath();
  if (!cliPath) {
    return {
      installed: false,
      plistPath: '',
      loaded: false,
      message: 'Could not find secretless-ai CLI. Install globally first: npm install -g secretless-ai',
      platform,
    };
  }

  // Ensure directories exist
  fs.mkdirSync(SECRETLESS_DIR, { recursive: true, mode: 0o700 });
  fs.mkdirSync(LAUNCH_AGENTS_DIR, { recursive: true });

  // Generate and write plist
  const plistPath = path.join(LAUNCH_AGENTS_DIR, PLIST_FILENAME);
  const plistContent = generatePlist(cliPath);
  fs.writeFileSync(plistPath, plistContent, { mode: 0o644 });

  // Load the launch agent
  let loaded = false;
  try {
    // Unload first if already loaded (idempotent)
    try {
      execSync(`launchctl unload "${plistPath}" 2>/dev/null`, {
        timeout: 5000,
        stdio: 'pipe',
      });
    } catch {
      // Not previously loaded — fine
    }

    execSync(`launchctl load "${plistPath}"`, {
      timeout: 5000,
      stdio: 'pipe',
    });
    loaded = true;
  } catch {
    // Load failed — plist is installed but not active
  }

  return {
    installed: true,
    plistPath,
    loaded,
    message: loaded
      ? `Broker daemon installed and started. Plist: ${plistPath}`
      : `Broker daemon installed but could not be started. Load manually: launchctl load "${plistPath}"`,
    platform,
  };
}

/**
 * Uninstall the Secretless broker LaunchAgent.
 */
export function uninstallDaemon(): UninstallResult {
  if (os.platform() !== 'darwin') {
    return {
      removed: false,
      message: 'Automatic daemon uninstall is only supported on macOS.',
    };
  }

  const plistPath = path.join(LAUNCH_AGENTS_DIR, PLIST_FILENAME);

  if (!fs.existsSync(plistPath)) {
    return {
      removed: false,
      message: 'Broker daemon is not installed (no plist found).',
    };
  }

  // Unload the agent
  try {
    execSync(`launchctl unload "${plistPath}" 2>/dev/null`, {
      timeout: 5000,
      stdio: 'pipe',
    });
  } catch {
    // May not be loaded — fine
  }

  // Remove the plist file
  try {
    fs.unlinkSync(plistPath);
  } catch {
    return {
      removed: false,
      message: `Could not remove plist at ${plistPath}. Remove manually.`,
    };
  }

  return {
    removed: true,
    message: 'Broker daemon uninstalled.',
  };
}

/**
 * Check if the daemon is installed as a LaunchAgent.
 */
export function isDaemonInstalled(): boolean {
  if (os.platform() !== 'darwin') return false;
  const plistPath = path.join(LAUNCH_AGENTS_DIR, PLIST_FILENAME);
  return fs.existsSync(plistPath);
}

/** Escape XML special characters. */
function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}
