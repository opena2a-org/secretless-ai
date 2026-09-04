export {
  readSessionState,
  writeSessionState,
  getSessionStatus,
  isSessionWarm,
  clearSessionState,
  getSessionFilePath,
  SESSION_TAMPERED,
  DEFAULT_SESSION_TTL_SECONDS,
  MAX_SESSION_TTL_SECONDS,
  type SessionState,
  type SessionStatus,
} from './session-state';

export {
  warmSession,
  isMacOS,
  isTouchIDAvailable,
} from './touchid';

export {
  warm,
  preloadCache,
  type WarmResult,
} from './warm';

export {
  installDaemon,
  uninstallDaemon,
  isDaemonInstalled,
  type InstallResult,
  type UninstallResult,
} from './install';

export {
  hookCheck,
  runHookCheck,
  type HookCheckResult,
} from './hook';
