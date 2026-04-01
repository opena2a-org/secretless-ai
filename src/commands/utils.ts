// eslint-disable-next-line @typescript-eslint/no-var-requires
export const VERSION: string = require('../../package.json').version;

/** Format seconds into a human-readable uptime string. */
export function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const secs = seconds % 60;
  if (minutes < 60) return `${minutes}m ${secs}s`;
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  if (hours < 24) return `${hours}h ${mins}m`;
  const days = Math.floor(hours / 24);
  const hrs = hours % 24;
  return `${days}d ${hrs}h`;
}

export function formatRemainingTime(seconds: number): string {
  if (seconds <= 0) return 'expired';
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}
