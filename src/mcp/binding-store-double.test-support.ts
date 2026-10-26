import type { BackendHealth, ResolveOptions, WritableSecretBackend } from '../backends/types';

/**
 * A store held in memory, for cells that must never reach a real one: no
 * keychain, no network and no file. It is named as the backend it stands in
 * for. Each binding write it is asked for is recorded, refused or not, and
 * `refuse`, where set, is asked before each binding write: the error it
 * returns is thrown and nothing is stored.
 */
export class MemoryStore implements WritableSecretBackend {
  readonly entries = new Map<string, string>();
  /** The value of each binding write asked for, in order. */
  readonly bindingWrites: string[] = [];
  /** An error to refuse a binding write with, or undefined to take it. */
  refuse?: (key: string, value: string) => Error | undefined;

  constructor(readonly name = 'local') {}

  async resolve(at: string, options?: ResolveOptions): Promise<Record<string, string>> {
    const found: Record<string, string> = {};
    for (const [key, value] of this.entries) {
      if (key === at || (!options?.exact && key.startsWith(`${at}/`))) found[key] = value;
    }
    return found;
  }

  async healthCheck(): Promise<BackendHealth> {
    return { healthy: true, latencyMs: 0 };
  }

  async store(key: string, value: string): Promise<void> {
    if (key.startsWith('mcp-binding/')) {
      this.bindingWrites.push(value);
      const refused = this.refuse?.(key, value);
      if (refused !== undefined) throw refused;
    }
    this.entries.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.entries.delete(key);
  }
}
