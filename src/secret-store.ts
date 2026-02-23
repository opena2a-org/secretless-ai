/**
 * Secret store — CRUD operations for user-managed secrets.
 *
 * Stores secrets with key prefix `secret/` to separate them from MCP secrets
 * (`mcp/` prefix). Uses the same pluggable backend infrastructure (local
 * encrypted file or OS keychain).
 */

import { createBackend } from './backends/factory';
import { resolveBackendType } from './backends/config';
import type { WritableSecretBackend } from './backends/types';
import type { SelectableBackendType } from './backends/config';

const SECRET_PREFIX = 'secret';

/** Validates secret names: alphanumeric, dash, underscore only. */
const SAFE_NAME = /^[a-zA-Z0-9_-]+$/;

export interface SecretStoreOptions {
  /** Backend type to use. Resolved from config if not provided. */
  backendType?: SelectableBackendType;
  /** Pre-constructed backend instance (overrides backendType). For DI/testing. */
  backend?: WritableSecretBackend;
}

export class SecretStore {
  private readonly backend: WritableSecretBackend;

  constructor(options?: SecretStoreOptions) {
    if (options?.backend) {
      this.backend = options.backend;
      return;
    }

    const backendType = resolveBackendType(options?.backendType);
    this.backend = createBackend(backendType);
  }

  /** Store a secret by name. */
  async setSecret(name: string, value: string): Promise<void> {
    validateSecretName(name);
    const key = `${SECRET_PREFIX}/${name}`;
    await this.backend.store(key, value);
  }

  /** Retrieve a secret value by name. Returns undefined if not found. */
  async getSecret(name: string): Promise<string | undefined> {
    validateSecretName(name);
    const key = `${SECRET_PREFIX}/${name}`;
    const result = await this.backend.resolve(key);
    return result[key];
  }

  /** List all stored secret names (no values). */
  async listSecrets(): Promise<string[]> {
    const all = await this.backend.resolve(SECRET_PREFIX);
    const names: string[] = [];
    for (const fullKey of Object.keys(all)) {
      // Keys are in format: secret/{name}
      const name = fullKey.slice(SECRET_PREFIX.length + 1);
      if (name) {
        names.push(name);
      }
    }
    return names.sort();
  }

  /** Remove a secret by name. Returns true if the secret existed. */
  async removeSecret(name: string): Promise<boolean> {
    validateSecretName(name);
    const key = `${SECRET_PREFIX}/${name}`;
    return this.backend.delete(key);
  }

  /** Load all secrets as key-value pairs. Optionally filter by name list. */
  async loadSecrets(only?: string[]): Promise<Record<string, string>> {
    const all = await this.backend.resolve(SECRET_PREFIX);
    const result: Record<string, string> = {};

    for (const [fullKey, value] of Object.entries(all)) {
      const name = fullKey.slice(SECRET_PREFIX.length + 1);
      if (!name) continue;
      if (only && !only.includes(name)) continue;
      result[name] = value;
    }
    return result;
  }
}

function validateSecretName(name: string): void {
  if (!SAFE_NAME.test(name)) {
    throw new Error(
      `Invalid secret name: "${name}". Only alphanumeric, dash, and underscore allowed.`,
    );
  }
}
