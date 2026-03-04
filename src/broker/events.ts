/**
 * Structured credential events — typed audit trail for AIM integration.
 *
 * Extends the existing audit logger with strongly-typed credential lifecycle
 * events. These events can be emitted to AIM's audit endpoint for centralized
 * visibility into credential usage across all agents.
 *
 * Event types follow the credential lifecycle:
 *   requested -> granted | denied
 *   granted -> expired | revoked
 *   (any time) -> leak_detected | rotated
 */

import * as http from 'http';
import * as https from 'https';
import { AuditLogger } from './audit';

/** Credential event types covering the full lifecycle. */
export type CredentialEventType =
  | 'credential.requested'
  | 'credential.granted'
  | 'credential.denied'
  | 'credential.expired'
  | 'credential.revoked'
  | 'credential.rotated'
  | 'credential.leak_detected';

/** Alert severity levels. */
export type AlertLevel = 'info' | 'warning' | 'critical';

/** Structured credential event for AIM audit trail. */
export interface CredentialEvent {
  /** Event type. */
  type: CredentialEventType;
  /** ISO 8601 timestamp. */
  timestamp: string;
  /** Agent that triggered the event. */
  agentId: string;
  /** Secret reference (URI or name, never the actual value). */
  secretRef: string;
  /** AIM trust score at the time of the event (0.0 to 1.0). */
  trustScore?: number;
  /** TTL in seconds for granted credentials. */
  ttlSeconds?: number;
  /** Reason for the decision (denial reason, expiry reason, etc.). */
  reason?: string;
  /** Alert level for events that need attention. */
  alertLevel?: AlertLevel;
  /** Policy rule that matched (if any). */
  policyRuleId?: string;
  /** Capability that was requested or exercised. */
  capability?: string;
  /** Backend that was used (keychain, vault, etc.). */
  backend?: string;
  /** Event version for forward compatibility. */
  version: 1;
}

/**
 * Credential event emitter — writes structured events to audit log
 * and optionally forwards them to AIM.
 */
export class CredentialEventEmitter {
  private readonly auditLogger: AuditLogger;
  private readonly aimAuditUrl: string | null;

  constructor(auditLogger: AuditLogger, aimAuditUrl?: string) {
    this.auditLogger = auditLogger;
    this.aimAuditUrl = aimAuditUrl ?? null;
  }

  /** Emit a credential requested event. */
  emitRequested(
    agentId: string,
    secretRef: string,
    capability?: string,
  ): void {
    this.emit({
      type: 'credential.requested',
      timestamp: new Date().toISOString(),
      agentId,
      secretRef,
      capability,
      alertLevel: 'info',
      version: 1,
    });
  }

  /** Emit a credential granted event. */
  emitGranted(
    agentId: string,
    secretRef: string,
    options: {
      trustScore?: number;
      ttlSeconds?: number;
      policyRuleId?: string;
      backend?: string;
    },
  ): void {
    this.emit({
      type: 'credential.granted',
      timestamp: new Date().toISOString(),
      agentId,
      secretRef,
      trustScore: options.trustScore,
      ttlSeconds: options.ttlSeconds,
      policyRuleId: options.policyRuleId,
      backend: options.backend,
      alertLevel: 'info',
      version: 1,
    });
  }

  /** Emit a credential denied event. */
  emitDenied(
    agentId: string,
    secretRef: string,
    reason: string,
    options?: {
      trustScore?: number;
      policyRuleId?: string;
      alertLevel?: AlertLevel;
    },
  ): void {
    this.emit({
      type: 'credential.denied',
      timestamp: new Date().toISOString(),
      agentId,
      secretRef,
      reason,
      trustScore: options?.trustScore,
      policyRuleId: options?.policyRuleId,
      alertLevel: options?.alertLevel ?? 'warning',
      version: 1,
    });
  }

  /** Emit a credential expired event. */
  emitExpired(
    agentId: string,
    secretRef: string,
    wasUsed: boolean,
  ): void {
    this.emit({
      type: 'credential.expired',
      timestamp: new Date().toISOString(),
      agentId,
      secretRef,
      reason: wasUsed ? 'TTL expired after use' : 'TTL expired (unused)',
      alertLevel: wasUsed ? 'info' : 'warning',
      version: 1,
    });
  }

  /** Emit a credential revoked event. */
  emitRevoked(
    agentId: string,
    secretRef: string,
    reason: string,
  ): void {
    this.emit({
      type: 'credential.revoked',
      timestamp: new Date().toISOString(),
      agentId,
      secretRef,
      reason,
      alertLevel: 'warning',
      version: 1,
    });
  }

  /** Emit a credential leak detected event. */
  emitLeakDetected(
    agentId: string,
    secretRef: string,
    leakContext: string,
  ): void {
    this.emit({
      type: 'credential.leak_detected',
      timestamp: new Date().toISOString(),
      agentId,
      secretRef,
      reason: leakContext,
      alertLevel: 'critical',
      version: 1,
    });
  }

  /** Emit a credential rotated event. */
  emitRotated(
    secretRef: string,
    trigger: string,
  ): void {
    this.emit({
      type: 'credential.rotated',
      timestamp: new Date().toISOString(),
      agentId: 'system',
      secretRef,
      reason: trigger,
      alertLevel: 'info',
      version: 1,
    });
  }

  /**
   * Core emit: write to local audit log + forward to AIM.
   */
  private emit(event: CredentialEvent): void {
    // Write to local audit log (always)
    this.auditLogger.logEvent(
      event.type,
      event.agentId,
      event.secretRef,
      event.policyRuleId ?? '',
      event.type.includes('denied') || event.type.includes('revoked') || event.type.includes('leak')
        ? 'denied'
        : 'allowed',
      event.reason ?? '',
      0,
    );

    // Forward to AIM (best-effort, fire-and-forget)
    if (this.aimAuditUrl) {
      this.forwardToAim(event).catch(() => {
        // Silently ignore AIM forwarding failures
      });
    }
  }

  /**
   * Forward an event to AIM's audit endpoint.
   * Non-blocking, fire-and-forget. Failure is never visible to the caller.
   */
  private forwardToAim(event: CredentialEvent): Promise<void> {
    return new Promise((resolve) => {
      if (!this.aimAuditUrl) { resolve(); return; }

      try {
        const url = new URL(this.aimAuditUrl);
        const transport = url.protocol === 'https:' ? https : http;
        const body = JSON.stringify(event);

        const req = transport.request(
          {
            hostname: url.hostname,
            port: url.port,
            path: url.pathname,
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(body),
            },
            timeout: 3000, // 3s timeout — don't block on AIM
          },
          (res) => {
            res.resume(); // Drain response
            resolve();
          },
        );

        req.on('error', () => resolve());
        req.on('timeout', () => { req.destroy(); resolve(); });
        req.write(body);
        req.end();
      } catch {
        resolve();
      }
    });
  }
}
