/**
 * Structured credential events — typed audit trail for AIM integration.
 *
 * Extends the existing audit logger with strongly-typed credential lifecycle
 * events. The record each event writes can also be sent to AIM's audit
 * endpoint for centralized visibility into credential usage across all agents.
 *
 * Event types follow the credential lifecycle:
 *   requested -> granted | denied
 *   granted -> expired | revoked
 *   (any time) -> leak_detected | rotated
 */

import * as http from 'http';
import * as https from 'https';
import { AuditLogger } from './audit';
import { parsedAgentId, unparsed } from './parsed-form';
import type { AuditEntry, AuditReason } from './types';

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

/** The names an emitter's records may write as sent. */
export interface CredentialEventAnchor {
  /** Secret references written as sent. */
  credentialNames?: Iterable<string>;
  /** Policy rule ids written as sent. */
  policyRuleIds?: Iterable<string>;
}

/** The record's code for each event type but `credential.expired`, which is coded by use. */
const EVENT_CODES: Record<Exclude<CredentialEventType, 'credential.expired'>, AuditReason> = {
  'credential.requested': 'credential-requested',
  'credential.granted': 'credential-granted',
  'credential.denied': 'credential-denied',
  'credential.revoked': 'credential-revoked',
  'credential.rotated': 'credential-rotated',
  'credential.leak_detected': 'credential-leak-detected',
};

/** The reason `emitExpired` sets for a credential that was used before it expired. */
const EXPIRED_AFTER_USE = 'TTL expired after use';

/** The record's code for an event: by its type, and for an expiry by whether it was used. */
function eventCode(event: CredentialEvent): AuditReason {
  if (event.type === 'credential.expired') {
    return event.reason === EXPIRED_AFTER_USE ? 'credential-expired-after-use' : 'credential-expired-unused';
  }
  return EVENT_CODES[event.type];
}

/**
 * Credential event emitter — writes a signed audit record for each event,
 * and optionally sends that record to AIM.
 */
export class CredentialEventEmitter {
  private readonly auditLogger: AuditLogger;
  private readonly aimAuditUrl: string | null;
  private readonly aimAuthHeader: string | null;
  private readonly credentialNames: ReadonlySet<string>;
  private readonly policyRuleIds: ReadonlySet<string>;

  /**
   * Each event's record carries the code of its type, never the caller's reason, leak context or
   * trigger. Its agent id is written as sent only when it is at most 128 bytes and parses as a DID
   * or as an agent name. Its secret reference is written as sent only when `anchor.credentialNames`
   * lists it, and its policy rule id only when `anchor.policyRuleIds` lists it. Any other value is
   * written as the marker `unparsed:<length>`, its length in UTF-8 bytes; an absent policy rule id
   * is written empty. With no anchor, every secret reference and every policy rule id is a marker.
   *
   * @param auditLogger The signed audit log each event is written to.
   * @param aimAuditUrl AIM's audit endpoint. When set, the record written for each event, and
   *   nothing else, is posted there.
   * @param anchor The secret references and policy rule ids the records may write as sent.
   */
  constructor(auditLogger: AuditLogger, aimAuditUrl?: string, anchor?: CredentialEventAnchor) {
    this.auditLogger = auditLogger;
    this.aimAuditUrl = aimAuditUrl ?? null;
    this.credentialNames = new Set(anchor?.credentialNames ?? []);
    this.policyRuleIds = new Set(anchor?.policyRuleIds ?? []);
    // Read AIM API key from environment for authenticated event forwarding
    const aimApiKey = process.env.AIM_API_KEY;
    this.aimAuthHeader = aimApiKey ? `Bearer ${aimApiKey}` : null;
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
   * Core emit: write the event's record to the local audit log, then send that record to AIM.
   */
  private emit(event: CredentialEvent): void {
    // The written forms, computed once before the chain write: the code of the event type, and
    // each member as sent only in parsed form, otherwise the marker.
    const agentId = parsedAgentId(event.agentId);
    const credentialName = this.credentialNames.has(event.secretRef) ? event.secretRef : unparsed(event.secretRef);
    const ruleId = event.policyRuleId;
    const policyId = ruleId === undefined || ruleId === '' ? '' : this.policyRuleIds.has(ruleId) ? ruleId : unparsed(ruleId);
    const result = event.type.includes('denied') || event.type.includes('revoked') || event.type.includes('leak')
      ? 'denied'
      : 'allowed';
    const reason = eventCode(event);

    // Write to local audit log (always)
    const written = this.auditLogger.logEvent(event.type, agentId, credentialName, policyId, result, reason, 0);

    // Send the written record to AIM, and nothing else (best-effort, fire-and-forget)
    if (this.aimAuditUrl && written) {
      this.forwardToAim(written).catch(() => {
        // Silently ignore AIM forwarding failures
      });
    }
  }

  /**
   * Send a written record to AIM's audit endpoint.
   * Non-blocking, fire-and-forget. Failure is never visible to the caller.
   */
  private forwardToAim(record: AuditEntry): Promise<void> {
    return new Promise((resolve) => {
      if (!this.aimAuditUrl) { resolve(); return; }

      try {
        const url = new URL(this.aimAuditUrl);
        const transport = url.protocol === 'https:' ? https : http;
        const body = JSON.stringify(record);

        const headers: Record<string, string | number> = {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        };
        if (this.aimAuthHeader) {
          headers['Authorization'] = this.aimAuthHeader;
        }

        const req = transport.request(
          {
            hostname: url.hostname,
            port: url.port,
            path: url.pathname,
            method: 'POST',
            headers,
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
