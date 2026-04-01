/**
 * Optional NanoMind integration layer.
 *
 * NanoMind is an optional peer dependency. All functions gracefully
 * degrade when NanoMind packages are not installed.
 */

// ---------------------------------------------------------------------------
// Guard: prompt injection screening
// ---------------------------------------------------------------------------

export interface InjectionScreenResult {
  safe: boolean;
  patterns: Array<{
    type: string;
    match: string;
    severity: 'critical' | 'high' | 'medium';
  }>;
  recommendation: string;
}

let guardLoaded = false;
let screenInputFn: ((input: string, source?: string) => InjectionScreenResult) | null = null;

function loadGuard(): boolean {
  if (guardLoaded) return screenInputFn !== null;
  guardLoaded = true;
  try {
    const guard = require('@nanomind/guard');
    screenInputFn = guard.screenInput;
    return true;
  } catch {
    return false;
  }
}

/**
 * Screen a string for prompt injection patterns using @nanomind/guard.
 * Returns null if NanoMind guard is not installed.
 */
export function screenForInjection(input: string, source?: string): InjectionScreenResult | null {
  if (!loadGuard() || !screenInputFn) return null;
  try {
    return screenInputFn(input, source);
  } catch {
    return null;
  }
}

/**
 * Screen MCP env var values for prompt injection.
 * Returns findings for any values containing injection patterns.
 */
export function screenMcpEnvVars(
  env: Record<string, string>,
): Array<{ key: string; value: string; result: InjectionScreenResult }> {
  if (!loadGuard()) return [];

  const findings: Array<{ key: string; value: string; result: InjectionScreenResult }> = [];

  for (const [key, value] of Object.entries(env)) {
    // Only screen non-trivial values (skip short numbers, booleans, etc.)
    if (value.length < 10) continue;
    // Skip values that look like pure URLs, paths, or numbers
    if (/^(https?:\/\/|\/|[0-9.]+$)/.test(value)) continue;

    const result = screenForInjection(value, 'env');
    if (result && !result.safe) {
      findings.push({ key, value, result });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Engine: rich credential context
// ---------------------------------------------------------------------------

let engineLoaded = false;
let engineInstance: any = null;

async function loadEngine(): Promise<boolean> {
  if (engineLoaded) return engineInstance !== null;
  engineLoaded = true;
  try {
    const { NanoMindEngine } = require('@nanomind/engine');
    engineInstance = new NanoMindEngine();
    const ready = await engineInstance.isReady();
    if (!ready) {
      engineInstance = null;
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Classify a credential finding for risk assessment.
 * Returns null if NanoMind engine is not installed or not ready.
 */
export async function classifyCredentialRisk(
  patternName: string,
  filePath: string,
  lineContent: string,
): Promise<{ category: string; confidence: number } | null> {
  if (!await loadEngine() || !engineInstance) return null;
  try {
    const context = `Credential type: ${patternName}. Found in: ${filePath}. Context: ${lineContent.substring(0, 200)}`;
    return await engineInstance.classify(context, [
      'admin_access',
      'read_only',
      'write_access',
      'billing',
      'test_credential',
      'infrastructure',
    ]);
  } catch {
    return null;
  }
}

/**
 * Generate a rich explanation for a credential finding.
 * Returns null if NanoMind engine is not installed or not ready.
 */
export async function explainFinding(
  patternName: string,
  patternId: string,
  filePath: string,
): Promise<string | null> {
  if (!await loadEngine() || !engineInstance) return null;
  try {
    const prompt = `In one sentence, explain the security risk of a hardcoded ${patternName} found in ${filePath}. Include what an attacker could do with it and the immediate action to take.`;
    const result = await engineInstance.infer(prompt, { maxTokens: 100, temperature: 0.1 });
    return result?.text?.trim() || null;
  } catch {
    return null;
  }
}

/**
 * Check if NanoMind guard is available.
 */
export function isGuardAvailable(): boolean {
  return loadGuard();
}

/**
 * Check if NanoMind engine is available (async -- needs model check).
 */
export async function isEngineAvailable(): Promise<boolean> {
  return loadEngine();
}
