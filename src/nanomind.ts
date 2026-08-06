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
 * Build the explanation prompt. Exported so the validator can be driven with the
 * exact prompt a given finding produced — echo detection is derived from the
 * prompt rather than hard-coded, so it survives edits to the wording.
 *
 * The prompt deliberately asks for IMPACT ONLY. Remediation is owned by the
 * deterministic `fix` field on the finding; soliciting it from the model is what
 * produced a fabricated `require('openai-project-key')` (no such package) in the
 * 0.21.0 release-test pass.
 */
export function buildExplainPrompt(patternName: string, filePath: string): string {
  return `In one sentence, explain the security risk of a hardcoded ${patternName} found in ${filePath}. Describe only what an attacker could do with it. Do not suggest remediation, commands, package names, or URLs.`;
}

/** Normalize to a lowercase word list for overlap / repetition analysis. */
function words(s: string): string[] {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().split(' ').filter(Boolean);
}

/** Contiguous n-grams of a word list, as joined strings. */
function ngrams(list: string[], n: number): string[] {
  const out: string[] = [];
  for (let i = 0; i + n <= list.length; i++) out.push(list.slice(i, i + n).join(' '));
  return out;
}

/** Longest run of words the output shares verbatim with the prompt. */
const ECHO_NGRAM = 8;
/** A 5-gram repeated this many times marks a degenerate repetition loop. */
const REPEAT_LIMIT = 3;

/**
 * Model output that instructs an install / import. A security tool must never
 * emit a package name it invented, so any output reaching for one is dropped
 * wholesale rather than partially scrubbed.
 */
const INSTALL_DIRECTIVE = [
  /\b(?:npm|yarn|pnpm|pip3?|gem|go|cargo|brew|apt|composer)\s+(?:install|add|get|require)\b/i,
  /\brequire\s*\(/,
  /\bimport\s+[^;\n]*\bfrom\b/,
  /\bfrom\s+['"][^'"\n]+['"]\s+import\b/,
];

/**
 * Model output naming a host. A fabricated rotation URL is the same class of
 * harm as a fabricated package name — it can send a user to a domain an
 * attacker is free to register. Verified URLs live in the deterministic fix.
 */
const HOST_REFERENCE = [
  /https?:\/\//i,
  /\bwww\./i,
  /\b[a-z0-9][a-z0-9-]*\.(?:com|net|org|io|ai|dev|co|app|cloud|sh|me|xyz)\b/i,
];

/**
 * Validate generated explanation text before it is shown to a user.
 * Returns the trimmed text, or null when it must be dropped.
 *
 * Every rule here exists because the 0.21.0 release-test pass observed the
 * failure: prompt echo replacing the remediation, a fabricated package name,
 * and a degenerate repetition loop.
 */
export function validateExplanation(raw: string | null | undefined, prompt: string): string | null {
  if (!raw) return null;
  const text = raw.trim();
  if (text.length < 20 || text.length > 400) return null;

  for (const re of INSTALL_DIRECTIVE) if (re.test(text)) return null;
  for (const re of HOST_REFERENCE) if (re.test(text)) return null;

  const outWords = words(text);
  if (outWords.length < 5) return null;

  // Prompt echo: the model restating its instructions back at us.
  const promptGrams = new Set(ngrams(words(prompt), ECHO_NGRAM));
  for (const g of ngrams(outWords, ECHO_NGRAM)) if (promptGrams.has(g)) return null;

  // Degenerate repetition loop.
  const counts = new Map<string, number>();
  for (const g of ngrams(outWords, 5)) {
    const n = (counts.get(g) ?? 0) + 1;
    if (n >= REPEAT_LIMIT) return null;
    counts.set(g, n);
  }

  return text;
}

/**
 * Generate a rich explanation for a credential finding.
 * Returns null if NanoMind engine is not installed, not ready, or if the
 * generated text fails validation.
 *
 * Callers MUST render the result as clearly-labelled generated content
 * ALONGSIDE the deterministic fix, never in place of it.
 */
export async function explainFinding(
  patternName: string,
  patternId: string,
  filePath: string,
): Promise<string | null> {
  if (!await loadEngine() || !engineInstance) return null;
  try {
    const prompt = buildExplainPrompt(patternName, filePath);
    const result = await engineInstance.infer(prompt, { maxTokens: 100, temperature: 0.1 });
    return validateExplanation(result?.text, prompt);
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
