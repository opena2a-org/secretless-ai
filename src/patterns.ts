/**
 * Credential patterns used across all Secretless integrations.
 * Shared between scanner, hooks, and MCP server.
 *
 * ORDERING RULE: More specific prefixes (e.g. sk-ant-, sk-proj-, sk-or-v1-)
 * MUST precede catch-all patterns (e.g. openai-legacy sk-[a-zA-Z0-9]{48,})
 * because scan.ts and transcript.ts break on first match.
 */

export interface CredentialPattern {
  id: string;
  name: string;
  regex: RegExp;
  envPrefix: string;
  category?: string;
}

export const CREDENTIAL_PATTERNS: CredentialPattern[] = [
  // ── AI/ML (category: ai-ml) ──────────────────────────────────────────
  { id: 'anthropic', name: 'Anthropic API Key', regex: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/, envPrefix: 'ANTHROPIC_API_KEY', category: 'ai-ml' },
  { id: 'openai-proj', name: 'OpenAI Project Key', regex: /sk-proj-[a-zA-Z0-9]{20,}/, envPrefix: 'OPENAI_API_KEY', category: 'ai-ml' },
  { id: 'openrouter', name: 'OpenRouter API Key', regex: /sk-or-v1-[a-zA-Z0-9]{48,}/, envPrefix: 'OPENROUTER_API_KEY', category: 'ai-ml' },
  { id: 'openai-legacy', name: 'OpenAI Legacy Key', regex: /sk-[a-zA-Z0-9]{48,}/, envPrefix: 'OPENAI_API_KEY', category: 'ai-ml' },
  { id: 'groq', name: 'Groq API Key', regex: /gsk_[a-zA-Z0-9]{20,}/, envPrefix: 'GROQ_API_KEY', category: 'ai-ml' },
  { id: 'replicate', name: 'Replicate API Token', regex: /r8_[a-zA-Z0-9]{20,}/, envPrefix: 'REPLICATE_API_TOKEN', category: 'ai-ml' },
  { id: 'huggingface', name: 'Hugging Face Token', regex: /hf_[a-zA-Z0-9]{20,}/, envPrefix: 'HUGGING_FACE_HUB_TOKEN', category: 'ai-ml' },
  { id: 'perplexity', name: 'Perplexity API Key', regex: /pplx-[a-zA-Z0-9]{48,}/, envPrefix: 'PERPLEXITY_API_KEY', category: 'ai-ml' },
  { id: 'fireworks', name: 'Fireworks AI Key', regex: /fw_[a-zA-Z0-9]{20,}/, envPrefix: 'FIREWORKS_API_KEY', category: 'ai-ml' },

  // ── Cloud Providers (category: cloud) ─────────────────────────────────
  { id: 'aws-access', name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/, envPrefix: 'AWS_ACCESS_KEY_ID', category: 'cloud' },
  { id: 'aws-sts', name: 'AWS STS Temporary Key', regex: /ASIA[0-9A-Z]{16}/, envPrefix: 'AWS_ACCESS_KEY_ID', category: 'cloud' },
  // Name-gated AWS secret access key (lockstep with @opena2a/credential-patterns
  // 0.1.2): 40-char prefix-less value flagged only when an aws…secret…key /
  // secret_access_key name precedes it (value in group 1). See the package for
  // the design rationale (forward capture group, not lookbehind — ReDoS budget).
  { id: 'aws-secret', name: 'AWS Secret Access Key', regex: /(?:aws.{0,16}(?:secret|private).{0,16}key|secret[_\s.-]?access[_\s.-]?key)["'\s]*[:=]+>?\s*["']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/i, envPrefix: 'AWS_SECRET_ACCESS_KEY', category: 'cloud' },
  { id: 'gcp-service-account', name: 'GCP Service Account JSON', regex: /"type"\s*:\s*"service_account"/, envPrefix: 'GOOGLE_APPLICATION_CREDENTIALS', category: 'cloud' },
  { id: 'digitalocean', name: 'DigitalOcean PAT', regex: /dop_v1_[a-f0-9]{64}/, envPrefix: 'DIGITALOCEAN_TOKEN', category: 'cloud' },
  { id: 'heroku', name: 'Heroku API Key', regex: /HRKU-[a-zA-Z0-9_-]{30,}/, envPrefix: 'HEROKU_API_KEY', category: 'cloud' },
  { id: 'fly-io', name: 'Fly.io Token', regex: /fo1_[a-zA-Z0-9_-]{20,}/, envPrefix: 'FLY_API_TOKEN', category: 'cloud' },
  { id: 'netlify', name: 'Netlify PAT', regex: /nfp_[a-zA-Z0-9]{40,}/, envPrefix: 'NETLIFY_AUTH_TOKEN', category: 'cloud' },
  { id: 'azure', name: 'Azure Key', regex: /(?:AccountKey|SharedAccessKey|azure[_-]?(?:storage|key|account))\s*[=:]\s*[a-zA-Z0-9+/]{43}=/i, envPrefix: 'AZURE_API_KEY', category: 'cloud' },
  { id: 'supabase', name: 'Supabase Service Key', regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]{50,}/, envPrefix: 'SUPABASE_SERVICE_ROLE_KEY', category: 'cloud' },

  // ── Communication (category: communication) ───────────────────────────
  { id: 'slack', name: 'Slack Token', regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/, envPrefix: 'SLACK_TOKEN', category: 'communication' },
  { id: 'slack-webhook', name: 'Slack Webhook URL', regex: /hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{24}/, envPrefix: 'SLACK_WEBHOOK_URL', category: 'communication' },
  { id: 'slack-app', name: 'Slack App Token', regex: /xapp-[0-9]+-[A-Z0-9]+-[0-9]+-[a-z0-9]+/, envPrefix: 'SLACK_APP_TOKEN', category: 'communication' },
  { id: 'telegram-bot', name: 'Telegram Bot Token', regex: /[0-9]{8,10}:[A-Za-z0-9_-]{35}/, envPrefix: 'TELEGRAM_BOT_TOKEN', category: 'communication' },
  { id: 'discord-bot', name: 'Discord Bot Token', regex: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/, envPrefix: 'DISCORD_BOT_TOKEN', category: 'communication' },
  { id: 'discord-webhook', name: 'Discord Webhook URL', regex: /discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/, envPrefix: 'DISCORD_WEBHOOK_URL', category: 'communication' },
  { id: 'twilio', name: 'Twilio API Key', regex: /SK[0-9a-fA-F]{32}/, envPrefix: 'TWILIO_API_KEY', category: 'communication' },
  { id: 'sendgrid', name: 'SendGrid Key', regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/, envPrefix: 'SENDGRID_API_KEY', category: 'communication' },

  // ── Developer Platforms (category: developer) ─────────────────────────
  { id: 'github-pat', name: 'GitHub Token', regex: /ghp_[a-zA-Z0-9]{36}/, envPrefix: 'GITHUB_TOKEN', category: 'developer' },
  { id: 'github-fine', name: 'GitHub Fine-Grained PAT', regex: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/, envPrefix: 'GITHUB_TOKEN', category: 'developer' },
  { id: 'github-oauth', name: 'GitHub OAuth Token', regex: /gho_[a-zA-Z0-9]{36}/, envPrefix: 'GITHUB_TOKEN', category: 'developer' },
  { id: 'github-app', name: 'GitHub App Installation Token', regex: /ghs_[a-zA-Z0-9]{36}/, envPrefix: 'GITHUB_TOKEN', category: 'developer' },
  { id: 'github-refresh', name: 'GitHub Refresh Token', regex: /ghr_[a-zA-Z0-9]{36,}/, envPrefix: 'GITHUB_TOKEN', category: 'developer' },
  { id: 'gitlab', name: 'GitLab PAT', regex: /glpat-[a-zA-Z0-9_-]{20,}/, envPrefix: 'GITLAB_TOKEN', category: 'developer' },
  { id: 'gitlab-pipeline', name: 'GitLab Pipeline Trigger', regex: /glptt-[a-f0-9]{40,}/, envPrefix: 'GITLAB_TOKEN', category: 'developer' },
  { id: 'gitlab-runner', name: 'GitLab Runner Token', regex: /GR1348941[a-zA-Z0-9_-]{20,}/, envPrefix: 'GITLAB_TOKEN', category: 'developer' },
  { id: 'npm', name: 'npm Access Token', regex: /npm_[a-zA-Z0-9]{36}/, envPrefix: 'NPM_TOKEN', category: 'developer' },
  { id: 'pypi', name: 'PyPI API Token', regex: /pypi-[A-Za-z0-9_-]{50,}/, envPrefix: 'PYPI_API_TOKEN', category: 'developer' },
  { id: 'dockerhub', name: 'Docker Hub PAT', regex: /dckr_pat_[a-zA-Z0-9_-]{20,}/, envPrefix: 'DOCKER_TOKEN', category: 'developer' },
  { id: 'bitbucket', name: 'Bitbucket App Password', regex: /ATBB[a-zA-Z0-9]{32,}/, envPrefix: 'BITBUCKET_TOKEN', category: 'developer' },

  // ── Payment (category: payment) ───────────────────────────────────────
  { id: 'stripe-test', name: 'Stripe Test Key', regex: /sk_test_[0-9a-zA-Z]{24,}/, envPrefix: 'STRIPE_SECRET_KEY', category: 'payment' },
  { id: 'stripe-restricted', name: 'Stripe Restricted Key', regex: /rk_live_[0-9a-zA-Z]{24,}/, envPrefix: 'STRIPE_RESTRICTED_KEY', category: 'payment' },
  { id: 'stripe', name: 'Stripe Live Key', regex: /sk_live_[0-9a-zA-Z]{24,}/, envPrefix: 'STRIPE_SECRET_KEY', category: 'payment' },
  { id: 'stripe-webhook', name: 'Stripe Webhook Secret', regex: /whsec_[a-zA-Z0-9]{32,}/, envPrefix: 'STRIPE_WEBHOOK_SECRET', category: 'payment' },
  { id: 'square', name: 'Square API Key', regex: /sq0[a-z]{3}-[a-zA-Z0-9_-]{22,}/, envPrefix: 'SQUARE_ACCESS_TOKEN', category: 'payment' },

  // ── Database (category: database) ─────────────────────────────────────
  { id: 'mongodb', name: 'MongoDB Connection String', regex: /mongodb\+srv:\/\/[^\s]{10,}/, envPrefix: 'MONGODB_URI', category: 'database' },
  { id: 'postgres', name: 'PostgreSQL Connection String', regex: /postgres(?:ql)?:\/\/[^\s]{10,}/, envPrefix: 'DATABASE_URL', category: 'database' },
  { id: 'mysql', name: 'MySQL Connection String', regex: /mysql:\/\/[^\s]{10,}/, envPrefix: 'DATABASE_URL', category: 'database' },
  { id: 'redis', name: 'Redis Connection String', regex: /rediss?:\/\/[^\s]{10,}/, envPrefix: 'REDIS_URL', category: 'database' },

  // ── Auth & Crypto (category: auth) ────────────────────────────────────
  { id: 'google', name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/, envPrefix: 'GOOGLE_API_KEY', category: 'auth' },
  { id: 'google-oauth', name: 'Google OAuth Access Token', regex: /ya29\.[a-zA-Z0-9_-]{50,}/, envPrefix: 'GOOGLE_ACCESS_TOKEN', category: 'auth' },
  { id: 'pem-private-key', name: 'PEM Private Key', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, envPrefix: 'PRIVATE_KEY', category: 'auth' },
  { id: 'firebase-fcm', name: 'Firebase FCM Server Key', regex: /AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140,}/, envPrefix: 'FIREBASE_SERVER_KEY', category: 'auth' },

  // ── Monitoring (category: monitoring) ──────────────────────────────────
  { id: 'newrelic', name: 'New Relic API Key', regex: /NRAK-[A-Z0-9]{27}/, envPrefix: 'NEW_RELIC_API_KEY', category: 'monitoring' },
  { id: 'newrelic-insight', name: 'New Relic Insights Key', regex: /NRIQ-[A-Z0-9]{27,}/, envPrefix: 'NEW_RELIC_API_KEY', category: 'monitoring' },
  { id: 'sentry', name: 'Sentry Auth Token', regex: /sntrys_[a-zA-Z0-9]{40,}/, envPrefix: 'SENTRY_AUTH_TOKEN', category: 'monitoring' },
  { id: 'grafana', name: 'Grafana Cloud API Key', regex: /glc_[a-zA-Z0-9_+/]{32,}=*/, envPrefix: 'GRAFANA_API_KEY', category: 'monitoring' },
  { id: 'linear', name: 'Linear API Key', regex: /lin_api_[a-zA-Z0-9]{40,}/, envPrefix: 'LINEAR_API_KEY', category: 'monitoring' },
];

/**
 * Quick-check regex: if a line contains ${VAR} but no credential prefix, skip it.
 * Auto-generated from pattern prefixes so it stays in sync as patterns are added.
 */
export const CREDENTIAL_PREFIX_QUICK_CHECK = new RegExp(
  CREDENTIAL_PATTERNS.map(p => {
    const src = p.regex.source;
    // Extract leading literal prefix (up to first quantifier or alternation)
    const m = src.match(/^([a-zA-Z0-9_\-.+:/]{3,})/);
    return m ? m[1].replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : null;
  })
  .filter(Boolean)
  // Deduplicate prefixes (e.g. multiple sk- patterns)
  .filter((v, i, a) => a.indexOf(v) === i)
  .join('|')
);

/**
 * Known example/placeholder credentials used in documentation and tutorials.
 * These are NOT real secrets and should be excluded from scan results.
 */
export const KNOWN_EXAMPLE_KEYS = new Set([
  // AWS (official docs)
  'AKIAIOSFODNN7EXAMPLE',
  'AKIAI44QH8DHBEXAMPLE',
  // AWS docs secret access key, paired with AKIAIOSFODNN7EXAMPLE in the
  // canonical example (docs.aws.amazon.com/.../id_credentials_access-keys.html).
  'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  // OpenAI (from docs)
  'sk-proj-abc123',
]);

/**
 * Substrings that indicate a credential is a placeholder, not a real secret.
 * Case-insensitive check against the matched credential value.
 */
export const PLACEHOLDER_INDICATORS = [
  'example', 'placeholder', 'your_', 'your-', 'insert_', 'insert-',
  'xxx', 'XXXX', 'test_key', 'test_secret', 'fake',
  'dummy', 'sample', 'replace_me', 'change_me', 'todo', '<your',
  'not-a-real', 'not_a_real', 'just-for-testing', 'supabase-demo',
];

/** File patterns that should never be read by AI tools */
export const SECRET_FILE_PATTERNS: string[] = [
  '.env',
  '.env.local',
  '.env.development',
  '.env.production',
  '.env.staging',
  '*.key',
  '*.pem',
  '*.p12',
  '*.pfx',
  '*.crt',
  '.aws/credentials',
  '.ssh/*',
  '.docker/config.json',
  '.git-credentials',
  '.npmrc',
  '.pypirc',
  '*.tfstate',
  '*.tfvars',
  'secrets/',
  'credentials/',
  '.opena2a/secretless-ai/',
];

/** Config files that may contain hardcoded secrets */
export const CONFIG_FILES = [
  'config.json', 'config.yaml', 'config.yml',
  '.env', '.env.local',
  'package.json', 'mcp.json',
  'CLAUDE.md',
  '.openclaw/config.json', '.moltbot/config.json',
  'openclaw.json', 'moltbot.json',
  '.curse/mcp.json', '.vscode/mcp.json',
  '.claude/settings.json',
  '.cursor/settings.json',
  '.github/copilot-instructions.md',
  // Nanobot variants
  '.nanobot/config.json', 'nanobot.yaml', 'nanobot.yml',
  // Docker/containers
  'docker-compose.yml', 'docker-compose.yaml', 'docker-compose.override.yml',
  // Terraform
  'terraform.tfvars', 'terraform.tfvars.json',
  // Other AI tools
  '.codeium/config.json', '.tabnine/config.json',
  // Kubernetes
  'kubeconfig.yaml', '.kube/config',
];

/** Source file extensions to scan for hardcoded credentials */
export const SOURCE_FILE_EXTENSIONS = new Set([
  '.js', '.jsx', '.mjs', '.cjs',
  '.ts', '.tsx', '.mts', '.cts',
  '.py',
  '.go',
  '.java',
  '.rb',
  '.rs',
  '.cs',
  '.php',
  '.swift',
  '.kt', '.kts',
  '.scala',
  '.sh', '.bash', '.zsh',
]);

/** Directories to skip when walking source files */
export const SOURCE_SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg',
  'vendor', 'dist', 'build', 'out', '.next',
  '__pycache__', '.venv', 'venv', 'env',
  '.tox', '.mypy_cache', '.pytest_cache',
  'target', 'bin', 'obj',
  '.gradle', '.maven',
  'coverage', '.nyc_output',
]);
