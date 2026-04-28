import * as path from 'path';

export function runRules(args: string[]): number {
  const {
    loadCustomRulesDetailed,
    customRulesToDenyRules,
    generateTemplate,
    RULES_FILENAME,
  } = require('../custom-rules') as typeof import('../custom-rules');

  const subcommand = args[0] ?? 'list';
  const projectDir = process.cwd();

  switch (subcommand) {
    case 'list': {
      const result = loadCustomRulesDetailed(projectDir);
      if (result.status === 'missing') {
        console.log(`\n  No ${RULES_FILENAME} found in this directory.`);
        console.log(`  Create one: npx secretless-ai rules init\n`);
        return 0;
      }
      if (result.status === 'empty') {
        console.log(`\n  ${RULES_FILENAME} exists but has no active rules.`);
        console.log('  Uncomment or add patterns, then run: npx secretless-ai init\n');
        return 0;
      }
      const rules = result.rules!;

      console.log(`\n  Custom Rules (${RULES_FILENAME})\n`);

      if (rules.env.length > 0) {
        console.log('  Environment variables:');
        for (const p of rules.env) {
          console.log(`    ${p}`);
        }
      }
      if (rules.files.length > 0) {
        console.log('  File patterns:');
        for (const p of rules.files) {
          console.log(`    ${p}`);
        }
      }
      if (rules.bash.length > 0) {
        console.log('  Bash commands:');
        for (const p of rules.bash) {
          console.log(`    ${p}`);
        }
      }

      const denyRules = customRulesToDenyRules(rules);
      console.log(`\n  Generates ${denyRules.length} deny rules.`);
      console.log('  Run: npx secretless-ai init  (to apply)\n');
      return 0;
    }

    case 'init': {
      const nodeFs = require('fs') as typeof import('fs');
      const rulesPath = path.join(projectDir, RULES_FILENAME);
      if (nodeFs.existsSync(rulesPath)) {
        console.log(`\n  ${RULES_FILENAME} already exists.`);
        console.log('  Edit it directly or use: npx secretless-ai rules list\n');
        return 0;
      }
      nodeFs.writeFileSync(rulesPath, generateTemplate());
      console.log(`\n  Created ${RULES_FILENAME}`);
      console.log('  Edit it to add your organization-specific patterns.');
      console.log('  Then run: npx secretless-ai init  (to apply)\n');
      return 0;
    }

    case 'test': {
      // Support: rules test <pattern> [--env|--file|--bash]
      const nonFlags = args.slice(1).filter(a => !a.startsWith('--'));
      const flags = args.slice(1).filter(a => a.startsWith('--'));
      const pattern = nonFlags[0];
      if (!pattern) {
        console.error('\n  Usage: secretless-ai rules test <pattern> [--env|--file|--bash]\n');
        console.error('  Examples:');
        console.error('    secretless-ai rules test "ACME_*"              (auto-detects env)');
        console.error('    secretless-ai rules test "*.corp-secret"       (auto-detects file)');
        console.error('    secretless-ai rules test "curl*corp*" --bash   (force bash type)\n');
        return 1;
      }

      const { envPatternToDenyRules, filePatternToDenyRules, validatePattern, globToShellRegex } =
        require('../custom-rules') as typeof import('../custom-rules');

      if (!validatePattern(pattern)) {
        console.error(`\n  Invalid pattern: ${pattern}`);
        console.error('  Only alphanumeric, *, ., -, _, / characters allowed.\n');
        return 1;
      }

      console.log(`\n  Testing pattern: ${pattern}\n`);

      // Determine type: explicit flag > auto-detect
      const explicitType = flags.includes('--env') ? 'env'
        : flags.includes('--file') ? 'file'
        : flags.includes('--bash') ? 'bash'
        : null;

      const BASH_COMMAND_PREFIXES = [
        'curl', 'wget', 'ssh', 'scp', 'sftp', 'rsync',
        'vault', 'aws', 'gcloud', 'az', 'kubectl',
        'docker', 'npm', 'pip', 'gem', 'cargo',
        'git', 'gh', 'openssl', 'gpg', 'mysql', 'psql',
        'redis-cli', 'mongosh', 'mongo',
      ];

      const patternType = explicitType
        ?? (/^[A-Z_*]+$/.test(pattern) ? 'env'
          : BASH_COMMAND_PREFIXES.some(cmd => pattern.startsWith(cmd)) ? 'bash'
          : 'file');

      if (patternType === 'env') {
        console.log('  Type: environment variable pattern');
        console.log('  Deny rules generated:');
        for (const rule of envPatternToDenyRules(pattern)) {
          console.log(`    ${rule}`);
        }
      } else if (patternType === 'bash') {
        console.log('  Type: bash command pattern');
        console.log('  Deny rule generated:');
        console.log(`    Bash(${pattern})`);
      } else {
        console.log('  Type: file pattern');
        console.log('  Deny rules generated:');
        for (const rule of filePatternToDenyRules(pattern)) {
          console.log(`    ${rule}`);
        }
      }
      console.log(`  Shell regex: ${globToShellRegex(pattern)}`);
      console.log();
      return 0;
    }

    default:
      console.error(`\n  Unknown rules subcommand: ${subcommand}`);
      console.error('  Usage: secretless-ai rules <list|init|test>\n');
      return 1;
  }
}
