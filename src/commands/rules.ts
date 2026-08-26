import * as path from 'path';
import * as fs from 'fs';
import {
  loadCustomRulesDetailed,
  customRulesToDenyRules,
  generateTemplate,
  envPatternToDenyRules,
  filePatternToDenyRules,
  validatePattern,
  globToShellRegex,
  RULES_FILENAME,
} from '../custom-rules';

export function runRules(args: string[], projectDir: string = process.cwd()): number {
  const subcommand = args[0] ?? 'list';

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

      const issues = result.status === 'unrecognised-content' ? (result.issues ?? []) : [];
      if (issues.length > 0) {
        console.log(`\n  ${RULES_FILENAME}: ${issues.length} line${issues.length === 1 ? '' : 's'} not read\n`);
        for (const issue of issues) {
          console.log(`    line ${issue.line}: ${issue.text}`);
          console.log(`      ${issue.message}`);
        }
      }

      const rules = result.rules;
      if (rules) {
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
        console.log(`\n  Generates ${denyRules.length} deny rules${issues.length > 0 ? ' from the lines that were read' : ''}.`);
        console.log('  Run: npx secretless-ai init  (to apply)\n');
      }

      if (issues.length > 0) {
        if (!rules) {
          console.log(`\n  No deny rules are generated from this file — nothing in it was read as a pattern.`);
        }
        console.log(`  The flagged lines generate no deny rules. Fix them, then run: npx secretless-ai rules list  (to re-check)\n`);
        return 1;
      }
      return 0;
    }

    case 'init': {
      const rulesPath = path.join(projectDir, RULES_FILENAME);
      if (fs.existsSync(rulesPath)) {
        console.log(`\n  ${RULES_FILENAME} already exists.`);
        console.log('  Edit it directly or use: npx secretless-ai rules list\n');
        return 0;
      }
      fs.writeFileSync(rulesPath, generateTemplate());
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
