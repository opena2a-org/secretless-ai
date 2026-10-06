# Secretless AI — credential scan showing what AI tools can see
# Run from the repository root, with SECRETLESS_DEMO_DIR naming a directory
# of sample (never real) credentials for the scan to find:
#   SECRETLESS_DEMO_DIR=<directory> vhs docs/demo.tape

Output docs/secretless-ai-demo.gif

Set Width 880
Set Height 500
Set FontSize 15
Set FontFamily "JetBrains Mono"
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms
Set Padding 15

Hide
Type 'cd "$SECRETLESS_DEMO_DIR" && clear'
Enter
Sleep 500ms
Show

Sleep 1s
Type "npx secretless-ai scan"
Enter
Sleep 5s

# Hold so viewers can read the findings
Sleep 6s
