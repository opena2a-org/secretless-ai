# secretless-ai init in a new project, then verify.
# Record: docs/vhs/record-init.sh
# The script renders this tape in the recording container (docs/vhs/docker/Dockerfile) and writes
# docs/vhs/init.json, which names the build, the fixture and the render. Edit this tape, render again.
Output docs/vhs/init.gif
Output docs/vhs/out/init.mp4
Require npx
Require secretless-ai
Require sh
Require clear
Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 14
Set Columns 120
Set Rows 40
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 20
Set Framerate 10
Set CursorBlink false

Hide
Type "sh docs/vhs/setup-fixture.sh /work/project /work/new-home && cd /work/project && export HOME=/work/new-home && clear"
Enter
Show
Sleep 1s
Type "npx secretless-ai init"
Sleep 300ms
Enter
Sleep 5s
Type "npx secretless-ai verify"
Sleep 300ms
Enter
Sleep 7s
