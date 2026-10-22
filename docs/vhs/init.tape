# secretless-ai init in a new project, then verify.
# Record: docs/vhs/record-init.sh
# The script renders this tape in the recording container (docs/vhs/docker/Dockerfile) and writes
# docs/vhs/init.json, which names the build, the fixture and the render. Edit this tape, render again.
#
# Pace: 120 ms a character on screen and 800 ms before each Enter. After each step the screen holds
# for at least 3 s, 1 s for every 4 lines the step prints (docs/vhs/init-capture.txt), and the time
# its sentence in docs/vhs/init.narration.json takes at 150 words a minute plus 0.5 s; and for at
# most 12 s. Each hold has about 0.5 s more than that, because a render shows a step's output for
# up to 0.4 s less than its Sleep. Typing inside Hide is not shown, so it runs at 10 ms a character.
Output docs/vhs/init.gif
Output docs/vhs/out/init.mp4
Require npx
Require secretless-ai
Require sh
Require clear
Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 14
Set Columns 110
Set Rows 28
Set Theme "Catppuccin Mocha"
Set TypingSpeed 120ms
Set Padding 20
Set Framerate 10
Set CursorBlink false

Hide
Type@10ms "sh docs/vhs/setup-fixture.sh /work/project /work/new-home && cd /work/project && export HOME=/work/new-home && clear"
Enter
Show
Sleep 1s

# step: s1
Type "npx secretless-ai init"
Sleep 800ms
Enter
Wait
Screenshot docs/vhs/init-s1.png
Sleep 10s

Hide
Type@10ms "clear"
Enter
Sleep 300ms
Show

# step: s2
Type "npx secretless-ai verify"
Sleep 800ms
Enter
Wait
Screenshot docs/vhs/init-s2.png
Sleep 9s
