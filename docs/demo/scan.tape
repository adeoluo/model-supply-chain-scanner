# Records docs/demo/scan.gif from a real run: `make build && vhs docs/demo/scan.tape` from the repo root.
Output docs/demo/scan.gif
Set Shell "bash"
Set FontSize 14
Set Width 1300
Set Height 640
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 25ms

Hide
Type `export PS1='$ ' && clear` Enter
Sleep 500ms
Show
Type `./target/release/msscan scan tests/fixtures` Enter
Sleep 7s
