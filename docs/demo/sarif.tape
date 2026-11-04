# Records docs/demo/sarif.gif from a real run: `make build && vhs docs/demo/sarif.tape` from the repo root.
Output docs/demo/sarif.gif
Set Shell "bash"
Set FontSize 14
Set Width 1300
Set Height 520
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 25ms

Hide
Type `export PS1='$ ' && clear` Enter
Sleep 500ms
Show
Type `./target/release/msscan scan -f sarif -o report.sarif tests/fixtures; echo "exit status $?"` Enter
Sleep 2s
Type `jq -r '.runs[0].results[] | [.level, .ruleId, .message.text] | @tsv' report.sarif | cut -c1-120 | head -12` Enter
Sleep 6s
Hide
Type `rm -f report.sarif` Enter
