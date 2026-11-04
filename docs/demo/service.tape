# Records docs/demo/service.gif from a real run: `make build && vhs docs/demo/service.tape` from the repo root.
Output docs/demo/service.gif
Set Shell "bash"
Set FontSize 14
Set Width 1300
Set Height 560
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 25ms

Hide
Type `export PS1='$ ' && clear` Enter
Type `./target/release/msscan serve --addr 127.0.0.1:8099 2>/dev/null & sleep 1; clear` Enter
Sleep 1500ms
Show
Type `curl -s localhost:8099/health; echo` Enter
Sleep 1s
Type `curl -s --data-binary @tests/fixtures/malicious_torch.pt 'localhost:8099/v1/scan?name=model.pt' | jq '{format, verdict, risk_score, findings: [.findings[].message]}'` Enter
Sleep 3s
Type `curl -s localhost:8099/metrics | grep -E '^msscan_(files|findings)'` Enter
Sleep 5s
Hide
Type `kill %1` Enter
