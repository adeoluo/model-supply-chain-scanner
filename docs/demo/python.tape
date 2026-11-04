# Records docs/demo/python.gif from a real run: `uv sync && vhs docs/demo/python.tape` from the repo root.
Output docs/demo/python.gif
Set Shell "bash"
Set FontSize 14
Set Width 1300
Set Height 520
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 20ms

Hide
Type `export PS1='$ ' && clear` Enter
Sleep 500ms
Show
Type `cat docs/demo/python_api.py` Enter
Sleep 2s
Type `.venv/bin/python docs/demo/python_api.py` Enter
Sleep 5s
