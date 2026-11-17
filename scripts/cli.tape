# The command-line recording in the README and docs/cli.md. From the repository root, after
# `cargo build --release -p binfera-cli --features decompiler` and with web/public/demos present:
#
#   vhs scripts/cli.tape
#
# The samples are copied to /tmp/binfera-demo so the path binfera prints names no one's home folder.

Output docs/images/cli.gif

Set Shell "bash"
Set FontSize 15
Set Width 1200
Set Height 720
Set Padding 24
Set Theme "GitHub Dark"
Set TypingSpeed 45ms
Set CursorBlink false

Hide
Type `export PATH="$PWD/target/release:$PATH" PS1='$ '` Enter
Type "node web/scripts/decode-demo.mjs wannacry /tmp/binfera-demo/wannacry.exe && cd /tmp/binfera-demo && clear" Enter
Sleep 500ms
Show

# What can it do? Capabilities, with their ATT&CK and MBC ids.
Type "binfera wannacry.exe | head -32"
Sleep 400ms
Enter
Sleep 5s

# One function as C: the ransom address writer.
Type "clear" Enter
Type "binfera wannacry.exe --decompile-function 0x401e9e 2>/dev/null"
Sleep 400ms
Enter
Sleep 6s

# Every function, as one JSON object per line.
Type "clear" Enter
Type `time binfera wannacry.exe --decompile-all | jq -r 'select(.type == "function") | .address' | wc -l`
Sleep 400ms
Enter
Sleep 6s
