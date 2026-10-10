# demo/: a console recording of the suite's smoke run on a stack that is already built, plus the
# testnet transaction ids re-checked on Horizon. Records a REAL run (new testnet payments).
# Needs: brew install vhs   (ttyd + ffmpeg). vhs only accepts a relative Output path, so run it from
# the directory where the webm should land:
#   cd ~/Documents && vhs /Users/user/sonoranpub/impala/demo/recordings/demo.tape
Output impala-demo-suite.webm

Set Shell bash
Set FontSize 15
Set Width 1500
Set Height 1000
Set Padding 20
Set Framerate 24
Set TypingSpeed 30ms

Type "cd /Users/user/sonoranpub/impala/demo && clear" Enter
Sleep 800ms
Type "# Impala on Stellar testnet: bridge stack in containers, a custodial payment, then every testnet id re-checked on Horizon" Enter
Sleep 2s
Type "scripts/run-all.sh --smoke --no-build" Enter
Sleep 150s
Sleep 10s

Type "clear" Enter
Sleep 500ms
Type "# every testnet transaction id the suite recorded, re-confirmed on Horizon" Enter
Type "scripts/txids.sh --check" Enter
Sleep 15s
Sleep 4s

Type "clear" Enter
Sleep 500ms
Type "# the custodial payment as Horizon (Stellar testnet) sees it" Enter
Type `curl -s "https://horizon-testnet.stellar.org/transactions/$(jq -r .stellar_hash state/records/scenario-02-custodial-payment.json)" | jq '{hash, successful, ledger, created_at, memo_type, memo, source_account, fee_charged}'` Enter
Sleep 6s
Type "cat state/report.md" Enter
Sleep 12s
