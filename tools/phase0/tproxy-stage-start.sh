#!/system/bin/sh
# Throwaway official sing-box TPROXY on 61235. Does not touch fluxd.
SB=/data/adb/modules/Flux-rs/bin/sing-box
CFG=/data/local/tmp/fluxrs-tproxy-stage.json
LOG=/data/local/tmp/fluxrs-tproxy-stage.log
PIDF=/data/local/tmp/fluxrs-tproxy-stage.pid

if [ -f "$PIDF" ]; then
	old=$(cat "$PIDF")
	kill "$old" 2>/dev/null || true
	rm -f "$PIDF"
fi
rm -f "$LOG"
export HOME=/data/local/tmp
"$SB" check -c "$CFG" >"$LOG" 2>&1 || {
	echo "check_fail"
	cat "$LOG"
	exit 1
}
trap '' HUP
"$SB" run -c "$CFG" >>"$LOG" 2>&1 &
echo $! >"$PIDF"
sleep 1
if ! kill -0 "$(cat "$PIDF")" 2>/dev/null; then
	echo "run_fail"
	cat "$LOG"
	exit 1
fi
echo "PID $(cat "$PIDF")"
exit 0
