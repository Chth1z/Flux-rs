#!/system/bin/sh
PIDF=/data/local/tmp/fluxrs-tproxy-stage.pid
if [ -f "$PIDF" ]; then
	kill "$(cat "$PIDF")" 2>/dev/null || true
	rm -f "$PIDF"
fi
echo stopped
