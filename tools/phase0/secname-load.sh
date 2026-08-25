#!/system/bin/sh
# Loader half of the section-name probe. Runs on the device, because the
# device's bpftool is the one that has to be able to inspect our programs.
#
# Also tries the explicit "type sched_cls" form, which decides whether an
# unrecognised section name is merely inconvenient or actually fatal.

D=/data/local/tmp/secprobe
echo "bpftool: $(bpftool version 2>&1 | head -1)"
echo
printf '%-20s %-14s %s\n' "SECTION" "AUTO-DETECT" "EXPLICIT type sched_cls"
printf '%-20s %-14s %s\n' "-------" "-----------" "-----------------------"

while IFS="$(printf '\t')" read -r f n; do
	[ -z "$f" ] && continue
	obj="$D/o_$f.o"
	[ -f "$obj" ] || continue

	rm -f /sys/fs/bpf/_sn 2>/dev/null
	if bpftool prog load "$obj" /sys/fs/bpf/_sn >/dev/null 2>&1; then
		a=OK
	else
		a=fail
	fi
	rm -f /sys/fs/bpf/_sn 2>/dev/null

	if bpftool prog load "$obj" /sys/fs/bpf/_sn type sched_cls >/dev/null 2>&1; then
		e=OK
	else
		e=fail
	fi
	rm -f /sys/fs/bpf/_sn 2>/dev/null

	printf '%-20s %-14s %s\n' "$n" "$a" "$e"
done <"$D/names.txt"
