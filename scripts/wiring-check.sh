#!/bin/bash
# Shared library, sourced (never executed) by verify.sh and by this file's
# own companion, wiring-check-test.sh. Detects whether a call site that an
# anchored grep matched by text is actually unconditional and reachable, or
# only looks that way -- four evasions that change nothing about the
# matched line's own text or column, so a grep alone cannot tell them apart
# from a real, unconditional call.

# Prints the if/for/while/until/case nesting depth in effect immediately
# before $line in $file, relying on this repo's own style convention of
# putting control keywords and their closing keywords on their own line
# with zero leading whitespace for every top-level statement. A line at
# depth 0 is unconditional; depth > 0 means some call was wrapped in an
# "if" (or similar) without changing the matched line's own text, which
# an anchored grep alone cannot tell apart from a truly unconditional call.
depth_at_line() {
	local file=$1 line=$2
	awk -v target="$line" '
	NR>=target { exit }
	{
		l = $0
		sub(/^[[:space:]]+/, "", l)
		if (l ~ /^(if|for|while|until|case)([[:space:]]|\()/) depth++
		else if (l ~ /^(fi|done|esac)([[:space:];]|$)/) depth--
	}
	END { print depth + 0 }
	' "$file"
}

# True if $line in $file sits inside a heredoc BODY (data, never code) --
# tracks the one active "<<TAG" opener up to $line and clears it on a
# line that is exactly TAG, the same no-op idiom (": <<'SKIP' ... SKIP")
# that comments out a block while an anchored grep still finds the text.
in_heredoc_body() {
	local file=$1 line=$2
	awk -v target="$line" '
	NR>=target { exit }
	{
		if (tag == "") {
			p = index($0, "<<")
			if (p > 0) {
				rest = substr($0, p + 2)
				sub(/^-/, "", rest)
				sub(/^[[:space:]]+/, "", rest)
				gsub(/[\x27\x22]/, "", rest)
				split(rest, parts, /[^A-Za-z0-9_]/)
				if (parts[1] != "") tag = parts[1]
			}
		} else {
			t = $0
			gsub(/^[[:space:]]+/, "", t)
			gsub(/[[:space:]]+$/, "", t)
			if (t == tag) tag = ""
		}
	}
	END { print (tag != "") ? 1 : 0 }
	' "$file"
}

# Name of the function $line in $file sits inside, or empty at top level.
# Tracks only this repo's own convention -- "name() {" on its own line,
# a lone "}" closing it -- the same shape every function in this repo
# already uses, never a full parser.
enclosing_function() {
	local file=$1 line=$2
	awk -v target="$line" '
	NR>=target { exit }
	{
		if (fn == "" && $0 ~ /^[A-Za-z_][A-Za-z0-9_]*\(\)[[:space:]]*\{[[:space:]]*$/) {
			name = $0
			sub(/\(\).*/, "", name)
			fn = name
		} else if (fn != "" && $0 ~ /^\}[[:space:]]*$/) {
			fn = ""
		}
	}
	END { print fn }
	' "$file"
}

# True if the line immediately before $line in $file ends with a
# "&& \" line-continuation guard -- a condition on the call that changes
# neither the call's own text nor its column, so an anchored grep at
# depth 0 cannot tell it apart from a truly unconditional call.
and_guarded() {
	local file=$1 line=$2
	[ "$line" -le 1 ] && return 1
	local prev
	prev=$(sed -n "$((line - 1))p" "$file")
	[[ "$prev" =~ \&\&[[:space:]]*\\$ ]]
}

# True if the line immediately before $line in $file is a "true || \"
# line-continuation guard -- joined onto the next line, that reads as
# "true || <the call>", and since "true" always succeeds, the "||"
# short-circuits and the call after it never runs at all. This is the
# opposite of and_guarded's "sometimes runs": grep still finds the call's
# own unchanged text and column, but it is dead, not conditional.
true_or_guarded() {
	local file=$1 line=$2
	[ "$line" -le 1 ] && return 1
	local prev
	prev=$(sed -n "$((line - 1))p" "$file")
	[[ "$prev" =~ ^[[:space:]]*true[[:space:]]*\|\|[[:space:]]*\\$ ]]
}

# Combines all evasions this file guards against into one reason string,
# empty when $line in $file is a real, unconditional, reachable
# statement. Callers treat any non-empty result as a wiring failure.
# $3 is an internal recursion depth (never passed by callers): the
# function-uncalled check below re-runs this same check on each
# candidate caller line, to catch a caller that is itself unreachable
# (issue #1 round 4); the cap only guards against a call cycle (a
# function whose only caller is itself), never hit by this repo's own
# scripts.
unreachable_reason() {
	local file=$1 line=$2 depth=${3:-0} reason="" d fn

	if [ "$depth" -gt 10 ]; then
		echo ""
		return
	fi

	d=$(depth_at_line "$file" "$line")
	if [ "$d" -ne 0 ]; then
		reason="sits inside a conditional block (depth $d)"
	elif [ "$(in_heredoc_body "$file" "$line")" = 1 ]; then
		reason="sits inside a heredoc block, which is data, not code"
	elif and_guarded "$file" "$line"; then
		reason="is guarded by a leading \"&&\" line-continuation condition"
	elif true_or_guarded "$file" "$line"; then
		reason="is guarded by a leading \"true ||\" line-continuation, so it never runs"
	else
		fn=$(enclosing_function "$file" "$line")
		if [ -n "$fn" ]; then
			local reachable_call=0 caller_line
			while IFS=: read -r caller_line _; do
				[ -z "$caller_line" ] && continue
				if [ -z "$(unreachable_reason "$file" "$caller_line" "$((depth + 1))")" ]; then
					reachable_call=1
					break
				fi
			done < <(grep -nE "^[[:space:]]*${fn}([[:space:]]|\$)" "$file")
			if [ "$reachable_call" -eq 0 ]; then
				reason="sits inside function \"$fn\", which is never called"
			fi
		fi
	fi
	echo "$reason"
}
