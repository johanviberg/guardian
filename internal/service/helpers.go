package service

import "strings"

// xmlEscape escapes a string for safe inclusion in plist/XML <string> bodies.
func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}

// splitEnv converts ["K=V", "A=B=C"] into key/value pairs, splitting on the
// first '='. Entries without '=' are treated as a key with an empty value.
func splitEnv(env []string) []kv {
	out := make([]kv, 0, len(env))
	for _, e := range env {
		if i := strings.IndexByte(e, '='); i >= 0 {
			out = append(out, kv{Key: e[:i], Value: e[i+1:]})
		} else {
			out = append(out, kv{Key: e, Value: ""})
		}
	}
	return out
}

// shellJoin joins argv into a single command string, quoting any element that
// contains shell-significant characters. Used for systemd ExecStart and cron
// lines, both of which take a single command string.
func shellJoin(parts []string) string {
	quoted := make([]string, len(parts))
	for i, p := range parts {
		quoted[i] = shellQuote(p)
	}
	return strings.Join(quoted, " ")
}

// shellQuote single-quotes s if it contains whitespace or shell metacharacters,
// escaping embedded single quotes the POSIX way.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n\"'\\$`&|;<>(){}*?#~=") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// quoteWindows wraps s in double quotes when it contains whitespace, as
// expected inside a schtasks /TR payload.
func quoteWindows(s string) string {
	if strings.ContainsAny(s, " \t") {
		return `"` + s + `"`
	}
	return s
}
