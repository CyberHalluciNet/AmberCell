// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package wizard

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// validateEnvValue rejects values that would corrupt .env line-oriented format.
func validateEnvValue(v string) error {
	if strings.ContainsAny(v, "\n\r\x00") {
		return fmt.Errorf("value must not contain newlines or NUL")
	}
	return nil
}

// MergeEnvFile updates or appends keys in path. Unrelated keys are left intact.
// Never logs values (callers must not print secrets). If the file is newly
// created, mode is 0600; existing mode is preserved.
func MergeEnvFile(path string, kv map[string]string) error {
	if len(kv) == 0 {
		return nil
	}
	for k, v := range kv {
		if strings.TrimSpace(k) == "" || strings.ContainsAny(k, "=\n\r\x00") {
			return fmt.Errorf("invalid env key %q", k)
		}
		if err := validateEnvValue(v); err != nil {
			return fmt.Errorf("env %s: %w", k, err)
		}
	}
	var lines []string
	created := false
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		created = true
		lines = []string{
			"# AmberCell — written by amberctl init wizard",
			"# See docs/providers.md (provider_contract.v1) and .env.example",
			"",
		}
	} else {
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		if err := sc.Err(); err != nil {
			return err
		}
	}

	seen := map[string]bool{}
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		body := trim
		if strings.HasPrefix(body, "export ") {
			body = strings.TrimSpace(strings.TrimPrefix(body, "export "))
		}
		k, _, ok := strings.Cut(body, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if v, want := kv[k]; want {
			lines[i] = k + "=" + v
			seen[k] = true
		}
	}
	for k, v := range kv {
		if seen[k] {
			continue
		}
		lines = append(lines, k+"="+v)
	}

	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	mode := os.FileMode(0o600)
	if !created {
		if st, err := os.Stat(path); err == nil {
			mode = st.Mode().Perm()
		}
	}
	return os.WriteFile(path, []byte(out), mode)
}

// FormatSummaryLine is a display helper (no secrets).
func FormatSummaryLine(svc, mode, detail string) string {
	return fmt.Sprintf("%-12s %-10s %s", svc, mode, detail)
}
