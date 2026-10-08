// SPDX-License-Identifier: LicenseRef-AmberCell-PSL-1.0

package wizard

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/CyberHalluciNet/AmberCell/amberctl/internal/compose"
)

// Options controls the textual init wizard.
type Options struct {
	Root       string   // compose repo root
	Cells      []string // empty → prompt; non-empty → limit to these
	In         io.Reader
	Out        io.Writer
	Err        io.Writer
	ForceStdin bool // --wizard: require readable stdin even if non-TTY
}

type cellChoice struct {
	Svc      string
	Mode     string // premade | image | context
	Provider string
	Image    string
	Context  string
	Extras   map[string]string
}

// Run executes the numbered-menu walkthrough and merges choices into root/.env.
func Run(opt Options) error {
	if opt.In == nil {
		opt.In = os.Stdin
	}
	if opt.Out == nil {
		opt.Out = os.Stdout
	}
	if opt.Err == nil {
		opt.Err = os.Stderr
	}
	if opt.Root == "" {
		return fmt.Errorf("wizard: empty root")
	}
	if opt.ForceStdin {
		if opt.In == nil {
			return fmt.Errorf("wizard: --wizard requires stdin")
		}
	}

	sc := bufio.NewScanner(opt.In)
	printf := func(format string, args ...any) { fmt.Fprintf(opt.Out, format, args...) }
	warnf := func(format string, args ...any) { fmt.Fprintf(opt.Err, format, args...) }

	printf("AmberCell provider wizard\n")
	printf("  Premade Dockerfiles under services/<svc>/providers/<name>/\n")
	printf("  Own Docker: prebuilt HI_IMAGE or PROVIDER_CONTEXT (see docs/providers.md).\n")
	printf("  Precedence: HI_IMAGE > PROVIDER_CONTEXT > builtin path.\n\n")

	selected, err := selectCells(opt, sc, printf)
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		printf("No cells selected — skipping provider env write.\n")
		return nil
	}

	choices := make([]cellChoice, 0, len(selected))
	for _, svc := range selected {
		c, err := configureCell(opt, sc, printf, warnf, svc)
		if err != nil {
			return err
		}
		choices = append(choices, c)
	}

	printf("\nSummary\n")
	printf("%-12s %-10s %s\n", "CELL", "MODE", "DETAIL")
	for _, c := range choices {
		detail := c.Provider
		switch c.Mode {
		case "image":
			detail = c.Provider + " image=" + c.Image
		case "context":
			detail = c.Provider + " context=" + c.Context
		}
		printf("%s\n", FormatSummaryLine(c.Svc, c.Mode, detail))
		for k, v := range c.Extras {
			printf("  %s=%s\n", k, v)
		}
	}
	ok, err := promptYN(sc, printf, "Write these into .env?", true)
	if err != nil {
		return err
	}
	if !ok {
		printf("Aborted — .env unchanged.\n")
		return nil
	}

	kv := map[string]string{}
	for _, c := range choices {
		spec, ok := compose.Cells[c.Svc]
		if !ok {
			continue
		}
		kv[spec.ProviderEnv] = c.Provider
		switch c.Mode {
		case "image":
			kv[spec.HiImageEnv()] = c.Image
			// Clear CONTEXT so HI_IMAGE is the sole override (precedence is HI_IMAGE first,
			// but a stale CONTEXT would resurface if HI_IMAGE is later removed).
			kv[spec.ProviderContextEnv()] = ""
		case "context":
			kv[spec.ProviderContextEnv()] = c.Context
			// Clear HI_IMAGE so CONTEXT actually wins (HI_IMAGE takes precedence).
			kv[spec.HiImageEnv()] = ""
		case "premade":
			// Clear overrides so builtin PROVIDER path matches intent.
			kv[spec.HiImageEnv()] = ""
			kv[spec.ProviderContextEnv()] = ""
		}
		for k, v := range c.Extras {
			kv[k] = v
		}
	}

	// Drop empty values from merge map for keys we want to remove from .env
	envPath := filepath.Join(opt.Root, ".env")
	if err := mergeEnvAllowClear(envPath, kv); err != nil {
		return err
	}
	printf("Wrote provider choices to %s\n", envPath)
	printf("Next: amberctl up <svc>\n")
	return nil
}

// mergeEnvAllowClear writes kv; empty string values remove the key from the file.
func mergeEnvAllowClear(path string, kv map[string]string) error {
	set := map[string]string{}
	clear := map[string]bool{}
	for k, v := range kv {
		if v == "" {
			clear[k] = true
		} else {
			set[k] = v
		}
	}
	if err := MergeEnvFile(path, set); err != nil {
		return err
	}
	if len(clear) == 0 {
		return nil
	}
	return removeEnvKeys(path, clear)
}

func removeEnvKeys(path string, keys map[string]bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		trim := strings.TrimSpace(line)
		if trim != "" && !strings.HasPrefix(trim, "#") {
			body := trim
			if strings.HasPrefix(body, "export ") {
				body = strings.TrimSpace(strings.TrimPrefix(body, "export "))
			}
			k, _, ok := strings.Cut(body, "=")
			if ok {
				k = strings.TrimSpace(k)
				if keys[k] {
					continue
				}
			}
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	text := strings.Join(out, "\n")
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	return os.WriteFile(path, []byte(text), mode)
}

func selectCells(opt Options, sc *bufio.Scanner, printf func(string, ...any)) ([]string, error) {
	if len(opt.Cells) > 0 {
		for _, s := range opt.Cells {
			if _, ok := compose.Cells[s]; !ok {
				return nil, fmt.Errorf("wizard: unknown cell %q", s)
			}
		}
		return opt.Cells, nil
	}

	core := CoreDefaultSvcs()
	printf("Which cells to configure?\n")
	printf("  1) Core defaults (%s)\n", strings.Join(core, ", "))
	printf("  2) Pick from catalog (multi-select)\n")
	printf("  3) Skip wizard for providers\n")
	choice, err := promptNumber(sc, printf, "Choice", 1, 3, 1)
	if err != nil {
		return nil, err
	}
	switch choice {
	case 1:
		return core, nil
	case 3:
		return nil, nil
	}

	names := AllSvcNames()
	printf("Enter comma-separated numbers (or names):\n")
	for i, n := range names {
		printf("  %2d) %s\n", i+1, n)
	}
	line, err := promptLine(sc, printf, "Cells")
	if err != nil {
		return nil, err
	}
	return parseCellList(line, names)
}

func parseCellList(line string, names []string) ([]string, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("wizard: empty cell selection")
	}
	index := map[string]string{}
	for _, n := range names {
		index[n] = n
	}
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(line, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var svc string
		if n, err := parseInt(part); err == nil && n >= 1 && n <= len(names) {
			svc = names[n-1]
		} else if _, ok := index[part]; ok {
			svc = part
		} else if _, ok := compose.Cells[part]; ok {
			svc = part
		} else {
			return nil, fmt.Errorf("wizard: unknown cell %q", part)
		}
		if !seen[svc] {
			seen[svc] = true
			out = append(out, svc)
		}
	}
	return out, nil
}

func configureCell(opt Options, sc *bufio.Scanner, printf, warnf func(string, ...any), svc string) (cellChoice, error) {
	cell, ok := CellBySvc(svc)
	if !ok {
		return cellChoice{}, fmt.Errorf("wizard: unknown cell %q", svc)
	}
	spec, okSpec := compose.Cells[svc]
	if !okSpec {
		return cellChoice{}, fmt.Errorf("wizard: unknown cell %q", svc)
	}
	printf("\n=== %s ===\n", svc)
	printf("  (A) Premade provider\n")
	printf("  (B) Own prebuilt image (%s)\n", spec.HiImageEnv())
	printf("  (C) Own Dockerfile context (%s)\n", spec.ProviderContextEnv())
	modeLetter, err := promptChoice(sc, printf, "Mode [A/B/C]", []string{"a", "b", "c"}, "a")
	if err != nil {
		return cellChoice{}, err
	}

	choice := cellChoice{Svc: svc, Extras: map[string]string{}}

	switch modeLetter {
	case "a":
		avail := AvailableProviders(opt.Root, cell)
		if len(avail) == 0 {
			warnf("amberctl: warning: no premade Dockerfiles for %s yet; use own image/context or wait for phase providers\n", svc)
			return cellChoice{}, fmt.Errorf("wizard: no premade providers available for %s", svc)
		}
		// Warn about catalog entries missing Dockerfiles.
		for _, p := range cell.Providers {
			df := filepath.Join(opt.Root, "services", svc, "providers", p.ID, "Dockerfile")
			if !fileExists(df) {
				warnf("amberctl: note: premade %s/%s not built yet (no Dockerfile) — skipped\n", svc, p.ID)
			}
		}
		printf("Premade providers:\n")
		for i, p := range avail {
			printf("  %d) %s — %s\n", i+1, p.ID, p.Desc)
		}
		defIdx := 1
		for i, p := range avail {
			if p.ID == spec.DefaultProv {
				defIdx = i + 1
				break
			}
		}
		n, err := promptNumber(sc, printf, "Provider", 1, len(avail), defIdx)
		if err != nil {
			return cellChoice{}, err
		}
		choice.Mode = "premade"
		choice.Provider = avail[n-1].ID

	case "b":
		printf("Own images should follow docs/providers.md (Active Mode off, caps, no docker.sock, stable event fields).\n")
		img, err := promptLine(sc, printf, "Image ref (prefer digest)")
		if err != nil {
			return cellChoice{}, err
		}
		img = strings.TrimSpace(img)
		if img == "" {
			return cellChoice{}, fmt.Errorf("wizard: image ref required")
		}
		if err := validateEnvValue(img); err != nil {
			return cellChoice{}, fmt.Errorf("wizard: image ref: %w", err)
		}
		if strings.HasSuffix(img, ":latest") || img == "latest" {
			warnf("amberctl: warning: floating :latest tag — prefer digest pins\n")
		}
		prov, err := promptLineDefault(sc, printf, "provider_id", "custom")
		if err != nil {
			return cellChoice{}, err
		}
		choice.Mode = "image"
		choice.Image = img
		choice.Provider = sanitizeProviderID(prov)

	case "c":
		printf("Own contexts should follow docs/providers.md (Active Mode off, caps, no docker.sock, stable event fields).\n")
		dir, err := promptLine(sc, printf, "Dockerfile context directory")
		if err != nil {
			return cellChoice{}, err
		}
		dir = strings.TrimSpace(dir)
		if dir == "" {
			return cellChoice{}, fmt.Errorf("wizard: context path required")
		}
		if err := validateEnvValue(dir); err != nil {
			return cellChoice{}, fmt.Errorf("wizard: context path: %w", err)
		}
		dir = filepath.Clean(dir)
		abs := dir
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(opt.Root, dir)
		}
		abs = filepath.Clean(abs)
		if st, err := os.Stat(abs); err != nil || !st.IsDir() {
			return cellChoice{}, fmt.Errorf("wizard: context path not a directory: %s", dir)
		}
		if !fileExists(filepath.Join(abs, "Dockerfile")) {
			return cellChoice{}, fmt.Errorf("wizard: no Dockerfile in %s", dir)
		}
		prov, err := promptLineDefault(sc, printf, "provider_id", "custom")
		if err != nil {
			return cellChoice{}, err
		}
		choice.Mode = "context"
		choice.Context = dir
		choice.Provider = sanitizeProviderID(prov)
	}

	if cell.ExtraHint == "AMBER_FTP_PASV_ADDRESS" {
		pasv, err := promptLineDefault(sc, printf, "AMBER_FTP_PASV_ADDRESS (lab often 127.0.0.1)", "127.0.0.1")
		if err != nil {
			return cellChoice{}, err
		}
		pasv = strings.TrimSpace(pasv)
		if pasv != "" {
			if err := validateEnvValue(pasv); err != nil {
				return cellChoice{}, fmt.Errorf("wizard: AMBER_FTP_PASV_ADDRESS: %w", err)
			}
			choice.Extras["AMBER_FTP_PASV_ADDRESS"] = pasv
		}
	}
	return choice, nil
}

func sanitizeProviderID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "custom"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-_")
	if out == "" {
		return "custom"
	}
	return strings.ToLower(out)
}

func promptLine(sc *bufio.Scanner, printf func(string, ...any), label string) (string, error) {
	printf("%s: ", label)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("wizard: EOF on stdin")
	}
	return sc.Text(), nil
}

func promptLineDefault(sc *bufio.Scanner, printf func(string, ...any), label, def string) (string, error) {
	printf("%s [%s]: ", label, def)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("wizard: EOF on stdin")
	}
	t := strings.TrimSpace(sc.Text())
	if t == "" {
		return def, nil
	}
	return t, nil
}

func promptYN(sc *bufio.Scanner, printf func(string, ...any), label string, defYes bool) (bool, error) {
	hint := "Y/n"
	if !defYes {
		hint = "y/N"
	}
	printf("%s [%s]: ", label, hint)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return false, err
		}
		return false, fmt.Errorf("wizard: EOF on stdin")
	}
	t := strings.TrimSpace(strings.ToLower(sc.Text()))
	if t == "" {
		return defYes, nil
	}
	return t == "y" || t == "yes", nil
}

func promptNumber(sc *bufio.Scanner, printf func(string, ...any), label string, min, max, def int) (int, error) {
	printf("%s [%d]: ", label, def)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("wizard: EOF on stdin")
	}
	t := strings.TrimSpace(sc.Text())
	if t == "" {
		return def, nil
	}
	n, err := parseInt(t)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("wizard: enter a number %d–%d", min, max)
	}
	return n, nil
}

func promptChoice(sc *bufio.Scanner, printf func(string, ...any), label string, allowed []string, def string) (string, error) {
	printf("%s: ", label)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("wizard: EOF on stdin")
	}
	t := strings.ToLower(strings.TrimSpace(sc.Text()))
	if t == "" {
		t = def
	}
	for _, a := range allowed {
		if t == a {
			return t, nil
		}
	}
	return "", fmt.Errorf("wizard: choose one of %v", allowed)
}

func parseInt(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

// IsTTY reports whether stdin is a character device (no x/term dependency).
func IsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// NonInteractive reports --yes / AMBER_INIT_NONINTERACTIVE=1 style skip.
func NonInteractive(yesFlag bool) bool {
	if yesFlag {
		return true
	}
	v := strings.TrimSpace(os.Getenv("AMBER_INIT_NONINTERACTIVE"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}
