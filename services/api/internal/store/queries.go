// Package store owns the database pools and the named SQL loaded from db/queries.
package store

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Queries maps a statement name (from a `-- name: <name>` marker) to its SQL text.
type Queries map[string]string

// LoadQueries reads every *.sql file in dir and splits it into named statements. Each statement
// is introduced by a line of the form `-- name: <name>`. This is the thin-swap seam: no SQL is
// inlined in Go, so the same statements could back a different language's implementation.
func LoadQueries(dir string) (Queries, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no .sql files found in %q", dir)
	}
	q := Queries{}
	for _, f := range files {
		if err := loadFile(f, q); err != nil {
			return nil, err
		}
	}
	return q, nil
}

func loadFile(path string, q Queries) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	const marker = "-- name:"
	var name string
	var body strings.Builder
	flush := func() error {
		if name == "" {
			return nil
		}
		sql := strings.TrimSpace(body.String())
		if sql == "" {
			return fmt.Errorf("statement %q in %s is empty", name, path)
		}
		if _, dup := q[name]; dup {
			return fmt.Errorf("duplicate statement name %q (in %s)", name, path)
		}
		q[name] = sql
		body.Reset()
		return nil
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), marker) {
			if err := flush(); err != nil {
				return err
			}
			name = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), marker))
			continue
		}
		if name == "" {
			continue // header comments before the first statement
		}
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue // per-statement comment lines are not part of the SQL
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return flush()
}

// MustGet returns the named statement or panics; a missing name is a programming error caught at
// startup, not a runtime condition.
func (q Queries) MustGet(name string) string {
	sql, ok := q[name]
	if !ok {
		panic(fmt.Sprintf("unknown query %q", name))
	}
	return sql
}
