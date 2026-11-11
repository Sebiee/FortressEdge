package collect

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
)

// mergeMetrics writes the edges' metrics (Prometheus's text format, by
// edge name) as one exposition: each family once, with its HELP and TYPE,
// and under it every edge's samples with an edge label in front.
func mergeMetrics(w io.Writer, byEdge map[string][]byte) {
	type family struct {
		help, typ string // as the first edge that has them sent them
		samples   []string
	}
	families := map[string]*family{}
	var order []string
	get := func(name string) *family {
		f := families[name]
		if f == nil {
			f = &family{}
			families[name] = f
			order = append(order, name)
		}
		return f
	}
	for _, edge := range slices.Sorted(maps.Keys(byEdge)) {
		current := ""
		sc := bufio.NewScanner(bytes.NewReader(byEdge[edge]))
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
			case strings.HasPrefix(line, "# HELP "), strings.HasPrefix(line, "# TYPE "):
				current, _, _ = strings.Cut(line[len("# HELP "):], " ")
				if f := get(current); line[2] == 'H' && f.help == "" {
					f.help = line
				} else if line[2] == 'T' && f.typ == "" {
					f.typ = line
				}
			case strings.HasPrefix(line, "#"):
			default:
				name := current
				if name == "" {
					name = line[:strings.IndexAny(line+" ", "{ ")]
				}
				f := get(name)
				f.samples = append(f.samples, withEdge(line, edge))
			}
		}
	}
	for _, name := range order {
		f := families[name]
		for _, l := range []string{f.help, f.typ} {
			if l != "" {
				fmt.Fprintln(w, l)
			}
		}
		for _, l := range f.samples {
			fmt.Fprintln(w, l)
		}
	}
}

// withEdge puts edge="<name>" in front of a sample's labels.
func withEdge(sample, edge string) string {
	i := strings.IndexAny(sample, "{ ")
	if i < 0 {
		return sample
	}
	if sample[i] == '{' {
		sep := ","
		if strings.HasPrefix(sample[i+1:], "}") {
			sep = ""
		}
		return sample[:i+1] + `edge="` + edge + `"` + sep + sample[i+1:]
	}
	return sample[:i] + `{edge="` + edge + `"}` + sample[i:]
}
