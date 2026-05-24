package config

// This file implements a small, dependency-free parser for the subset of YAML
// guardian's config uses: nested mappings, block sequences of scalars, inline
// flow sequences ([a, b, c]), and scalar values. It deliberately does NOT aim
// to be a general YAML implementation; it accepts the shapes documented in
// guardian.yaml and rejects anything it does not understand.
//
// Supported:
//   key: value                      scalar
//   key:                            nested mapping (indented children)
//     child: value
//   list:                           block sequence
//     - a
//     - b
//   list: [a, b, c]                 inline flow sequence
//   # comment                       full-line and trailing comments
//   "quoted" / 'quoted' scalars
//
// Not supported (and rejected if encountered): anchors, tags, multi-line
// scalars, multi-document streams, sequences of mappings.

import (
	"fmt"
	"strconv"
	"strings"
)

// yamlNode is the parsed representation: exactly one of the fields is set.
type yamlNode struct {
	scalar   string
	hasValue bool
	mapping  map[string]*yamlNode
	sequence []string
}

func (n *yamlNode) isMapping() bool  { return n.mapping != nil }
func (n *yamlNode) isSequence() bool { return n.sequence != nil }

// parseYAML parses the supported subset into a root mapping node.
func parseYAML(src string) (*yamlNode, error) {
	lines := splitLines(src)
	p := &yamlParser{lines: lines}
	root := &yamlNode{mapping: map[string]*yamlNode{}}
	if err := p.parseBlock(root, 0); err != nil {
		return nil, err
	}
	if p.pos != len(p.lines) {
		return nil, fmt.Errorf("yaml: unexpected content at line %d", p.lines[p.pos].num)
	}
	return root, nil
}

type srcLine struct {
	num    int
	indent int
	text   string // content after indentation, comments stripped
}

type yamlParser struct {
	lines []srcLine
	pos   int
}

// splitLines tokenises source into significant lines (blank/comment lines are
// dropped) recording each line's indentation and comment-stripped content.
func splitLines(src string) []srcLine {
	var out []srcLine
	for i, raw := range strings.Split(src, "\n") {
		line := strings.TrimRight(raw, "\r")
		// Compute indent from leading spaces (tabs are disallowed in YAML).
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		content := stripComment(line[indent:])
		content = strings.TrimRight(content, " ")
		if content == "" {
			continue
		}
		out = append(out, srcLine{num: i + 1, indent: indent, text: content})
	}
	return out
}

// stripComment removes a trailing/full-line comment, respecting quotes.
func stripComment(s string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				// Comment must be at start or preceded by whitespace.
				if i == 0 || s[i-1] == ' ' {
					return s[:i]
				}
			}
		}
	}
	return s
}

// parseBlock parses a mapping at the given indentation into node.mapping.
func (p *yamlParser) parseBlock(node *yamlNode, indent int) error {
	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		if line.indent < indent {
			return nil
		}
		if line.indent > indent {
			return fmt.Errorf("yaml: unexpected indentation at line %d", line.num)
		}
		if strings.HasPrefix(line.text, "- ") || line.text == "-" {
			return fmt.Errorf("yaml: unexpected sequence item at line %d", line.num)
		}

		key, rest, ok := splitKey(line.text)
		if !ok {
			return fmt.Errorf("yaml: expected 'key:' at line %d: %q", line.num, line.text)
		}
		p.pos++

		if rest != "" {
			// Inline value (scalar or flow sequence).
			child, err := parseInline(rest, line.num)
			if err != nil {
				return err
			}
			node.mapping[key] = child
			continue
		}

		// Block child: either a nested mapping or a block sequence.
		child, err := p.parseChild(indent)
		if err != nil {
			return err
		}
		node.mapping[key] = child
	}
	return nil
}

// parseChild parses whatever follows a "key:" line with no inline value.
func (p *yamlParser) parseChild(parentIndent int) (*yamlNode, error) {
	if p.pos >= len(p.lines) {
		// "key:" with nothing after it -> empty/null value.
		return &yamlNode{hasValue: false}, nil
	}
	next := p.lines[p.pos]
	if next.indent <= parentIndent {
		return &yamlNode{hasValue: false}, nil
	}
	if strings.HasPrefix(next.text, "- ") || next.text == "-" {
		return p.parseSequence(next.indent)
	}
	child := &yamlNode{mapping: map[string]*yamlNode{}}
	if err := p.parseBlock(child, next.indent); err != nil {
		return nil, err
	}
	return child, nil
}

// parseSequence parses a block sequence of scalars at the given indent.
func (p *yamlParser) parseSequence(indent int) (*yamlNode, error) {
	node := &yamlNode{sequence: []string{}}
	for p.pos < len(p.lines) {
		line := p.lines[p.pos]
		if line.indent != indent {
			if line.indent < indent {
				break
			}
			return nil, fmt.Errorf("yaml: bad sequence indentation at line %d", line.num)
		}
		if !strings.HasPrefix(line.text, "- ") && line.text != "-" {
			break
		}
		item := strings.TrimSpace(strings.TrimPrefix(line.text, "-"))
		if item == "" {
			return nil, fmt.Errorf("yaml: empty sequence item at line %d", line.num)
		}
		if strings.Contains(item, ":") && !isQuoted(item) {
			return nil, fmt.Errorf("yaml: sequences of mappings are unsupported (line %d)", line.num)
		}
		node.sequence = append(node.sequence, unquote(item))
		p.pos++
	}
	return node, nil
}

// splitKey splits "key: rest" returning key and the (possibly empty) rest.
func splitKey(s string) (key, rest string, ok bool) {
	// Find the first unquoted colon.
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case ':':
			if !inSingle && !inDouble {
				if i+1 < len(s) && s[i+1] != ' ' {
					continue // part of value, e.g. URL scheme without space
				}
				key = strings.TrimSpace(s[:i])
				rest = strings.TrimSpace(s[i+1:])
				return unquote(key), rest, key != ""
			}
		}
	}
	return "", "", false
}

// parseInline parses an inline scalar or flow sequence value.
func parseInline(s string, lineNum int) (*yamlNode, error) {
	if strings.HasPrefix(s, "[") {
		if !strings.HasSuffix(s, "]") {
			return nil, fmt.Errorf("yaml: unterminated flow sequence at line %d", lineNum)
		}
		inner := strings.TrimSpace(s[1 : len(s)-1])
		node := &yamlNode{sequence: []string{}}
		if inner == "" {
			return node, nil
		}
		for _, part := range strings.Split(inner, ",") {
			part = strings.TrimSpace(part)
			node.sequence = append(node.sequence, unquote(part))
		}
		return node, nil
	}
	if strings.HasPrefix(s, "{") {
		return nil, fmt.Errorf("yaml: flow mappings are unsupported (line %d)", lineNum)
	}
	return &yamlNode{scalar: unquote(s), hasValue: true}, nil
}

func isQuoted(s string) bool {
	return len(s) >= 2 &&
		((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\''))
}

// unquote removes surrounding quotes and unescapes a double-quoted scalar.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if uq, err := strconv.Unquote(s); err == nil {
			return uq
		}
		return s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	return s
}
