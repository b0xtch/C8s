package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// canonicalJSON renders a decoded JSON tree in the canonical form of RFC 8785:
// no whitespace, object members sorted by their names' UTF-16 code units,
// strings escaped as ECMAScript's JSON.stringify escapes them. A browser that
// parses the bytes and serializes them again gets the same bytes back.
//
// The tree comes from a decoder with UseNumber. Numbers are limited to the
// non-negative integers a double holds exactly, which is every number a bind
// document carries, so no floating-point formatting is involved. Null has no
// place in one either.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch v := v.(type) {
	case map[string]any:
		names := make([]string, 0, len(v))
		for name := range v {
			names = append(names, name)
		}
		slices.SortFunc(names, func(a, b string) int {
			return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
		})
		buf.WriteByte('{')
		for i, name := range names {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalString(buf, name); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, v[name]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case string:
		return writeCanonicalString(buf, v)
	case json.Number:
		n, err := strconv.ParseUint(v.String(), 10, 64)
		if err != nil || n >= 1<<53 || strconv.FormatUint(n, 10) != v.String() {
			return fmt.Errorf("number %s is not a plain non-negative integer below 2^53", v)
		}
		buf.WriteString(v.String())
	case bool:
		buf.WriteString(strconv.FormatBool(v))
	default:
		return fmt.Errorf("value of type %T has no canonical form here", v)
	}
	return nil
}

func writeCanonicalString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("string is not valid UTF-8")
	}
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}
