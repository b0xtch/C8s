package imagestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/containerd/containerd/v2/core/images"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// documentType is the type a document of that media type is read into.
func documentType(mediaType string) reflect.Type {
	switch {
	case images.IsIndexType(mediaType):
		return reflect.TypeFor[ocispec.Index]()
	case images.IsManifestType(mediaType):
		return reflect.TypeFor[ocispec.Manifest]()
	case images.IsConfigType(mediaType):
		return reflect.TypeFor[ocispec.Image]()
	}
	return nil
}

// exactMembers refuses a JSON document that two readers could take
// differently. The readers here are Go's: they match a member to a field
// whatever the case of its name, and of two members with one name they take
// the last. A reader that matches names exactly, or takes the first, would
// see another image under the same digest. So no object holds a name twice,
// and where an object is read into a struct, no name twice under any
// capitalization, and a member that names a field is spelled as the field is.
//
// into is the type the document is read into, or nil for a document read into
// none: then only names held twice are refused.
func exactMembers(data []byte, into reflect.Type) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := exactValue(dec, into, "the document"); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("the document is followed by more")
	}
	return nil
}

func exactValue(dec *json.Decoder, into reflect.Type, where string) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	for into != nil && into.Kind() == reflect.Pointer {
		into = into.Elem()
	}
	switch token {
	case json.Delim('{'):
		return exactObject(dec, into, where)
	case json.Delim('['):
		var element reflect.Type
		if into != nil && (into.Kind() == reflect.Slice || into.Kind() == reflect.Array) {
			element = into.Elem()
		}
		for i := 0; dec.More(); i++ {
			if err := exactValue(dec, element, fmt.Sprintf("%s[%d]", where, i)); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	}
	return nil
}

func exactObject(dec *json.Decoder, into reflect.Type, where string) error {
	// Nil for an object that is read into a map or into nothing.
	var fields map[string]reflect.Type
	if into != nil && into.Kind() == reflect.Struct {
		fields = map[string]reflect.Type{}
		memberTypes(into, fields)
	}
	var seen []string
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		name, _ := token.(string)
		for _, earlier := range seen {
			// A map's keys are data, told apart by their case as well.
			if earlier == name || (fields != nil && strings.EqualFold(earlier, name)) {
				return fmt.Errorf("%s holds the member %q twice (%q)", where, name, earlier)
			}
		}
		seen = append(seen, name)
		var next reflect.Type
		for field, fieldType := range fields {
			if strings.EqualFold(field, name) {
				if field != name {
					return fmt.Errorf("%s holds a member %q, which is read as %q", where, name, field)
				}
				next = fieldType
			}
		}
		if err := exactValue(dec, next, where+"."+name); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

// memberTypes lists the members a struct is read from, by the names their
// fields are tagged with, as encoding/json takes them: an embedded struct
// without a name of its own gives its fields to the struct that embeds it.
func memberTypes(t reflect.Type, into map[string]reflect.Type) {
	for i := range t.NumField() {
		field := t.Field(i)
		tag, tagged := field.Tag.Lookup("json")
		// A field tagged "-" keeps that for a name, which no member has in
		// another case.
		name, _, _ := strings.Cut(tag, ",")
		embedded := field.Type
		for embedded.Kind() == reflect.Pointer {
			embedded = embedded.Elem()
		}
		if field.Anonymous && (!tagged || name == "") && embedded.Kind() == reflect.Struct {
			memberTypes(embedded, into)
			continue
		}
		// The decoder reads into an embedded struct even if its type has no
		// exported name.
		if !field.IsExported() && (!field.Anonymous || embedded.Kind() != reflect.Struct) {
			continue
		}
		if name == "" {
			name = field.Name
		}
		into[name] = field.Type
	}
}
