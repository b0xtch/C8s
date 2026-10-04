package session

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// BindSchemaFormat names the format of the published bind schema.
const BindSchemaFormat = "c8s-bind-schema/v1"

// BindPurposes are the purposes of a bind this build's agent takes.
var BindPurposes = []string{PurposeStart}

// BindMember is one member of a bind, or of an object inside one.
type BindMember struct {
	Name string `json:"name,omitempty"`
	// Type is string, integer, flag, list, map or object.
	Type string `json:"type"`
	// Optional members may be absent.
	Optional bool `json:"optional,omitempty"`
	// Item is what a list or a map holds.
	Item *BindMember `json:"item,omitempty"`
	// Members are an object's.
	Members []BindMember `json:"members,omitempty"`
}

// BindSchema is the bind this build's agent takes, as a document: every
// member it knows, read from the definitions it decodes a bind with, and the
// purposes it accepts. An agent refuses a bind with any other member, so this
// is the whole of what an owner can ask of a guest of this image. The image
// build puts it on the image's verity root and publishes it with the image's
// reference values.
func BindSchema() []byte {
	doc, err := json.MarshalIndent(struct {
		SchemaVersion string       `json:"schemaVersion"`
		Bind          string       `json:"bind"`
		Purposes      []string     `json:"purposes"`
		Members       []BindMember `json:"members"`
	}{BindSchemaFormat, BindSchemaVersion, BindPurposes, bindMembers(reflect.TypeFor[Bind]())}, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(doc, '\n')
}

// bindMembers lists the members the decoder takes for a struct: the ones its
// JSON tags name.
func bindMembers(t reflect.Type) []BindMember {
	var members []BindMember
	for i := range t.NumField() {
		field := t.Field(i)
		name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
		// Every member of a bind has a name on the wire that its definition
		// states. One without would be decoded under its Go name, in any case.
		if !field.IsExported() || name == "" || name == "-" {
			panic(fmt.Sprintf("bind member %s.%s states no name", t.Name(), field.Name))
		}
		member := bindType(field.Type)
		member.Name = name
		member.Optional = strings.Contains(options, "omitempty")
		members = append(members, member)
	}
	return members
}

func bindType(t reflect.Type) BindMember {
	switch t.Kind() {
	case reflect.Pointer:
		return bindType(t.Elem())
	case reflect.String:
		return BindMember{Type: "string"}
	case reflect.Bool:
		return BindMember{Type: "flag"}
	case reflect.Int, reflect.Int32, reflect.Int64, reflect.Uint32, reflect.Uint64:
		return BindMember{Type: "integer"}
	case reflect.Slice:
		item := bindType(t.Elem())
		return BindMember{Type: "list", Item: &item}
	case reflect.Map:
		item := bindType(t.Elem())
		return BindMember{Type: "map", Item: &item}
	case reflect.Struct:
		return BindMember{Type: "object", Members: bindMembers(t)}
	}
	panic(fmt.Sprintf("a bind holds a %s, which its schema has no word for", t.Kind()))
}
