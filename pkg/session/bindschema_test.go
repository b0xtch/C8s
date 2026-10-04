package session_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/session"
)

var update = flag.Bool("update", false, "rewrite testdata/bind-schema.json from the definitions")

// The published bind schema is a file in the repository, so a change to what
// an agent takes shows up as a change to that file.
func TestBindSchemaIsThePublishedOne(t *testing.T) {
	const path = "testdata/bind-schema.json"
	got := session.BindSchema()
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the bind schema is not %s: run go test ./pkg/session -run TestBindSchemaIsThePublishedOne -update, and review what an agent now takes\n%s", path, got)
	}
	if !bytes.Equal(got, session.BindSchema()) {
		t.Fatal("two renderings of the schema differ")
	}
}

type bindSchema struct {
	SchemaVersion string
	Bind          string
	Purposes      []string
	Members       []session.BindMember
}

func parseBindSchema(t *testing.T) bindSchema {
	t.Helper()
	var schema bindSchema
	dec := json.NewDecoder(bytes.NewReader(session.BindSchema()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&schema); err != nil {
		t.Fatal(err)
	}
	if schema.SchemaVersion != session.BindSchemaFormat || schema.Bind != session.BindSchemaVersion {
		t.Fatalf("the schema is %q for binds of %q", schema.SchemaVersion, schema.Bind)
	}
	return schema
}

// fill sets every member of v, however deep, to something that is not its
// zero value, so that nothing is left out of its rendering.
func fill(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fill(v.Elem())
	case reflect.Struct:
		for i := range v.NumField() {
			fill(v.Field(i))
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fill(v.Index(0))
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
		key, value := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		fill(key)
		fill(value)
		v.SetMapIndex(key, value)
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	}
}

// same holds a rendered value to the members the schema lists for it: every
// member rendered is listed, with its type, and every member listed is
// rendered.
func same(t *testing.T, at string, members []session.BindMember, rendered map[string]any) {
	t.Helper()
	for name := range rendered {
		if !slices.ContainsFunc(members, func(m session.BindMember) bool { return m.Name == name }) {
			t.Errorf("%s: a bind carries %q, which the schema does not list", at, name)
		}
	}
	for _, member := range members {
		value, ok := rendered[member.Name]
		if !ok {
			t.Errorf("%s: the schema lists %q, which a bind does not carry", at, member.Name)
			continue
		}
		sameType(t, at+"."+member.Name, &member, value)
	}
}

func sameType(t *testing.T, at string, member *session.BindMember, value any) {
	t.Helper()
	switch v := value.(type) {
	case string:
		if member.Type != "string" {
			t.Errorf("%s: a string, listed as %s", at, member.Type)
		}
	case bool:
		if member.Type != "flag" {
			t.Errorf("%s: a flag, listed as %s", at, member.Type)
		}
	case json.Number:
		if member.Type != "integer" {
			t.Errorf("%s: a number, listed as %s", at, member.Type)
		}
	case []any:
		if member.Type != "list" || member.Item == nil || len(v) != 1 {
			t.Fatalf("%s: a list of %d, listed as %s", at, len(v), member.Type)
		}
		sameType(t, at+"[]", member.Item, v[0])
	case map[string]any:
		switch member.Type {
		case "object":
			same(t, at, member.Members, v)
		case "map":
			if member.Item == nil || len(v) != 1 {
				t.Fatalf("%s: a map of %d with no item listed", at, len(v))
			}
			for _, item := range v {
				sameType(t, at+"{}", member.Item, item)
			}
		default:
			t.Errorf("%s: an object, listed as %s", at, member.Type)
		}
	default:
		t.Errorf("%s: a %T, which the schema has no word for", at, value)
	}
}

// The schema is read from the definitions a bind is decoded with. This holds
// it to what the encoder does with those definitions: a bind with every
// member set renders exactly the members the schema lists, each of the type
// it lists.
func TestBindSchemaListsWhatABindCarries(t *testing.T) {
	schema := parseBindSchema(t)
	var full session.Bind
	fill(reflect.ValueOf(&full).Elem())
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var rendered map[string]any
	if err := dec.Decode(&rendered); err != nil {
		t.Fatal(err)
	}
	same(t, "bind", schema.Members, rendered)

	// A member that omitempty leaves out when it is empty is one the schema
	// calls optional, and no other.
	empty, err := json.Marshal(session.Bind{})
	if err != nil {
		t.Fatal(err)
	}
	var bare map[string]any
	if err := json.Unmarshal(empty, &bare); err != nil {
		t.Fatal(err)
	}
	for _, member := range schema.Members {
		if _, kept := bare[member.Name]; kept == member.Optional {
			t.Errorf("bind.%s: optional is %v, and an empty bind renders it: %v", member.Name, member.Optional, kept)
		}
	}
}

// objectsOf lists where the schema has an object: each as the steps to it
// from the bind, a member's name, "[]" into a list or "{}" into a map.
func objectsOf(members []session.BindMember, at []string) [][]string {
	objects := [][]string{at}
	var into func(member *session.BindMember, at []string)
	into = func(member *session.BindMember, at []string) {
		switch member.Type {
		case "object":
			objects = append(objects, objectsOf(member.Members, at)...)
		case "list":
			into(member.Item, append(slices.Clone(at), "[]"))
		case "map":
			into(member.Item, append(slices.Clone(at), "{}"))
		}
	}
	for i := range members {
		into(&members[i], append(slices.Clone(at), members[i].Name))
	}
	return objects
}

// An agent refuses a bind with a member its schema does not list, wherever
// the member sits.
func TestBindWithAMemberOutsideTheSchemaIsRefused(t *testing.T) {
	var full session.Bind
	fill(reflect.ValueOf(&full).Elem())
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	objects := objectsOf(parseBindSchema(t).Members, nil)
	// The bind itself, its policy and the areas under it, its key service.
	if len(objects) < 8 {
		t.Fatalf("the schema has %d objects: %v", len(objects), objects)
	}
	for _, steps := range objects {
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		target := doc
		for _, step := range steps {
			switch v := target.(type) {
			case map[string]any:
				if step == "{}" {
					for _, item := range v {
						target = item
					}
				} else {
					target = v[step]
				}
			case []any:
				target = v[0]
			}
		}
		object, ok := target.(map[string]any)
		if !ok {
			t.Fatalf("the schema has an object at %v, and a full bind has a %T there", steps, target)
		}
		object["unlisted"] = "x"
		changed, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.ParseBind(changed); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Errorf("a bind with an unlisted member at %v: %v", steps, err)
		}
	}
}

// The purposes the schema publishes are the ones a bind is validated against.
func TestBindSchemaPurposes(t *testing.T) {
	schema := parseBindSchema(t)
	if !slices.Equal(schema.Purposes, session.BindPurposes) || !slices.Contains(schema.Purposes, session.PurposeStart) {
		t.Fatalf("the schema's purposes are %v", schema.Purposes)
	}
	signed, err := session.NewBind(bindOptions(t, newKey(t), newKey(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, purpose := range append(slices.Clone(schema.Purposes), "restore", "fork", "") {
		bind := *signed.Doc
		bind.Purpose = purpose
		err := bind.Validate()
		if listed := slices.Contains(schema.Purposes, purpose); (err == nil) != listed {
			t.Errorf("purpose %q, listed %v: %v", purpose, listed, err)
		}
	}
}
