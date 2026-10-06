package session

import (
	"encoding/json"
	"reflect"
)

// RehearseDocuments has the JSON encoder and decoder make now what they make
// for a type the first time they meet it, for every document a bind and its
// first command pass through and for more, with every type those are made
// of. A bind is every guest's first, so without this every start pays for
// them. It encodes and decodes empty documents only: nothing of a bind, and
// nothing a bind could find.
func RehearseDocuments(more ...any) {
	documents := append([]any{
		&BindRequest{}, &Bind{}, &SignedBind{}, &BindResponse{}, &BindReceipt{}, &SignedReceipt{},
		&SealedRequest{}, &sealedPlain{}, &sealedAnswer{}, &SealedAnswer{},
		&ExecRequest{}, &ExecResponse{}, &CredentialRequest{},
		&AttestRequest{}, &AttestResponse{}, &StateResponse{},
	}, more...)
	seen := map[reflect.Type]bool{}
	var rehearse func(reflect.Type)
	rehearse = func(t reflect.Type) {
		if seen[t] {
			return
		}
		seen[t] = true
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			rehearse(t.Elem())
		case reflect.Map:
			rehearse(t.Key())
			rehearse(t.Elem())
		case reflect.Struct:
			empty := reflect.New(t).Interface()
			// An empty document of a type may be none the type takes: what
			// counts is that the type was met.
			_, _ = json.Marshal(empty)
			_ = json.Unmarshal([]byte("{}"), empty)
			for i := range t.NumField() {
				if field := t.Field(i); field.IsExported() {
					rehearse(field.Type)
				}
			}
		}
	}
	for _, document := range documents {
		rehearse(reflect.TypeOf(document))
	}
}
