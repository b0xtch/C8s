package session

import (
	"bytes"
	"encoding/json"
	"testing"
)

func decodeTree(t *testing.T, in string) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(in)))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		t.Fatal(err)
	}
	return tree
}

// The string and member-order examples of RFC 8785, sections 3.2.2 and 3.2.3.
func TestCanonicalJSONFollowsRFC8785(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"string escapes": {
			`{"string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/"}`,
			`{"string":"€$\u000f\nA'B\"\\\\\"/"}`,
		},
		// U+1F600 sorts before U+FB33 by UTF-16 code unit and after it by code
		// point: the RFC's own trap.
		"members sort by UTF-16 code units": {
			`{"\u20ac": 1, "\r": 2, "\ufb33": 3, "1": 4, "\ud83d\ude00": 5, "\u0080": 6, "\u00f6": 7}`,
			"{\"\\r\":2,\"1\":4,\"\u0080\":6,\"\u00f6\":7,\"\u20ac\":1,\"\U0001F600\":5,\"\ufb33\":3}",
		},
		"nesting, whitespace and literals": {
			"{ \"b\" : [ true , false , { \"z\" : 0 , \"a\" : \"x\" } ] ,\n \"a\" : 9007199254740991 }",
			`{"a":9007199254740991,"b":[true,false,{"a":"x","z":0}]}`,
		},
		"html characters stay as they are": {`{"k": "<a href=\"x\">&</a>"}`, `{"k":"<a href=\"x\">&</a>"}`},
	} {
		got, err := canonicalJSON(decodeTree(t, tc.in))
		if err != nil || string(got) != tc.want {
			t.Errorf("%s:\n got %s (%v)\nwant %s", name, got, err, tc.want)
		}
	}
}

func TestCanonicalJSONRefusesWhatItCannotRender(t *testing.T) {
	for name, in := range map[string]string{
		"a fraction":           `{"n": 1.5}`,
		"an exponent":          `{"n": 1e3}`,
		"a negative number":    `{"n": -1}`,
		"an integer past 2^53": `{"n": 9007199254740992}`,
		"a leading zero form":  `{"n": 1.0}`,
		"null":                 `{"n": null}`,
	} {
		if got, err := canonicalJSON(decodeTree(t, in)); err == nil {
			t.Errorf("%s was rendered as %s", name, got)
		}
	}
}
