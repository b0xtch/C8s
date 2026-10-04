package session

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// The captured quote's own TCB, read from its PCK certificate and TD report:
// FMSPC b0c06f000000, PCE SVN 11, CPU SVN components 3 3 2 2 4 1 0 5 0..., TEE
// TCB SVN 10 1 3 0... (TDX module version 1 at SVN 10), quoting enclave SVN 7.
var (
	fixtureCPUSVN = []int{3, 3, 2, 2, 4, 1, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0}
	fixtureTDXSVN = []int{10, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
)

type level struct {
	sgx, tdx   []int
	pcesvn     int
	isvsvn     int
	status     string
	advisories []string
}

func (l level) json() map[string]any {
	components := func(svns []int) []map[string]int {
		out := make([]map[string]int, 0, len(svns))
		for _, svn := range svns {
			out = append(out, map[string]int{"svn": svn})
		}
		return out
	}
	return map[string]any{
		"tcb": map[string]any{
			"sgxtcbcomponents": components(l.sgx), "tdxtcbcomponents": components(l.tdx),
			"pcesvn": l.pcesvn, "isvsvn": l.isvsvn,
		},
		"tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": l.status, "advisoryIDs": l.advisories,
	}
}

func levels(ls ...level) []map[string]any {
	out := make([]map[string]any, 0, len(ls))
	for _, l := range ls {
		out = append(out, l.json())
	}
	return out
}

// intelsModule is the TDX module as Intel's TCB info names it: no signer but
// Intel, and no attribute set.
var intelsModule = map[string]string{
	"mrsigner": strings.Repeat("00", 48), "attributes": "0000000000000000", "attributesMask": "FFFFFFFFFFFFFFFF",
}

func tcbInfo(t *testing.T, fmspc string, platform, module []level) []byte {
	t.Helper()
	return tcbInfoOf(t, fmspc, "0000", intelsModule, platform, module)
}

func tcbInfoOf(t *testing.T, fmspc, pceID string, tdxModule map[string]string, platform, module []level) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"tcbInfo": map[string]any{
		"id": "TDX", "version": 3, "fmspc": fmspc, "pceId": pceID, "tdxModule": tdxModule,
		"tcbLevels":           levels(platform...),
		"tdxModuleIdentities": []map[string]any{{"id": "TDX_01", "tcbLevels": levels(module...)}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// intelsQE is the TD quoting enclave as Intel's identity document names it.
var intelsQE = map[string]any{
	"miscselect": "00000000", "miscselectMask": "FFFFFFFF",
	"attributes": "11000000000000000000000000000000", "attributesMask": "FBFFFFFFFFFFFFFF0000000000000000",
	"mrsigner": "DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5", "isvprodid": 2,
}

func qeIdentity(t *testing.T, ls ...level) []byte {
	t.Helper()
	return qeIdentityOf(t, nil, ls...)
}

// qeIdentityOf is the identity document with some of its members changed.
func qeIdentityOf(t *testing.T, change map[string]any, ls ...level) []byte {
	t.Helper()
	identity := map[string]any{"id": "TD_QE", "version": 2, "tcbLevels": levels(ls...)}
	for name, value := range intelsQE {
		identity[name] = value
	}
	for name, value := range change {
		identity[name] = value
	}
	data, err := json.Marshal(map[string]any{"enclaveIdentity": identity})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func bumped(svns []int, index int) []int {
	out := slices.Clone(svns)
	out[index]++
	return out
}

func TestTCBEvaluation(t *testing.T) {
	env, _ := fixture(t)
	quote, _, err := parseTDQuote(env.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	zeros := make([]int, 16)
	current := level{sgx: fixtureCPUSVN, tdx: fixtureTDXSVN, pcesvn: 11, status: "UpToDate"}
	// A level the platform does not reach: one microcode component is higher.
	newer := level{sgx: bumped(fixtureCPUSVN, 0), tdx: fixtureTDXSVN, pcesvn: 11, status: "UpToDate"}
	floor := level{sgx: zeros, tdx: zeros, status: "OutOfDate", advisories: []string{"INTEL-SA-00999"}}
	moduleCurrent := level{isvsvn: 10, status: "UpToDate"}
	qeCurrent := level{isvsvn: 4, status: "UpToDate"}

	for name, tc := range map[string]struct {
		info, qe []byte
		want     TCBFinding
	}{
		"everything current": {
			tcbInfo(t, "B0C06F000000", []level{current, floor}, []level{moduleCurrent}), qeIdentity(t, qeCurrent),
			TCBFinding{Platform: "UpToDate", Module: "UpToDate", QuotingEnclave: "UpToDate"},
		},
		// The platform's level and the module's are judged apart: one that is
		// behind is reported as behind, whatever the other is.
		"microcode behind, module current": {
			tcbInfo(t, "b0c06f000000", []level{newer, floor}, []level{moduleCurrent}), qeIdentity(t, qeCurrent),
			TCBFinding{Platform: "OutOfDate", Module: "UpToDate", QuotingEnclave: "UpToDate", Advisories: []string{"INTEL-SA-00999"}},
		},
		"module behind, microcode current": {
			tcbInfo(t, "b0c06f000000", []level{current, floor},
				[]level{{isvsvn: 11, status: "UpToDate"}, {isvsvn: 2, status: "OutOfDate", advisories: []string{"INTEL-SA-00888"}}}),
			qeIdentity(t, qeCurrent),
			TCBFinding{Platform: "UpToDate", Module: "OutOfDate", QuotingEnclave: "UpToDate", Advisories: []string{"INTEL-SA-00888"}},
		},
		"quoting enclave behind": {
			tcbInfo(t, "b0c06f000000", []level{current, floor}, []level{moduleCurrent}),
			qeIdentity(t, level{isvsvn: 8, status: "UpToDate"}, level{isvsvn: 1, status: "OutOfDate"}),
			TCBFinding{Platform: "UpToDate", Module: "UpToDate", QuotingEnclave: "OutOfDate"},
		},
		// Components 0 and 1 of the TEE TCB SVN describe the module. A platform
		// level must not be missed because it lists a newer module there.
		"module components are left to the module's identity": {
			tcbInfo(t, "b0c06f000000", []level{{sgx: fixtureCPUSVN, tdx: bumped(fixtureTDXSVN, 0), pcesvn: 11, status: "UpToDate"}, floor}, []level{moduleCurrent}),
			qeIdentity(t, qeCurrent),
			TCBFinding{Platform: "UpToDate", Module: "UpToDate", QuotingEnclave: "UpToDate"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := evaluateTDXTCB(quote, tc.info, tc.qe)
			if err != nil {
				t.Fatal(err)
			}
			if got.Platform != tc.want.Platform || got.Module != tc.want.Module || got.QuotingEnclave != tc.want.QuotingEnclave || !slices.Equal(got.Advisories, tc.want.Advisories) {
				t.Fatalf("finding = %+v, want %+v", *got, tc.want)
			}
			allCurrent := tc.want.Platform == "UpToDate" && tc.want.Module == "UpToDate" && tc.want.QuotingEnclave == "UpToDate"
			if got.UpToDate() != allCurrent {
				t.Fatalf("UpToDate() = %v for %+v", got.UpToDate(), *got)
			}
		})
	}

	for name, tc := range map[string]struct {
		info, qe []byte
		want     string
	}{
		"collateral for another platform": {tcbInfo(t, "00906ed50000", []level{current}, []level{moduleCurrent}), qeIdentity(t, qeCurrent), "FMSPC"},
		"no platform level matches":       {tcbInfo(t, "b0c06f000000", []level{newer}, []level{moduleCurrent}), qeIdentity(t, qeCurrent), "matches no level"},
		"no module level matches":         {tcbInfo(t, "b0c06f000000", []level{current}, []level{{isvsvn: 11, status: "UpToDate"}}), qeIdentity(t, qeCurrent), "TDX module"},
		"no quoting enclave level":        {tcbInfo(t, "b0c06f000000", []level{current}, []level{moduleCurrent}), qeIdentity(t, level{isvsvn: 9, status: "UpToDate"}), "quoting enclave SVN"},
		"TCB info is not JSON":            {[]byte("<html>"), qeIdentity(t, qeCurrent), "TCB info"},
		// What the quote's body says of the TDX module is held to the TCB
		// info on every quote: the collateral pass that also checks it is
		// not run for each one.
		"collateral for another PCE": {
			tcbInfoOf(t, "b0c06f000000", "0001", intelsModule, []level{current}, []level{moduleCurrent}), qeIdentity(t, qeCurrent), "PCE",
		},
		"a TDX module of another signer": {
			tcbInfoOf(t, "b0c06f000000", "0000", map[string]string{
				"mrsigner": "01" + strings.Repeat("00", 47), "attributes": "0000000000000000", "attributesMask": "FFFFFFFFFFFFFFFF",
			}, []level{current}, []level{moduleCurrent}), qeIdentity(t, qeCurrent), "TDX module's signer",
		},
		"TDX module attributes the TCB info does not name": {
			tcbInfoOf(t, "b0c06f000000", "0000", map[string]string{
				"mrsigner": strings.Repeat("00", 48), "attributes": "0000000000000001", "attributesMask": "FFFFFFFFFFFFFFFF",
			}, []level{current}, []level{moduleCurrent}), qeIdentity(t, qeCurrent), "TDX module's attributes",
		},
		"a mask of another length": {
			tcbInfoOf(t, "b0c06f000000", "0000", map[string]string{
				"mrsigner": strings.Repeat("00", 48), "attributes": "00", "attributesMask": "FF",
			}, []level{current}, []level{moduleCurrent}), qeIdentity(t, qeCurrent), "mask",
		},
		// And the quoting enclave's report to Intel's identity document.
		"a quoting enclave of another signer": {
			tcbInfo(t, "b0c06f000000", []level{current}, []level{moduleCurrent}),
			qeIdentityOf(t, map[string]any{"mrsigner": strings.Repeat("AB", 32)}, qeCurrent), "quoting enclave's signer",
		},
		"another product of that signer": {
			tcbInfo(t, "b0c06f000000", []level{current}, []level{moduleCurrent}),
			qeIdentityOf(t, map[string]any{"isvprodid": 1}, qeCurrent), "product",
		},
		"a MISCSELECT the document does not name": {
			tcbInfo(t, "b0c06f000000", []level{current}, []level{moduleCurrent}),
			qeIdentityOf(t, map[string]any{"miscselect": "01000000"}, qeCurrent), "MISCSELECT",
		},
		"attributes the document does not name": {
			tcbInfo(t, "b0c06f000000", []level{current}, []level{moduleCurrent}),
			qeIdentityOf(t, map[string]any{"attributes": "13000000000000000000000000000000"}, qeCurrent), "quoting enclave's attributes",
		},
		"an identity document with no masks": {
			tcbInfo(t, "b0c06f000000", []level{current}, []level{moduleCurrent}),
			qeIdentityOf(t, map[string]any{"miscselectMask": ""}, qeCurrent), "four-byte",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := evaluateTDXTCB(quote, tc.info, tc.qe)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error mentioning %q, got %+v, %v", tc.want, got, err)
			}
		})
	}
}
