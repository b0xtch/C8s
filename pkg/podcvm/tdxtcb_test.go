package podcvm

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

func tcbInfo(t *testing.T, fmspc string, platform, module []level) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"tcbInfo": map[string]any{
		"id": "TDX", "version": 3, "fmspc": fmspc, "pceId": "0000",
		"tcbLevels":           levels(platform...),
		"tdxModuleIdentities": []map[string]any{{"id": "TDX_01", "tcbLevels": levels(module...)}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func qeIdentity(t *testing.T, ls ...level) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"enclaveIdentity": map[string]any{"id": "TD_QE", "version": 2, "tcbLevels": levels(ls...)}})
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
	quote, err := parseTDQuote(env.Evidence)
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
		// The case the pinned go-tdx-guest reports as UpToDate: it returns the
		// module's level alone once the report names a module version.
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
	} {
		t.Run(name, func(t *testing.T) {
			got, err := evaluateTDXTCB(quote, tc.info, tc.qe)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error mentioning %q, got %+v, %v", tc.want, got, err)
			}
		})
	}
}

func TestEngineOptions(t *testing.T) {
	for name, opts := range map[string]EngineOptions{
		"unknown mode":            {Collateral: "lenient"},
		"accepting Revoked":       {Collateral: CollateralRequired, AcceptTCBStatus: []string{"Revoked"}},
		"accepting a made-up one": {Collateral: CollateralRequired, AcceptTCBStatus: []string{"Fine"}},
		"accepting without proof": {Collateral: CollateralSkip, AcceptTCBStatus: []string{"OutOfDate"}},
	} {
		if engine, err := NewEngine(opts); err == nil {
			t.Errorf("%s: accepted (%+v)", name, engine)
		}
	}
	if _, err := NewEngine(EngineOptions{Collateral: CollateralRequired, AcceptTCBStatus: []string{"OutOfDate", "SWHardeningNeeded"}}); err != nil {
		t.Fatal(err)
	}
}
