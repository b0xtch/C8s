package daemon

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"
)

// A binder signs for another TD on one answer alone: the daemon's word that
// no ready TD holds the key its bind names. Any other refusal of a bind,
// whatever its code, is none to sign again on.
func TestNotReadyIsOneAnswerAlone(t *testing.T) {
	with := func(code codes.Code, details ...protoadapt.MessageV1) error {
		t.Helper()
		st, err := status.New(code, "refused").WithDetails(details...)
		if err != nil {
			t.Fatal(err)
		}
		return st.Err()
	}
	gone := &errdetails.ErrorInfo{Reason: "TD_NOT_READY", Domain: "sessions.c8s"}
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"the daemon's answer":             {with(codes.FailedPrecondition, gone), true},
		"that answer, wrapped":            {fmt.Errorf("bind: %w", with(codes.FailedPrecondition, gone)), true},
		"that answer among other details": {with(codes.FailedPrecondition, &errdetails.RetryInfo{}, gone), true},
		"another reason":                  {with(codes.FailedPrecondition, &errdetails.ErrorInfo{Reason: "TD_ENDED", Domain: "sessions.c8s"}), false},
		"the reason in another domain":    {with(codes.FailedPrecondition, &errdetails.ErrorInfo{Reason: "TD_NOT_READY", Domain: "example.com"}), false},
		"the same code with no reason":    {status.Error(codes.FailedPrecondition, "the TD is ready, not claimed"), false},
		"a detail of another kind":        {with(codes.ResourceExhausted, &errdetails.RetryInfo{}), false},
		"an error that is no status":      {errors.New("TD_NOT_READY"), false},
		"no error":                        {nil, false},
	} {
		if got := NotReady(tc.err); got != tc.want {
			t.Errorf("%s: NotReady = %v, want %v", name, got, tc.want)
		}
	}
}
