package fiscobcos

import "testing"

func TestClassifyReceiptStatusPinnedV3163(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status int
		want   ReceiptStatusDisposition
	}{
		{status: ReceiptStatusOK, want: ReceiptStatusSucceeded},
		{status: 1, want: ReceiptStatusAmbiguous},
		{status: int(ReceiptStatusCodeBlockLimit), want: ReceiptStatusBlockLimit},
		{status: ReceiptStatusTransactionPoolFull, want: ReceiptStatusRetryable},
		{status: ReceiptStatusPoolTimeout, want: ReceiptStatusAmbiguous},
		{status: ReceiptStatusNonceCheckFailed, want: ReceiptStatusDuplicate},
		{status: ReceiptStatusAlreadyInPool, want: ReceiptStatusDuplicate},
		{status: ReceiptStatusAlreadyInChain, want: ReceiptStatusDuplicate},
		{status: ReceiptStatusAlreadyInPoolAccept, want: ReceiptStatusDuplicate},
		{status: 10012, want: ReceiptStatusPermanent},
		{status: 10013, want: ReceiptStatusPermanent},
		{status: 10014, want: ReceiptStatusPermanent},
		{status: 10015, want: ReceiptStatusPermanent},
		{status: 99999, want: ReceiptStatusAmbiguous},
	}
	for _, test := range tests {
		if got := ClassifyReceiptStatus(test.status); got != test.want {
			t.Errorf("ClassifyReceiptStatus(%d)=%q, want %q", test.status, got, test.want)
		}
	}
}

func TestAttemptJournalAcceptsRecoverableSubmissionForDeterministicLookup(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		status int64
	}{
		{name: "nonce duplicate", status: ReceiptStatusNonceCheckFailed},
		{name: "pool timeout", status: ReceiptStatusPoolTimeout},
		{name: "unknown response", status: 10099},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			_, _, prepared := testAttemptJournal(t)
			recoverable := cloneAttemptJournal(t, prepared)
			recoverable.Revision++
			recoverable.Attempts[0].Outcome = AttemptOutcomeSubmitUnknown
			recoverable.Attempts[0].Submission = &SubmissionObservation{
				Status:          test.status,
				StatusMessage:   "recoverable_response",
				ObservedAtUnixN: 2,
			}
			if err := ValidateAttemptJournalTransition(prepared, recoverable); err != nil {
				t.Fatalf("prepared -> recoverable response: %v", err)
			}
		})
	}
}
