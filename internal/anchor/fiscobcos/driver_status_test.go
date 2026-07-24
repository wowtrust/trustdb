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

func TestAttemptJournalAcceptsNonceDuplicateForDeterministicLookup(t *testing.T) {
	t.Parallel()

	_, _, prepared := testAttemptJournal(t)
	duplicate := cloneAttemptJournal(t, prepared)
	duplicate.Revision++
	duplicate.Attempts[0].Outcome = AttemptOutcomeSubmitUnknown
	duplicate.Attempts[0].Submission = &SubmissionObservation{
		Status:          ReceiptStatusNonceCheckFailed,
		StatusMessage:   "nonce_check_fail",
		ObservedAtUnixN: 2,
	}
	if err := ValidateAttemptJournalTransition(prepared, duplicate); err != nil {
		t.Fatalf("prepared -> nonce duplicate: %v", err)
	}
}
