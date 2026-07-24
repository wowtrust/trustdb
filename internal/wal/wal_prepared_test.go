package wal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/model"
)

func TestAppendPreparedAtDoesNotPersistWhenPreparationFails(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "000000000001.wal")
	writer, err := OpenWriter(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	wantErr := errors.New("signer unavailable")
	var failedPosition model.WALPosition
	if _, _, err := writer.AppendPreparedAt(context.Background(), []byte("claim"), time.Unix(100, 0), func(_ context.Context, position model.WALPosition) error {
		failedPosition = position
		return wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("AppendPreparedAt() error = %v, want signer error", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("WAL size after failed preparation = %d, want 0", info.Size())
	}

	var retriedPosition model.WALPosition
	position, _, err := writer.AppendPreparedAt(context.Background(), []byte("claim"), time.Unix(100, 0), func(_ context.Context, position model.WALPosition) error {
		retriedPosition = position
		return nil
	})
	if err != nil {
		t.Fatalf("AppendPreparedAt() retry error = %v", err)
	}
	if failedPosition != retriedPosition || position != retriedPosition {
		t.Fatalf("positions failed=%+v retried=%+v appended=%+v", failedPosition, retriedPosition, position)
	}
	if position.Sequence != 1 || position.SegmentID != 1 || position.Offset != 0 {
		t.Fatalf("first appended position = %+v", position)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || string(records[0].Payload) != "claim" {
		t.Fatalf("records after retry = %+v", records)
	}
}

func TestAppendPreparedAtReservesFIFOWhilePreparingConcurrently(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "000000000001.wal")
	writer, err := OpenWriter(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	type appendResult struct {
		position model.WALPosition
		err      error
	}
	firstSeen := make(chan model.WALPosition, 1)
	firstRelease := make(chan struct{})
	firstDone := make(chan appendResult, 1)
	var firstCalls atomic.Int32
	go func() {
		position, _, appendErr := writer.AppendPreparedAt(context.Background(), []byte("first"), time.Unix(100, 0), func(ctx context.Context, position model.WALPosition) error {
			firstCalls.Add(1)
			firstSeen <- position
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-firstRelease:
			}
			return nil
		})
		firstDone <- appendResult{position: position, err: appendErr}
	}()

	select {
	case position := <-firstSeen:
		if position.Sequence != 1 {
			t.Fatalf("first candidate position = %+v, want sequence 1", position)
		}
	case <-time.After(time.Second):
		t.Fatal("first preparation did not start")
	}

	secondPrepared := make(chan model.WALPosition, 1)
	secondDone := make(chan appendResult, 1)
	var secondCalls atomic.Int32
	go func() {
		position, _, appendErr := writer.AppendPreparedAt(context.Background(), []byte("second"), time.Unix(101, 0), func(_ context.Context, position model.WALPosition) error {
			secondCalls.Add(1)
			secondPrepared <- position
			return nil
		})
		secondDone <- appendResult{position: position, err: appendErr}
	}()

	select {
	case position := <-secondPrepared:
		if position.Sequence != 2 {
			t.Fatalf("second reserved position = %+v, want sequence 2", position)
		}
	case <-time.After(time.Second):
		t.Fatal("second preparation was blocked by the first callback")
	}

	select {
	case result := <-secondDone:
		t.Fatalf("second append completed before its predecessor: %+v", result)
	case <-time.After(50 * time.Millisecond):
	}
	close(firstRelease)

	first := <-firstDone
	second := <-secondDone
	if first.err != nil || second.err != nil {
		t.Fatalf("append errors first=%v second=%v", first.err, second.err)
	}
	if first.position.Sequence != 1 || second.position.Sequence != 2 {
		t.Fatalf("positions first=%+v second=%+v", first.position, second.position)
	}
	if firstCalls.Load() != 1 || secondCalls.Load() != 1 {
		t.Fatalf("prepare calls first=%d second=%d, want exactly one each", firstCalls.Load(), secondCalls.Load())
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	records, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || string(records[0].Payload) != "first" || string(records[1].Payload) != "second" {
		t.Fatalf("records = %+v", records)
	}
}

func TestAppendPreparedAtNWayConcurrencyPreparesOncePerReservation(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "000000000001.wal")
	writer, err := OpenWriter(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	const reservationCount = 16
	type preparedResult struct {
		index    int
		position model.WALPosition
	}
	type appendResult struct {
		index    int
		position model.WALPosition
		err      error
	}
	release := make(chan struct{})
	prepared := make(chan preparedResult, reservationCount)
	completed := make(chan appendResult, reservationCount)
	var prepareCalls atomic.Int32
	for index := 0; index < reservationCount; index++ {
		index := index
		payload := []byte(fmt.Sprintf("claim-%02d", index))
		go func() {
			position, _, appendErr := writer.AppendPreparedAt(context.Background(), payload, time.Unix(int64(100+index), 0), func(ctx context.Context, position model.WALPosition) error {
				prepareCalls.Add(1)
				prepared <- preparedResult{index: index, position: position}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-release:
					return nil
				}
			})
			completed <- appendResult{index: index, position: position, err: appendErr}
		}()
		select {
		case got := <-prepared:
			if got.index != index || got.position.Sequence != uint64(index+1) {
				t.Fatalf("prepared reservation = %+v, want index %d sequence %d", got, index, index+1)
			}
		case <-time.After(time.Second):
			t.Fatalf("reservation %d preparation did not start", index)
		}
	}
	close(release)

	seen := make([]bool, reservationCount)
	for range reservationCount {
		select {
		case result := <-completed:
			if result.err != nil {
				t.Fatalf("reservation %d append error = %v", result.index, result.err)
			}
			if result.position.Sequence != uint64(result.index+1) {
				t.Fatalf("reservation %d appended at %+v", result.index, result.position)
			}
			seen[result.index] = true
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent reservations did not drain")
		}
	}
	for index, ok := range seen {
		if !ok {
			t.Fatalf("reservation %d did not complete", index)
		}
	}
	if prepareCalls.Load() != reservationCount {
		t.Fatalf("prepare calls = %d, want %d", prepareCalls.Load(), reservationCount)
	}
}

func TestAppendPreparedAtFailureInvalidatesAndCancelsSuccessors(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "000000000001.wal")
	writer, err := OpenWriter(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	type appendResult struct {
		position model.WALPosition
		err      error
	}
	wantErr := errors.New("signer unavailable")
	firstStarted := make(chan struct{})
	firstRelease := make(chan struct{})
	firstDone := make(chan appendResult, 1)
	go func() {
		position, _, appendErr := writer.AppendPreparedAt(context.Background(), []byte("first"), time.Unix(100, 0), func(context.Context, model.WALPosition) error {
			close(firstStarted)
			<-firstRelease
			return wantErr
		})
		firstDone <- appendResult{position: position, err: appendErr}
	}()
	<-firstStarted

	secondStarted := make(chan struct{})
	secondCanceled := make(chan struct{})
	secondDone := make(chan appendResult, 1)
	go func() {
		position, _, appendErr := writer.AppendPreparedAt(context.Background(), []byte("second"), time.Unix(101, 0), func(ctx context.Context, position model.WALPosition) error {
			if position.Sequence != 2 {
				return fmt.Errorf("second reservation sequence = %d", position.Sequence)
			}
			close(secondStarted)
			<-ctx.Done()
			close(secondCanceled)
			return ctx.Err()
		})
		secondDone <- appendResult{position: position, err: appendErr}
	}()
	<-secondStarted
	close(firstRelease)

	first := <-firstDone
	second := <-secondDone
	if !errors.Is(first.err, wantErr) {
		t.Fatalf("first append error = %v, want signer error", first.err)
	}
	if !errors.Is(second.err, ErrAppendReservationInvalidated) {
		t.Fatalf("second append error = %v, want invalidated reservation", second.err)
	}
	select {
	case <-secondCanceled:
	case <-time.After(time.Second):
		t.Fatal("successor preparation context was not canceled")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("WAL size after failed reservation cascade = %d, want 0", info.Size())
	}

	retried, _, err := writer.AppendPreparedAt(context.Background(), []byte("second"), time.Unix(101, 0), func(_ context.Context, position model.WALPosition) error {
		if position.Sequence != 1 {
			return fmt.Errorf("retry sequence = %d", position.Sequence)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retry append error = %v", err)
	}
	if retried.Sequence != 1 {
		t.Fatalf("retry position = %+v", retried)
	}
}

func TestAppendPreparedAtMiddleFailureReplansFromValidPrefix(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "000000000001.wal")
	writer, err := OpenWriter(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	type appendResult struct {
		position model.WALPosition
		err      error
	}
	firstStarted := make(chan struct{})
	firstRelease := make(chan struct{})
	firstDone := make(chan appendResult, 1)
	go func() {
		position, _, appendErr := writer.AppendPreparedAt(context.Background(), []byte("first"), time.Unix(100, 0), func(ctx context.Context, _ model.WALPosition) error {
			close(firstStarted)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-firstRelease:
				return nil
			}
		})
		firstDone <- appendResult{position: position, err: appendErr}
	}()
	<-firstStarted

	middleErr := errors.New("middle signer failure")
	middleStarted := make(chan struct{})
	middleRelease := make(chan struct{})
	middleDone := make(chan error, 1)
	go func() {
		_, _, appendErr := writer.AppendPreparedAt(context.Background(), []byte("middle"), time.Unix(101, 0), func(context.Context, model.WALPosition) error {
			close(middleStarted)
			<-middleRelease
			return middleErr
		})
		middleDone <- appendErr
	}()
	<-middleStarted

	invalidatedStarted := make(chan struct{})
	invalidatedDone := make(chan error, 1)
	go func() {
		_, _, appendErr := writer.AppendPreparedAt(context.Background(), []byte("invalidated"), time.Unix(102, 0), func(ctx context.Context, position model.WALPosition) error {
			if position.Sequence != 3 {
				return fmt.Errorf("invalidated sequence = %d", position.Sequence)
			}
			close(invalidatedStarted)
			<-ctx.Done()
			return ctx.Err()
		})
		invalidatedDone <- appendErr
	}()
	<-invalidatedStarted
	close(middleRelease)
	if err := <-middleDone; !errors.Is(err, middleErr) {
		t.Fatalf("middle append error = %v", err)
	}
	if err := <-invalidatedDone; !errors.Is(err, ErrAppendReservationInvalidated) {
		t.Fatalf("successor append error = %v, want invalidated", err)
	}

	replacementPrepared := make(chan model.WALPosition, 1)
	replacementDone := make(chan appendResult, 1)
	go func() {
		position, _, appendErr := writer.AppendPreparedAt(context.Background(), []byte("replacement"), time.Unix(103, 0), func(_ context.Context, position model.WALPosition) error {
			replacementPrepared <- position
			return nil
		})
		replacementDone <- appendResult{position: position, err: appendErr}
	}()
	select {
	case position := <-replacementPrepared:
		if position.Sequence != 2 {
			t.Fatalf("replacement position = %+v, want sequence 2", position)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement reservation did not start")
	}
	close(firstRelease)
	first := <-firstDone
	replacement := <-replacementDone
	if first.err != nil || replacement.err != nil || first.position.Sequence != 1 || replacement.position.Sequence != 2 {
		t.Fatalf("prefix/replacement results first=%+v replacement=%+v", first, replacement)
	}
}

func TestAppendPreparedAtCloseInvalidatesPendingReservation(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "000000000001.wal")
	writer, err := OpenWriter(path, 1)
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, _, appendErr := writer.AppendPreparedAt(context.Background(), []byte("claim"), time.Unix(100, 0), func(ctx context.Context, _ model.WALPosition) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		})
		done <- appendErr
	}()
	<-started
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case appendErr := <-done:
		if !errors.Is(appendErr, errWriterClosed) {
			t.Fatalf("pending append error = %v, want writer closed", appendErr)
		}
	case <-time.After(time.Second):
		t.Fatal("pending prepared append did not return after Close")
	}
}
