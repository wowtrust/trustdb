package natsingress

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/wowtrust/trustdb/internal/model"
)

func TestStatusPublisherUsesConfiguredConcreteSubject(t *testing.T) {
	t.Parallel()

	server := startTestServer(t, nil)
	publisherConn, err := nats.Connect(server.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer publisherConn.Close()
	receiverConn, err := nats.Connect(server.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer receiverConn.Close()
	messages := make(chan *nats.Msg, 1)
	if _, err := receiverConn.ChanSubscribe("trustdb.status.upstream", messages); err != nil {
		t.Fatal(err)
	}
	if err := receiverConn.Flush(); err != nil {
		t.Fatal(err)
	}

	publisher, err := NewStatusPublisher(&Runtime{conn: publisherConn})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.PublishStatusRefresh(context.Background(), "trustdb.status.upstream", []byte("refresh")); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-messages:
		if string(message.Data) != "refresh" || message.Header.Get(HeaderSchemaVersion) != model.SchemaStatusRefresh || message.Header.Get(HeaderContentType) != StatusRefreshContentType {
			t.Fatalf("message = %+v", message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for NATS status refresh")
	}
}
