package main

import (
	"encoding/json"
	"fmt"

	"github.com/df-mc/go-xsapi/v2"
	"github.com/df-mc/go-xsapi/v2/mpsd"
	"github.com/df-mc/go-xsapi/v2/rta"
	"github.com/google/uuid"
)

type subscribeProbe struct {
	rta.NopSubscriptionHandler
	ready chan struct{}
}

// HandleSubscribe signals only after the real subscription callback receives its new snapshot.
func (p subscribeProbe) HandleSubscribe(json.RawMessage) error { p.ready <- struct{}{}; return nil }

// startRTA authenticates the actual Go WebSocket client through the same request peer.
func (d *driver) startRTA() error {
	if d.rtaConn != nil {
		return nil
	}
	client, err := xsapi.ClientConfig{HTTPClient: d.client, RTAMode: xsapi.RTADisabled, Logger: quiet}.New(d.ctx, d.session)
	if err != nil {
		return err
	}
	conn, err := rta.Dial(d.ctx, client.HTTPClient(), quiet)
	if err != nil {
		return err
	}
	d.rtaConn = conn
	d.directory = mpsd.New(client.HTTPClient(), conn, client.UserInfo(), quiet)
	d.closers = append(d.closers, conn.Close, d.directory.Close)
	return nil
}

// subscribeRTA retains one desired subscription across physical connection replacement.
func (d *driver) subscribeRTA() error {
	if err := d.startRTA(); err != nil {
		return err
	}
	d.rtaReady = make(chan struct{}, 1)
	sub := rta.NewSubscription("https://sessiondirectory.xboxlive.com/connections/", subscribeProbe{ready: d.rtaReady})
	if err := d.rtaConn.Subscribe(d.ctx, sub); err != nil {
		return err
	}
	<-d.rtaReady
	return nil
}

// dropRTA waits for the actual Go recovery callback or MPSD rebinding, without sleeping.
func (d *driver) dropRTA() error {
	if d.rtaConn == nil {
		return fmt.Errorf("RTA was not started")
	}
	d.srv.DropRTA()
	if d.rtaReady != nil {
		<-d.rtaReady
		return nil
	}
	d.srv.WaitDirectoryConnection(2)
	return nil
}

// joinDirectory drives Go's real bounded 412 retry loop and its real RTA subscription.
func (d *driver) joinDirectory() error {
	if err := d.startRTA(); err != nil {
		return err
	}
	_, err := d.directory.Join(d.ctx, uuid.MustParse("00000000-0000-0000-0000-000000000009"), mpsd.JoinConfig{})
	return err
}
