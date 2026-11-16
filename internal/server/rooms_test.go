package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jacobzymet/nullbin-go/internal/rooms"
)

func roomEnv(t *testing.T) *testEnv {
	t.Helper()
	return newEnv(t, func(c *Config) { c.Rooms = rooms.New(rooms.DefaultMaxRooms, rooms.DefaultMaxBytes) })
}

type roomCreated struct {
	ID          string `json:"id"`
	OwnerToken  string `json:"owner_token"`
	MemberToken string `json:"member_token"`
	Slot        int    `json:"slot"`
}

func createRoom(t *testing.T, e *testEnv) roomCreated {
	t.Helper()
	resp, data := e.do(t, "POST", "/api/v1/rooms", []byte(`{"expires_in":3600}`), jsonHdr)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, data)
	}
	var c roomCreated
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

var octet = map[string]string{"Content-Type": "application/octet-stream"}

func with(h map[string]string, k, v string) map[string]string {
	out := map[string]string{k: v}
	for a, b := range h {
		out[a] = b
	}
	return out
}

func TestRoomsOffMeansNoRoutes(t *testing.T) {
	e := newEnv(t, nil)
	for _, path := range []string{"/api/v1/rooms", "/r/0123456789abcdef0123456789abcdef"} {
		method := "POST"
		if strings.HasPrefix(path, "/r/") {
			method = "GET"
		}
		resp, _ := e.do(t, method, path, []byte(`{"expires_in":3600}`), jsonHdr)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %s with rooms off: %d", method, path, resp.StatusCode)
		}
	}
}

func TestRoomCreateValidation(t *testing.T) {
	e := roomEnv(t)
	for _, body := range []string{``, `{}`, `{"expires_in":60}`, `{"expires_in":"3600"}`, `{"expires_in":3600,"x":1}`, `{"expires_in":3600}{}`, `[]`, `{"expires_in":3600.5}`} {
		resp, _ := e.do(t, "POST", "/api/v1/rooms", []byte(body), jsonHdr)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%q: %d", body, resp.StatusCode)
		}
	}
	resp, _ := e.do(t, "POST", "/api/v1/rooms", []byte(`{"expires_in":3600}`), nil)
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("no content type: %d", resp.StatusCode)
	}
	resp, _ = e.do(t, "POST", "/api/v1/rooms", []byte(`{"expires_in":3600,"pad":"`+strings.Repeat("a", 200)+`"}`), jsonHdr)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("large body: %d", resp.StatusCode)
	}
	e.clock.add(time.Minute) // the cases above used the creation budget
	for _, ok := range []string{"300", "1800", "3600", "10800", "43200", "86400", "259200", "604800"} {
		resp, data := e.do(t, "POST", "/api/v1/rooms", []byte(`{"expires_in":`+ok+`}`), jsonHdr)
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("%s: %d %s", ok, resp.StatusCode, data)
		}
	}
}

func TestRoomFlowOverHTTP(t *testing.T) {
	const origin = "https://paste.example.com"
	e := newEnv(t, func(c *Config) {
		c.Rooms = rooms.New(rooms.DefaultMaxRooms, rooms.DefaultMaxBytes)
		c.FrontendOrigin = origin
	})
	c := createRoom(t, e)
	base := "/api/v1/rooms/" + c.ID
	owner := map[string]string{OwnerTokenHeader: c.OwnerToken}
	me := map[string]string{MemberTokenHeader: c.MemberToken}

	// Invite, then join once.
	resp, data := e.do(t, "POST", base+"/invites", nil, me)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a member token makes invites: %d %s", resp.StatusCode, data)
	}
	resp, data = e.do(t, "POST", base+"/invites", nil, owner)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("invite: %d %s", resp.StatusCode, data)
	}
	var inv struct {
		InviteToken string `json:"invite_token"`
		Slot        int    `json:"slot"`
	}
	json.Unmarshal(data, &inv)
	resp, data = e.do(t, "POST", base+"/join", nil, map[string]string{InviteTokenHeader: inv.InviteToken})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("join: %d %s", resp.StatusCode, data)
	}
	var joined struct {
		MemberToken string `json:"member_token"`
		Slot        int    `json:"slot"`
	}
	json.Unmarshal(data, &joined)
	if joined.Slot != inv.Slot || len(joined.MemberToken) != 43 || joined.MemberToken == inv.InviteToken {
		t.Fatalf("joined: %+v", joined)
	}
	if resp, _ := e.do(t, "POST", base+"/join", nil, map[string]string{InviteTokenHeader: inv.InviteToken}); resp.StatusCode != http.StatusGone {
		t.Fatalf("second join: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, "POST", base+"/join", nil, map[string]string{InviteTokenHeader: c.OwnerToken}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("join with the owner token: %d", resp.StatusCode)
	}
	them := map[string]string{MemberTokenHeader: joined.MemberToken}

	// Post and read; the server stamps the sender's slot.
	msg := bytes.Repeat([]byte{7}, 100)
	if resp, _ := e.do(t, "POST", base+"/records", msg, with(octet, MemberTokenHeader, joined.MemberToken)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("post: %d", resp.StatusCode)
	}
	for _, bad := range []struct {
		body []byte
		hdr  map[string]string
		want int
	}{
		{msg, octet, http.StatusNotFound},
		{msg, with(octet, MemberTokenHeader, inv.InviteToken), http.StatusNotFound},
		{msg, with(octet, MemberTokenHeader, c.OwnerToken), http.StatusNotFound},
		{msg, them, http.StatusUnsupportedMediaType},
		{make([]byte, rooms.MinRecordBytes-1), with(octet, MemberTokenHeader, c.MemberToken), http.StatusBadRequest},
		{make([]byte, rooms.MaxRecordBytes+1), with(octet, MemberTokenHeader, c.MemberToken), http.StatusRequestEntityTooLarge},
	} {
		if resp, _ := e.do(t, "POST", base+"/records", bad.body, bad.hdr); resp.StatusCode != bad.want {
			t.Fatalf("bad post (%d bytes): %d, want %d", len(bad.body), resp.StatusCode, bad.want)
		}
	}
	resp, data = e.do(t, "GET", base+"/records?after=0", nil, with(me, "Origin", origin))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read: %d %s", resp.StatusCode, data)
	}
	var got struct {
		Records []struct {
			From int    `json:"from"`
			Data string `json:"data"`
		} `json:"records"`
		Next      int   `json:"next"`
		ExpiresIn int64 `json:"expires_in"`
	}
	json.Unmarshal(data, &got)
	if len(got.Records) != 1 || got.Records[0].From != inv.Slot || got.Next != 1 || got.ExpiresIn <= 0 || got.ExpiresIn > 3600 {
		t.Fatalf("read: %s", data)
	}
	if b, _ := base64.StdEncoding.DecodeString(got.Records[0].Data); !bytes.Equal(b, msg) {
		t.Fatal("record changed")
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != origin {
		t.Fatal("CORS for the separately hosted website")
	}
	for _, q := range []string{"?after=-1", "?after=01", "?after=x", "?after=2", "?after=1001"} {
		if resp, _ := e.do(t, "GET", base+"/records"+q, nil, me); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("read %s: %d", q, resp.StatusCode)
		}
	}
	if resp, _ := e.do(t, "HEAD", base+"/records", nil, me); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD: %d", resp.StatusCode)
	}
	for _, hdr := range []map[string]string{nil, owner, {MemberTokenHeader: inv.InviteToken}} {
		if resp, _ := e.do(t, "GET", base+"/records", nil, hdr); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("read without a member token: %d", resp.StatusCode)
		}
	}

	// Members, remove, delete: owner only.
	if resp, _ := e.do(t, "GET", base+"/members", nil, me); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("members for a member: %d", resp.StatusCode)
	}
	resp, data = e.do(t, "GET", base+"/members", nil, owner)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(data)) != `{"members":{"0":"joined","1":"joined"}}` {
		t.Fatalf("members: %d %s", resp.StatusCode, data)
	}
	for _, n := range []string{"0", "-1", "20", "01", "x"} {
		resp, _ := e.do(t, "POST", base+"/members/"+n+"/remove", nil, owner)
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("remove %s: %d", n, resp.StatusCode)
		}
	}
	if resp, _ := e.do(t, "POST", base+"/members/1/remove", nil, them); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a member removes: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, "POST", base+"/members/1/remove", nil, owner); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("remove: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, "GET", base+"/records", nil, them); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("removed member reads: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, "DELETE", base, nil, them); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a removed member self-destructs: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, "DELETE", base, nil, map[string]string{MemberTokenHeader: inv.InviteToken}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an invite token self-destructs: %d", resp.StatusCode)
	}
	// Any current member can self-destruct the room.
	if resp, _ := e.do(t, "DELETE", base, nil, me); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("self-destruct: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, "GET", base+"/records", nil, me); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("read after delete: %d", resp.StatusCode)
	}
	// The room page exists only for well-formed IDs, and never says
	// whether the room does.
	if resp, _ := e.do(t, "GET", "/r/"+c.ID, nil, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("room page: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, "GET", "/r/nothex", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("bad room page: %d", resp.StatusCode)
	}
}

func TestRoomRequestsAreRateLimited(t *testing.T) {
	e := roomEnv(t)
	c := createRoom(t, e)
	me := map[string]string{MemberTokenHeader: c.MemberToken}
	limited := false
	for range 150 {
		if resp, _ := e.do(t, "GET", "/api/v1/rooms/"+c.ID+"/records", nil, me); resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("polling is not rate limited")
	}
	e.clock.add(time.Minute)
	if resp, _ := e.do(t, "GET", "/api/v1/rooms/"+c.ID+"/records", nil, me); resp.StatusCode != http.StatusOK {
		t.Fatalf("after waiting: %d", resp.StatusCode)
	}
}

func TestRoomDeleteFallsBackToTheOwnerToken(t *testing.T) {
	e := roomEnv(t)
	c := createRoom(t, e)
	base := "/api/v1/rooms/" + c.ID
	// A member token that no longer works does not hide a valid owner token.
	stale := map[string]string{MemberTokenHeader: strings.Repeat("A", len(c.MemberToken)), OwnerTokenHeader: c.OwnerToken}
	if resp, _ := e.do(t, "DELETE", base, nil, stale); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete with the owner token: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, "GET", base+"/records", nil, map[string]string{MemberTokenHeader: c.MemberToken}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("read after delete: %d", resp.StatusCode)
	}
	// Neither token working is a plain 404.
	c2 := createRoom(t, e)
	bad := map[string]string{MemberTokenHeader: strings.Repeat("A", len(c2.MemberToken)), OwnerTokenHeader: strings.Repeat("B", len(c2.OwnerToken))}
	if resp, _ := e.do(t, "DELETE", "/api/v1/rooms/"+c2.ID, nil, bad); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete with no valid token: %d", resp.StatusCode)
	}
}

func TestRoomCreateOptions(t *testing.T) {
	e := roomEnv(t)
	for _, body := range []string{
		`{"expires_in":3600,"max_members":1}`, `{"expires_in":3600,"max_members":21}`, `{"expires_in":3600,"max_members":"2"}`,
		`{"expires_in":3600,"max_members":2.5}`, `{"expires_in":3600,"invite_ttl":60}`, `{"expires_in":3600,"invite_ttl":7200}`,
		`{"expires_in":3600,"invite_ttl":"900"}`,
	} {
		resp, _ := e.do(t, "POST", "/api/v1/rooms", []byte(body), jsonHdr)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%q: %d", body, resp.StatusCode)
		}
	}
	e.clock.add(time.Minute) // the cases above used the creation budget
	// A one-to-one room with five-minute invites: one invite, then full.
	resp, data := e.do(t, "POST", "/api/v1/rooms", []byte(`{"expires_in":3600,"max_members":2,"invite_ttl":300}`), jsonHdr)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, data)
	}
	var c roomCreated
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	owner := map[string]string{"Nullbin-Owner-Token": c.OwnerToken}
	if resp, data := e.do(t, "POST", "/api/v1/rooms/"+c.ID+"/invites", nil, owner); resp.StatusCode != http.StatusCreated {
		t.Fatalf("first invite: %d %s", resp.StatusCode, data)
	}
	if resp, _ := e.do(t, "POST", "/api/v1/rooms/"+c.ID+"/invites", nil, owner); resp.StatusCode != http.StatusConflict {
		t.Fatalf("second invite in a one-to-one room: %d", resp.StatusCode)
	}
}

func TestRoomInviteLifetimeOverHTTP(t *testing.T) {
	e := roomEnv(t)
	c := createRoom(t, e)
	owner := map[string]string{"Nullbin-Owner-Token": c.OwnerToken}
	for _, bad := range []string{"60", "abc", "-300", "7200"} {
		if resp, _ := e.do(t, "POST", "/api/v1/rooms/"+c.ID+"/invites?ttl="+bad, nil, owner); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("ttl=%s: %d", bad, resp.StatusCode)
		}
	}
	for _, ok := range []string{"300", "900", "3600"} {
		if resp, data := e.do(t, "POST", "/api/v1/rooms/"+c.ID+"/invites?ttl="+ok, nil, owner); resp.StatusCode != http.StatusCreated {
			t.Errorf("ttl=%s: %d %s", ok, resp.StatusCode, data)
		}
	}
}
