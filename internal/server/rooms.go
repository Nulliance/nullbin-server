package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/jacobzymet/nullbin-go/internal/rooms"
)

// Null Chats: short-lived end-to-end encrypted group chats, kept in
// memory only (internal/rooms). The server relays opaque records and checks
// tokens; it never has the room key.

// Header names for room tokens.
const (
	OwnerTokenHeader  = "Nullbin-Owner-Token"
	MemberTokenHeader = "Nullbin-Member-Token"
	InviteTokenHeader = "Nullbin-Invite-Token"
)

const maxRoomCreateBody = 128 // {"expires_in": 604800, "max_members": 20, "invite_ttl": 3600}

// registerRooms adds the room API. Without a room store the routes do not
// exist, so a server with rooms turned off answers 404 as for any unknown
// path.
func (s *Server) registerRooms(mux *http.ServeMux) {
	if s.cfg.Rooms == nil {
		return
	}
	mux.Handle("POST /api/v1/rooms", s.route(maxRoomCreateBody, s.roomCreates, s.handleRoomCreate))
	mux.Handle("POST /api/v1/rooms/{id}/invites", s.route(0, s.roomWrites, s.handleRoomInvite))
	mux.Handle("POST /api/v1/rooms/{id}/join", s.route(0, s.roomWrites, s.handleRoomJoin))
	mux.Handle("POST /api/v1/rooms/{id}/records", s.route(rooms.MaxRecordBytes, s.roomWrites, s.handleRoomPost))
	mux.Handle("GET /api/v1/rooms/{id}/records", s.route(0, s.roomReads, s.handleRoomRead))
	mux.Handle("GET /api/v1/rooms/{id}/members", s.route(0, s.roomReads, s.handleRoomMembers))
	mux.Handle("POST /api/v1/rooms/{id}/members/{n}/admit", s.route(0, s.roomWrites, s.handleRoomAdmit))
	mux.Handle("POST /api/v1/rooms/{id}/members/{n}/remove", s.route(0, s.roomWrites, s.handleRoomRemove))
	mux.Handle("DELETE /api/v1/rooms/{id}", s.route(0, s.roomWrites, s.handleRoomDelete))
	if !s.cfg.APIOnly {
		mux.Handle("GET /r/{id}", s.route(0, s.pages, s.roomPage))
	}
}

func (s *Server) roomPage(w http.ResponseWriter, r *http.Request) {
	// Like paste pages, it never reveals whether the room exists.
	if !rooms.ValidID(r.PathValue("id")) {
		http.NotFound(w, r)
		return
	}
	s.page(w, r)
}

// roomError maps store errors to responses. Wrong tokens, unknown and
// expired rooms all look the same.
func (s *Server) roomError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, rooms.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, rooms.ErrNotAdmitted):
		writeError(w, http.StatusForbidden, "waiting for the creator to let you in")
	case errors.Is(err, rooms.ErrInviteUsed):
		writeError(w, http.StatusGone, "this invite was already used or removed")
	case errors.Is(err, rooms.ErrInviteExpired):
		writeError(w, http.StatusGone, "this invite has expired")
	case errors.Is(err, rooms.ErrRoomFull):
		writeError(w, http.StatusConflict, "this room is full")
	case errors.Is(err, rooms.ErrNoPlaces):
		writeError(w, http.StatusConflict, "this room has used all its places")
	case errors.Is(err, rooms.ErrCapacity):
		writeError(w, http.StatusInsufficientStorage, "no room for more burner rooms right now")
	case errors.Is(err, rooms.ErrTooMany):
		w.Header().Set("Retry-After", "3600")
		writeError(w, http.StatusTooManyRequests, "too many live burner rooms from this network")
	case errors.Is(err, rooms.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid request")
	default:
		s.internalError(w, op, err)
	}
}

// roomID reads and checks the {id} path value; a bad one is 404.
func roomID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !rooms.ValidID(id) {
		writeError(w, http.StatusNotFound, "not found")
		return "", false
	}
	return id, true
}

func (s *Server) handleRoomCreate(w http.ResponseWriter, r *http.Request) {
	if !hasContentType(r, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return
	}
	var req struct {
		ExpiresIn *int64 `json:"expires_in"`
		// Optional: without them a room allows MaxSlots members and
		// invites work for an hour.
		MaxMembers *int64 `json:"max_members"`
		InviteTTL  *int64 `json:"invite_ttl"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.bodyError(w, err, "invalid JSON")
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		s.bodyError(w, err, "unexpected data after JSON object")
		return
	}
	if req.ExpiresIn == nil {
		writeError(w, http.StatusBadRequest, "expires_in must be one of 300, 1800, 3600, 10800, 43200, 86400, 259200, 604800")
		return
	}
	expires, ok := rooms.Expiries[*req.ExpiresIn]
	if !ok {
		writeError(w, http.StatusBadRequest, "expires_in must be one of 300, 1800, 3600, 10800, 43200, 86400, 259200, 604800")
		return
	}
	opts := rooms.Options{Expires: expires, MaxMembers: rooms.MaxSlots, InviteTTL: rooms.InviteTTL}
	if req.MaxMembers != nil {
		if *req.MaxMembers < rooms.MinMembers || *req.MaxMembers > rooms.MaxSlots {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("max_members must be from %d to %d", rooms.MinMembers, rooms.MaxSlots))
			return
		}
		opts.MaxMembers = int(*req.MaxMembers)
	}
	if req.InviteTTL != nil {
		ttl, ok := rooms.InviteTTLs[*req.InviteTTL]
		if !ok {
			writeError(w, http.StatusBadRequest, "invite_ttl must be one of 300, 900, 3600")
			return
		}
		opts.InviteTTL = ttl
	}
	ip := s.ips.clientIP(r)
	by := rooms.Creator{Client: s.roomCreates.hash(ip)}
	by.Site, by.HasSite = s.roomCreates.hashSite(ip)
	c, err := s.cfg.Rooms.CreateWith(opts, by)
	if err != nil {
		s.roomError(w, "room create", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": c.ID, "owner_token": c.OwnerToken, "member_token": c.MemberToken, "slot": 0,
	})
}

func (s *Server) handleRoomInvite(w http.ResponseWriter, r *http.Request) {
	id, ok := roomID(w, r)
	if !ok {
		return
	}
	// Each invite may choose its own lifetime (?ttl=300, 900 or 3600
	// seconds), up to the room's longest; without it, that longest.
	var ttl time.Duration
	if v := r.URL.Query().Get("ttl"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		d, ok := rooms.InviteTTLs[n]
		if err != nil || !ok {
			writeError(w, http.StatusBadRequest, "ttl must be one of 300, 900, 3600")
			return
		}
		ttl = d
	}
	token, n, err := s.cfg.Rooms.InviteFor(id, r.Header.Get(OwnerTokenHeader), ttl)
	if err != nil {
		s.roomError(w, "room invite", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"invite_token": token, "slot": n})
}

func (s *Server) handleRoomJoin(w http.ResponseWriter, r *http.Request) {
	id, ok := roomID(w, r)
	if !ok {
		return
	}
	token, n, err := s.cfg.Rooms.Join(id, r.Header.Get(InviteTokenHeader))
	if err != nil {
		s.roomError(w, "room join", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"member_token": token, "slot": n})
}

func (s *Server) handleRoomPost(w http.ResponseWriter, r *http.Request) {
	id, ok := roomID(w, r)
	if !ok {
		return
	}
	if !hasContentType(r, "application/octet-stream") {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/octet-stream")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.bodyError(w, err, "could not read request body")
		return
	}
	n, err := s.cfg.Rooms.Post(id, r.Header.Get(MemberTokenHeader), body)
	if err != nil {
		s.roomError(w, "room post", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int{"index": n})
}

type roomRecord struct {
	From int    `json:"from"`
	Data string `json:"data"`
}

func (s *Server) handleRoomRead(w http.ResponseWriter, r *http.Request) {
	// "GET" patterns also match HEAD.
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id, ok := roomID(w, r)
	if !ok {
		return
	}
	// Like paste downloads and comments, a response holds a download slot,
	// so a client that reads slowly cannot pin many responses at once, and
	// is charged to the per-client and total download bandwidth.
	ip := s.ips.clientIP(r)
	release, ok := s.downloadSlots.acquire(ip)
	if !ok {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, "too many active downloads")
		return
	}
	defer release()
	if ok, _ := s.downloadBytes.allowN(ip, time.Now(), 0); !ok {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	after := 0
	if v := r.URL.Query().Get("after"); v != "" {
		n, ok := parseChunkIndex(v)
		if !ok || n > rooms.MaxRecords {
			writeError(w, http.StatusBadRequest, "after must be a record index")
			return
		}
		after = n
	}
	recs, next, expires, err := s.cfg.Rooms.Read(id, r.Header.Get(MemberTokenHeader), after)
	if err != nil {
		s.roomError(w, "room read", err)
		return
	}
	left := max(int64(expires.Sub(s.cfg.Rooms.Now())/time.Second), 0)
	// Stream one base64-encoded record at a time, through the bandwidth
	// budgets, and zero each copy once it is written.
	const maxResponse = (rooms.MaxReadBytes+2)/3*4 + rooms.MaxReadBatch*64 + 128
	deadline := downloadBaseDeadline + time.Duration(maxResponse/downloadMinRate)*time.Second
	ctx, cancel := context.WithTimeout(r.Context(), deadline)
	defer cancel()
	defer func() {
		for _, rec := range recs {
			clear(rec.Data)
		}
	}()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	bw := s.downloadWriter(ctx, w, ip, deadline)
	if _, err := fmt.Fprintf(bw, `{"next":%d,"expires_in":%d,"records":[`, next, left); err != nil {
		panic(http.ErrAbortHandler)
	}
	enc := json.NewEncoder(bw)
	for i, rec := range recs {
		if i > 0 {
			if _, err := io.WriteString(bw, ","); err != nil {
				panic(http.ErrAbortHandler)
			}
		}
		if err := enc.Encode(roomRecord{From: rec.From, Data: base64.StdEncoding.EncodeToString(rec.Data)}); err != nil {
			panic(http.ErrAbortHandler)
		}
	}
	if _, err := io.WriteString(bw, "]}"); err != nil {
		panic(http.ErrAbortHandler)
	}
}

func (s *Server) handleRoomMembers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id, ok := roomID(w, r)
	if !ok {
		return
	}
	states, err := s.cfg.Rooms.Members(id, r.Header.Get(OwnerTokenHeader))
	if err != nil {
		s.roomError(w, "room members", err)
		return
	}
	out := make(map[string]rooms.MemberState, len(states))
	for n, st := range states {
		out[strconv.Itoa(n)] = st
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": out})
}

func (s *Server) handleRoomAdmit(w http.ResponseWriter, r *http.Request) {
	id, ok := roomID(w, r)
	if !ok {
		return
	}
	n, ok := parseChunkIndex(r.PathValue("n"))
	if !ok || n >= rooms.MaxSlots {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err := s.cfg.Rooms.Admit(id, r.Header.Get(OwnerTokenHeader), n); err != nil {
		s.roomError(w, "room admit", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRoomRemove(w http.ResponseWriter, r *http.Request) {
	id, ok := roomID(w, r)
	if !ok {
		return
	}
	n, ok := parseChunkIndex(r.PathValue("n"))
	if !ok || n >= rooms.MaxSlots {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err := s.cfg.Rooms.Remove(id, r.Header.Get(OwnerTokenHeader), n); err != nil {
		s.roomError(w, "room remove", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRoomDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := roomID(w, r)
	if !ok {
		return
	}
	// Any member may self-destruct the room; the owner token works too,
	// also when a member token sent with it no longer does.
	err := rooms.ErrNotFound
	if token := r.Header.Get(MemberTokenHeader); token != "" {
		err = s.cfg.Rooms.Destroy(id, token)
	}
	if errors.Is(err, rooms.ErrNotFound) {
		if token := r.Header.Get(OwnerTokenHeader); token != "" {
			err = s.cfg.Rooms.Destroy(id, token)
		}
	}
	if err != nil {
		s.roomError(w, "room delete", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
