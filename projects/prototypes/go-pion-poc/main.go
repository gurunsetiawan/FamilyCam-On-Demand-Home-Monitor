package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/pion/interceptor"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

type Config struct {
	BindAddr                   string
	RTPListenAddr              string
	OwnerToken                 string
	MaxSessions                int
	SessionTTL                 time.Duration
	AutoStopNoViewers          time.Duration
	MaxStreamDuration          time.Duration
	PublisherBin               string
	PublisherArgs              []string
	VideoMime                  string
	VideoClockRate             uint32
	VideoFMTP                  string
	IceServers                 []string
	IceUDP4Only                bool
	IceDisconnectedTimeout     time.Duration
	IceFailedTimeout           time.Duration
	IceKeepAliveInterval       time.Duration
	IceUsername                string
	IceCredential              string
	PublisherStopGraceDuration time.Duration
}

type SessionEntry struct {
	ID        string
	PC        *webrtc.PeerConnection
	CreatedAt time.Time
	LastSeen  time.Time
}

type IngestStats struct {
	Packets        uint64 `json:"rtp_packets"`
	Bytes          uint64 `json:"rtp_bytes"`
	ParseErrors    uint64 `json:"rtp_parse_errors"`
	WriteErrors    uint64 `json:"rtp_write_errors"`
	LastPacketUnix int64  `json:"rtp_last_packet_unix,omitempty"`
	LastSource     string `json:"rtp_last_source,omitempty"`
}

type PublisherExit struct {
	ExitedUnix int64  `json:"exited_unix"`
	Code       int    `json:"code"`
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
}

type PublisherProcess struct {
	cmd         *exec.Cmd
	done        chan error
	pid         int
	startedAt   time.Time
	command     string
	args        []string
	cancelGuard context.CancelFunc
	stderr      *limitedBuffer
}

type PublisherState struct {
	Running  *PublisherProcess
	LastExit *PublisherExit
}

type App struct {
	cfg        Config
	api        *webrtc.API
	videoTrack *webrtc.TrackLocalStaticRTP

	startedAt time.Time

	sessionsMu sync.RWMutex
	sessions   map[string]*SessionEntry

	ingestMu    sync.Mutex
	ingestStats IngestStats

	publisherMu sync.Mutex
	publisher   PublisherState
}

type limitedBuffer struct {
	mu    sync.Mutex
	limit int
	data  []byte
}

func newLimitedBuffer(limit int) *limitedBuffer {
	return &limitedBuffer{limit: limit}
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, p...)
	if b.limit > 0 && len(b.data) > b.limit {
		b.data = append([]byte(nil), b.data[len(b.data)-b.limit:]...)
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	if b == nil {
		return ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(append([]byte(nil), b.data...))
}

type offerRequest struct {
	SDP string `json:"sdp"`
}

type offerResponse struct {
	SessionID string `json:"session_id"`
	SDP       string `json:"sdp"`
	Type      string `json:"type"`
}

type candidateRequest struct {
	SessionID        string  `json:"session_id"`
	Candidate        string  `json:"candidate"`
	SDPMid           string  `json:"sdpMid,omitempty"`
	SDPMLineIndex    *uint16 `json:"sdpMLineIndex,omitempty"`
	UsernameFragment string  `json:"usernameFragment,omitempty"`
}

type publisherStartRequest struct {
	Bin  string   `json:"bin"`
	Args []string `json:"args"`
}

type publisherStatusResponse struct {
	Running     bool           `json:"running"`
	PID         int            `json:"pid,omitempty"`
	StartedUnix int64          `json:"started_unix,omitempty"`
	Command     string         `json:"command,omitempty"`
	Args        []string       `json:"args"`
	LastExit    *PublisherExit `json:"last_exit,omitempty"`
}

type cameraProbeResponse struct {
	Cameras []cameraDevice `json:"cameras"`
}

type cameraDevice struct {
	Name        string         `json:"name"`
	Path        string         `json:"path"`
	Formats     []cameraFormat `json:"formats"`
	Resolutions []string       `json:"resolutions,omitempty"`
	FPSOptions  []int          `json:"fps_options,omitempty"`
}

type cameraFormat struct {
	Code        string `json:"code"`
	FFmpegInput string `json:"ffmpeg_input"`
}

func main() {
	_ = godotenv.Load()

	cfg := loadConfig()
	api, err := buildAPI(cfg)
	if err != nil {
		log.Fatalf("build pion api failed: %v", err)
	}

	track, err := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{
			MimeType:    cfg.VideoMime,
			ClockRate:   cfg.VideoClockRate,
			SDPFmtpLine: cfg.VideoFMTP,
		},
		"video",
		"familycam-go",
	)
	if err != nil {
		log.Fatalf("create track failed: %v", err)
	}

	app := &App{
		cfg:        cfg,
		api:        api,
		videoTrack: track,
		startedAt:  time.Now(),
		sessions:   map[string]*SessionEntry{},
	}

	go app.runRTPIngestLoop()
	go app.runSessionCleanupLoop()
	go app.runPublisherGuardLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleIndex)
	mux.HandleFunc("/healthz", app.handleHealthz)
	mux.HandleFunc("/metrics", app.handleMetrics)
	mux.HandleFunc("/webrtc/offer", app.handleOffer)
	mux.HandleFunc("/webrtc/candidate", app.handleCandidate)
	mux.HandleFunc("/webrtc/sessions", app.handleSessions)
	mux.HandleFunc("/camera/probe", app.handleCameraProbe)
	mux.HandleFunc("/publisher/status", app.handlePublisherStatus)
	mux.HandleFunc("/publisher/start", app.handlePublisherStart)
	mux.HandleFunc("/publisher/stop", app.handlePublisherStop)

	log.Printf("go-pion-poc listening on http://%s (RTP ingest: %s)", cfg.BindAddr, cfg.RTPListenAddr)
	if err := http.ListenAndServe(cfg.BindAddr, logMiddleware(mux)); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}

func buildAPI(cfg Config) (*webrtc.API, error) {
	m := &webrtc.MediaEngine{}
	if err := m.RegisterDefaultCodecs(); err != nil {
		return nil, err
	}

	i := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(m, i); err != nil {
		return nil, err
	}

	se := webrtc.SettingEngine{}
	se.SetICETimeouts(cfg.IceDisconnectedTimeout, cfg.IceFailedTimeout, cfg.IceKeepAliveInterval)
	if cfg.IceUDP4Only {
		se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	}

	api := webrtc.NewAPI(
		webrtc.WithMediaEngine(m),
		webrtc.WithInterceptorRegistry(i),
		webrtc.WithSettingEngine(se),
	)
	return api, nil
}

func loadConfig() Config {
	cfg := Config{}
	cfg.BindAddr = getenv("POC_BIND_ADDR", "0.0.0.0:9180")
	cfg.RTPListenAddr = getenv("POC_RTP_LISTEN_ADDR", "127.0.0.1:6004")
	cfg.OwnerToken = getenv("POC_OWNER_TOKEN", "owner-dev-token")
	cfg.MaxSessions = getenvInt("POC_MAX_SESSIONS", 3)
	cfg.SessionTTL = time.Duration(getenvInt("POC_SESSION_TTL_SECS", 600)) * time.Second
	cfg.AutoStopNoViewers = time.Duration(getenvInt("POC_AUTO_STOP_NO_VIEWERS_SECS", 20)) * time.Second
	cfg.MaxStreamDuration = time.Duration(getenvInt("POC_MAX_STREAM_SECS", 1800)) * time.Second
	cfg.PublisherBin = getenv("POC_PUBLISHER_BIN", "ffmpeg")
	cfg.PublisherArgs = splitArgs(getenv("POC_PUBLISHER_ARGS", "-f lavfi -i testsrc=size=640x360:rate=10 -an -c:v libx264 -preset ultrafast -tune zerolatency -pix_fmt yuv420p -profile:v baseline -level 3.1 -g 30 -keyint_min 30 -sc_threshold 0 -f rtp rtp://127.0.0.1:6004"))
	cfg.VideoMime = getenv("POC_VIDEO_MIME", "video/H264")
	cfg.VideoClockRate = uint32(getenvInt("POC_VIDEO_CLOCK_RATE", 90000))
	cfg.VideoFMTP = getenv("POC_VIDEO_FMTP", "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f")
	cfg.IceServers = splitServers(getenv("POC_ICE_SERVERS", "stun:stun.l.google.com:19302"))
	cfg.IceUDP4Only = getenvBool("POC_ICE_UDP4_ONLY", true)
	cfg.IceDisconnectedTimeout = time.Duration(getenvInt("POC_ICE_DISCONNECTED_TIMEOUT_SECS", 12)) * time.Second
	cfg.IceFailedTimeout = time.Duration(getenvInt("POC_ICE_FAILED_TIMEOUT_SECS", 45)) * time.Second
	cfg.IceKeepAliveInterval = time.Duration(getenvInt("POC_ICE_KEEPALIVE_INTERVAL_SECS", 2)) * time.Second
	cfg.IceUsername = getenv("POC_ICE_USERNAME", "")
	cfg.IceCredential = getenv("POC_ICE_CREDENTIAL", "")
	cfg.PublisherStopGraceDuration = 5 * time.Second
	return cfg
}

func (a *App) runRTPIngestLoop() {
	for {
		if err := a.runRTPIngest(); err != nil {
			log.Printf("rtp ingest error: %v", err)
			time.Sleep(2 * time.Second)
		}
	}
}

func (a *App) runRTPIngest() error {
	addr, err := net.ResolveUDPAddr("udp", a.cfg.RTPListenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("RTP ingest listening on udp://%s", a.cfg.RTPListenAddr)

	buf := make([]byte, 2048)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}

		pkt := &rtp.Packet{}
		if err := pkt.Unmarshal(buf[:n]); err != nil {
			a.ingestMu.Lock()
			a.ingestStats.ParseErrors++
			a.ingestMu.Unlock()
			continue
		}

		if err := a.videoTrack.WriteRTP(pkt); err != nil {
			a.ingestMu.Lock()
			a.ingestStats.WriteErrors++
			a.ingestMu.Unlock()
			continue
		}

		a.ingestMu.Lock()
		a.ingestStats.Packets++
		a.ingestStats.Bytes += uint64(n)
		a.ingestStats.LastPacketUnix = time.Now().Unix()
		a.ingestStats.LastSource = src.String()
		a.ingestMu.Unlock()
	}
}

func (a *App) runSessionCleanupLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		var toClose []*webrtc.PeerConnection

		a.sessionsMu.Lock()
		for id, session := range a.sessions {
			if now.Sub(session.LastSeen) >= a.cfg.SessionTTL {
				toClose = append(toClose, session.PC)
				delete(a.sessions, id)
			}
		}
		a.sessionsMu.Unlock()

		for _, pc := range toClose {
			_ = pc.Close()
		}
	}
}

func (a *App) runPublisherGuardLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var noViewerSince time.Time
	for range ticker.C {
		a.refreshPublisherStateLocked()
		viewerCount := a.sessionCount()

		if viewerCount == 0 {
			if noViewerSince.IsZero() {
				noViewerSince = time.Now()
			}
		} else {
			noViewerSince = time.Time{}
		}

		a.publisherMu.Lock()
		running := a.publisher.Running
		a.publisherMu.Unlock()
		if running == nil {
			continue
		}

		if a.cfg.MaxStreamDuration > 0 && time.Since(running.startedAt) >= a.cfg.MaxStreamDuration {
			if _, err := a.stopPublisher("auto-stop: max stream duration reached"); err != nil {
				log.Printf("publisher guard stop failed: %v", err)
			}
			continue
		}

		if a.cfg.AutoStopNoViewers > 0 && viewerCount == 0 && !noViewerSince.IsZero() && time.Since(noViewerSince) >= a.cfg.AutoStopNoViewers {
			if stopped, err := a.stopPublisher(fmt.Sprintf("auto-stop: no viewers for %.0fs", time.Since(noViewerSince).Seconds())); err == nil && stopped {
				noViewerSince = time.Time{}
			} else if err != nil {
				log.Printf("publisher guard stop failed: %v", err)
			}
		}
	}
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (a *App) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	a.refreshPublisherStateLocked()
	resp := map[string]interface{}{
		"status":                        "ok",
		"sessions":                      a.sessionCount(),
		"max_sessions":                  a.cfg.MaxSessions,
		"rtp_listen":                    a.cfg.RTPListenAddr,
		"video_mime":                    a.cfg.VideoMime,
		"ice_servers":                   a.cfg.IceServers,
		"ice_udp4_only":                 a.cfg.IceUDP4Only,
		"ice_disconnected_timeout_secs": int(a.cfg.IceDisconnectedTimeout / time.Second),
		"ice_failed_timeout_secs":       int(a.cfg.IceFailedTimeout / time.Second),
		"ice_keepalive_interval_secs":   int(a.cfg.IceKeepAliveInterval / time.Second),
		"publisher_running":             a.publisherRunning(),
		"publisher_pid":                 a.publisherPID(),
		"auto_stop_no_viewers_secs":     int(a.cfg.AutoStopNoViewers / time.Second),
		"max_stream_secs":               int(a.cfg.MaxStreamDuration / time.Second),
	}

	a.ingestMu.Lock()
	resp["rtp_packets"] = a.ingestStats.Packets
	resp["rtp_bytes"] = a.ingestStats.Bytes
	resp["rtp_parse_errors"] = a.ingestStats.ParseErrors
	resp["rtp_write_errors"] = a.ingestStats.WriteErrors
	resp["rtp_last_packet_unix"] = a.ingestStats.LastPacketUnix
	resp["rtp_last_source"] = a.ingestStats.LastSource
	a.ingestMu.Unlock()

	writeJSON(w, http.StatusOK, resp)
}

func (a *App) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	a.refreshPublisherStateLocked()
	a.ingestMu.Lock()
	stats := a.ingestStats
	a.ingestMu.Unlock()

	resp := map[string]interface{}{
		"status":           "ok",
		"app_started_unix": a.startedAt.Unix(),
		"app_uptime_secs":  int(time.Since(a.startedAt).Seconds()),
		"sessions":         map[string]interface{}{"current": a.sessionCount(), "max": a.cfg.MaxSessions},
		"ingest":           stats,
		"publisher":        a.publisherStatusLocked(),
		"process": map[string]interface{}{
			"pid": os.Getpid(),
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) handleOffer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if a.sessionCount() >= a.cfg.MaxSessions {
		writeError(w, http.StatusConflict, fmt.Sprintf("viewer penuh: maksimal %d", a.cfg.MaxSessions))
		return
	}

	var req offerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.SDP) == "" {
		writeError(w, http.StatusBadRequest, "invalid offer")
		return
	}

	pc, err := a.api.NewPeerConnection(webrtc.Configuration{ICEServers: a.iceServersConfig()})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("create peer connection failed: %v", err))
		return
	}

	sender, err := pc.AddTrack(a.videoTrack)
	if err != nil {
		_ = pc.Close()
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("add track failed: %v", err))
		return
	}
	sessionID := uuid.NewString()
	go func() {
		rtcpBuf := make([]byte, 1500)
		for {
			if _, _, readErr := sender.Read(rtcpBuf); readErr != nil {
				return
			}
			a.touchSession(sessionID)
		}
	}()

	entry := &SessionEntry{ID: sessionID, PC: pc, CreatedAt: time.Now(), LastSeen: time.Now()}
	a.sessionsMu.Lock()
	if len(a.sessions) >= a.cfg.MaxSessions {
		a.sessionsMu.Unlock()
		_ = pc.Close()
		writeError(w, http.StatusConflict, fmt.Sprintf("viewer penuh: maksimal %d", a.cfg.MaxSessions))
		return
	}
	a.sessions[sessionID] = entry
	a.sessionsMu.Unlock()

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		log.Printf("session %s state: %s", sessionID, state.String())
		switch state {
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed, webrtc.PeerConnectionStateDisconnected:
			a.removeSession(sessionID)
		}
	})

	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: req.SDP}
	if err := pc.SetRemoteDescription(offer); err != nil {
		a.removeAndCloseSession(sessionID)
		writeError(w, http.StatusBadRequest, fmt.Sprintf("set remote failed: %v", err))
		return
	}

	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		a.removeAndCloseSession(sessionID)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("create answer failed: %v", err))
		return
	}

	gatherComplete := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(answer); err != nil {
		a.removeAndCloseSession(sessionID)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("set local failed: %v", err))
		return
	}
	<-gatherComplete
	local := pc.LocalDescription()
	if local == nil {
		a.removeAndCloseSession(sessionID)
		writeError(w, http.StatusInternalServerError, "local description unavailable")
		return
	}

	a.touchSession(sessionID)
	writeJSON(w, http.StatusOK, offerResponse{SessionID: sessionID, SDP: local.SDP, Type: "answer"})
}

func (a *App) handleCandidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req candidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" || req.Candidate == "" {
		writeError(w, http.StatusBadRequest, "invalid candidate")
		return
	}
	pc := a.getSessionPC(req.SessionID)
	if pc == nil {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	init := webrtc.ICECandidateInit{
		Candidate:        req.Candidate,
		SDPMid:           strPtrOrNil(req.SDPMid),
		SDPMLineIndex:    req.SDPMLineIndex,
		UsernameFragment: strPtrOrNil(req.UsernameFragment),
	}
	if err := pc.AddICECandidate(init); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid candidate: %v", err))
		return
	}
	a.touchSession(req.SessionID)
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !a.ensureOwner(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	type sessionInfo struct {
		SessionID   string `json:"session_id"`
		CreatedUnix int64  `json:"created_unix"`
		IdleSecs    int64  `json:"idle_secs"`
	}
	resp := struct {
		Count    int           `json:"count"`
		Max      int           `json:"max"`
		Sessions []sessionInfo `json:"sessions"`
	}{Max: a.cfg.MaxSessions}

	a.sessionsMu.RLock()
	for _, s := range a.sessions {
		resp.Sessions = append(resp.Sessions, sessionInfo{
			SessionID:   s.ID,
			CreatedUnix: s.CreatedAt.Unix(),
			IdleSecs:    int64(time.Since(s.LastSeen).Seconds()),
		})
	}
	a.sessionsMu.RUnlock()
	resp.Count = len(resp.Sessions)
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) handleCameraProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !a.ensureOwner(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	cameras, err := probeCameras()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("camera probe gagal: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, cameraProbeResponse{Cameras: cameras})
}

func probeCameras() ([]cameraDevice, error) {
	cmd := exec.Command("v4l2-ctl", "--list-devices")
	out, err := cmd.Output()
	if err != nil {
		return probeCamerasByGlob()
	}

	cameras := parseCameraDevices(string(out))
	if len(cameras) == 0 {
		return probeCamerasByGlob()
	}

	for i := range cameras {
		formats, resolutions, fps := probeCameraFormatsAndCaps(cameras[i].Path)
		cameras[i].Formats = formats
		cameras[i].Resolutions = resolutions
		cameras[i].FPSOptions = fps
	}
	return usableCaptureCameras(cameras), nil
}

func probeCamerasByGlob() ([]cameraDevice, error) {
	paths, err := filepath.Glob("/dev/video*")
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)

	cameras := make([]cameraDevice, 0, len(paths))
	for _, p := range paths {
		formats, resolutions, fps := probeCameraFormatsAndCaps(p)
		cameras = append(cameras, cameraDevice{
			Name:        filepath.Base(p),
			Path:        p,
			Formats:     formats,
			Resolutions: resolutions,
			FPSOptions:  fps,
		})
	}
	return usableCaptureCameras(cameras), nil
}

func usableCaptureCameras(cameras []cameraDevice) []cameraDevice {
	out := make([]cameraDevice, 0, len(cameras))
	for _, camera := range cameras {
		if hasUsableCaptureFormat(camera.Formats) {
			out = append(out, camera)
		}
	}
	return out
}

func hasUsableCaptureFormat(formats []cameraFormat) bool {
	for _, format := range formats {
		switch strings.ToUpper(strings.TrimSpace(format.Code)) {
		case "MJPG", "JPEG", "YUYV", "YUY2", "H264", "NV12", "NV21", "BGR3", "RGB3":
			return true
		}
	}
	return false
}

func parseCameraDevices(raw string) []cameraDevice {
	sc := bufio.NewScanner(strings.NewReader(raw))
	var currentName string
	seen := map[string]struct{}{}
	out := make([]cameraDevice, 0)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trimmed, ":") {
			currentName = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if !strings.Contains(trimmed, "/dev/video") {
			continue
		}
		path := strings.Fields(trimmed)[0]
		if !strings.HasPrefix(path, "/dev/video") {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		name := currentName
		if name == "" {
			name = filepath.Base(path)
		}
		out = append(out, cameraDevice{Name: name, Path: path})
	}
	return out
}

func probeCameraFormatsAndCaps(path string) ([]cameraFormat, []string, []int) {
	cmd := exec.Command("v4l2-ctl", "--device", path, "--list-formats-ext")
	out, err := cmd.Output()
	if err != nil {
		return nil, nil, nil
	}

	codeRe := regexp.MustCompile(`'([A-Za-z0-9]{4})'`)
	sizeRe := regexp.MustCompile(`Size:\s+Discrete\s+([0-9]+x[0-9]+)`)
	fpsRe := regexp.MustCompile(`\(([0-9]+(?:\.[0-9]+)?)\s+fps\)`)

	formatSet := map[string]struct{}{}
	sizeSet := map[string]struct{}{}
	fpsSet := map[int]struct{}{}

	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		if m := codeRe.FindStringSubmatch(line); len(m) == 2 {
			formatSet[strings.ToUpper(m[1])] = struct{}{}
		}
		if m := sizeRe.FindStringSubmatch(line); len(m) == 2 {
			sizeSet[m[1]] = struct{}{}
		}
		if m := fpsRe.FindStringSubmatch(line); len(m) == 2 {
			if v, err := strconv.ParseFloat(m[1], 64); err == nil {
				fps := int(v + 0.5)
				if fps >= 1 && fps <= 120 {
					fpsSet[fps] = struct{}{}
				}
			}
		}
	}

	formats := make([]cameraFormat, 0, len(formatSet))
	for code := range formatSet {
		formats = append(formats, cameraFormat{
			Code:        code,
			FFmpegInput: ffmpegInputFormatFromCode(code),
		})
	}
	sort.Slice(formats, func(i, j int) bool {
		return formats[i].Code < formats[j].Code
	})

	resolutions := make([]string, 0, len(sizeSet))
	for size := range sizeSet {
		resolutions = append(resolutions, size)
	}
	sort.Slice(resolutions, func(i, j int) bool {
		return resolutionArea(resolutions[i]) < resolutionArea(resolutions[j])
	})

	fpsOptions := make([]int, 0, len(fpsSet))
	for fps := range fpsSet {
		fpsOptions = append(fpsOptions, fps)
	}
	sort.Ints(fpsOptions)

	return formats, resolutions, fpsOptions
}

func ffmpegInputFormatFromCode(code string) string {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "MJPG":
		return "mjpeg"
	case "JPEG":
		return "mjpeg"
	case "YUYV":
		return "yuyv422"
	case "YUY2":
		return "yuyv422"
	case "H264":
		return "h264"
	case "NV12":
		return "nv12"
	case "BGR3":
		return "bgr24"
	case "RGB3":
		return "rgb24"
	default:
		return strings.ToLower(strings.TrimSpace(code))
	}
}

func resolutionArea(v string) int {
	parts := strings.Split(strings.TrimSpace(v), "x")
	if len(parts) != 2 {
		return 0
	}
	w, errW := strconv.Atoi(parts[0])
	h, errH := strconv.Atoi(parts[1])
	if errW != nil || errH != nil || w <= 0 || h <= 0 {
		return 0
	}
	return w * h
}

func (a *App) handlePublisherStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !a.ensureOwner(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	a.refreshPublisherStateLocked()
	writeJSON(w, http.StatusOK, a.publisherStatusLocked())
}

func (a *App) handlePublisherStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !a.ensureOwner(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req publisherStartRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	bin := strings.TrimSpace(req.Bin)
	if bin == "" {
		bin = a.cfg.PublisherBin
	}
	args := req.Args
	if len(args) == 0 {
		args = a.cfg.PublisherArgs
	}
	if len(args) == 0 {
		writeError(w, http.StatusBadRequest, "publisher args kosong")
		return
	}

	started, err := a.startPublisher(bin, args)
	if err != nil {
		if errors.Is(err, errPublisherAlreadyRunning) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if started {
		writeJSON(w, http.StatusOK, a.publisherStatusLocked())
		return
	}
	writeError(w, http.StatusInternalServerError, "publisher not started")
}

func (a *App) handlePublisherStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !a.ensureOwner(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	stopped, err := a.stopPublisher("owner request")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !stopped {
		writeError(w, http.StatusConflict, "publisher tidak sedang berjalan")
		return
	}
	a.refreshPublisherStateLocked()
	writeJSON(w, http.StatusOK, a.publisherStatusLocked())
}

var errPublisherAlreadyRunning = errors.New("publisher sudah berjalan")

func (a *App) startPublisher(bin string, args []string) (bool, error) {
	a.publisherMu.Lock()
	defer a.publisherMu.Unlock()

	a.refreshPublisherStateNoLock()
	if a.publisher.Running != nil {
		return false, errPublisherAlreadyRunning
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = nil
	stderr := newLimitedBuffer(4096)
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		cancel()
		return false, fmt.Errorf("start publisher gagal: %w", err)
	}

	proc := &PublisherProcess{
		cmd:         cmd,
		done:        make(chan error, 1),
		pid:         cmd.Process.Pid,
		startedAt:   time.Now(),
		command:     bin,
		args:        append([]string{}, args...),
		cancelGuard: cancel,
		stderr:      stderr,
	}
	a.publisher.Running = proc

	go func(p *PublisherProcess) {
		err := p.cmd.Wait()
		p.done <- err
		close(p.done)
	}(proc)

	select {
	case err, ok := <-proc.done:
		exit := publisherExitFromWait(err, proc.stderr.String())
		a.publisher.LastExit = exit
		a.publisher.Running = nil
		cancel()
		if ok {
			return false, fmt.Errorf("publisher exited immediately: %s", publisherExitSummary(exit))
		}
		return false, fmt.Errorf("publisher exited immediately")
	case <-time.After(750 * time.Millisecond):
	}

	log.Printf("publisher started pid=%d cmd=%s args=%v", proc.pid, bin, args)
	return true, nil
}

func (a *App) stopPublisher(reason string) (bool, error) {
	a.publisherMu.Lock()
	a.refreshPublisherStateNoLock()
	proc := a.publisher.Running
	if proc == nil {
		a.publisherMu.Unlock()
		return false, nil
	}
	// prevent other stop attempts while we wait
	a.publisher.Running = nil
	a.publisherMu.Unlock()

	if proc.cmd.Process != nil {
		_ = proc.cmd.Process.Signal(os.Interrupt)
	}

	var waitErr error
	select {
	case waitErr = <-proc.done:
	case <-time.After(a.cfg.PublisherStopGraceDuration):
		if proc.cmd.Process != nil {
			_ = proc.cmd.Process.Kill()
		}
		waitErr = <-proc.done
	}
	proc.cancelGuard()

	exit := publisherExitFromWait(waitErr, proc.stderr.String())
	a.publisherMu.Lock()
	a.publisher.LastExit = exit
	a.publisherMu.Unlock()
	log.Printf("publisher stopped pid=%d reason=%s", proc.pid, reason)
	return true, nil
}

func publisherExitFromWait(err error, stderr string) *PublisherExit {
	exit := &PublisherExit{
		ExitedUnix: time.Now().Unix(),
		Code:       extractExitCode(err),
		Success:    err == nil,
		Stderr:     strings.TrimSpace(stderr),
	}
	if err != nil {
		exit.Error = err.Error()
	}
	return exit
}

func publisherExitSummary(exit *PublisherExit) string {
	if exit == nil {
		return "unknown"
	}
	parts := []string{fmt.Sprintf("code=%d", exit.Code)}
	if exit.Error != "" {
		parts = append(parts, exit.Error)
	}
	if exit.Stderr != "" {
		parts = append(parts, exit.Stderr)
	}
	return strings.Join(parts, " ")
}

func extractExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func (a *App) publisherStatusLocked() publisherStatusResponse {
	a.publisherMu.Lock()
	defer a.publisherMu.Unlock()
	a.refreshPublisherStateNoLock()
	if a.publisher.Running == nil {
		return publisherStatusResponse{Running: false, LastExit: a.publisher.LastExit, Args: []string{}}
	}
	p := a.publisher.Running
	return publisherStatusResponse{
		Running:     true,
		PID:         p.pid,
		StartedUnix: p.startedAt.Unix(),
		Command:     p.command,
		Args:        append([]string{}, p.args...),
		LastExit:    a.publisher.LastExit,
	}
}

func (a *App) refreshPublisherStateLocked() {
	a.publisherMu.Lock()
	defer a.publisherMu.Unlock()
	a.refreshPublisherStateNoLock()
}

func (a *App) refreshPublisherStateNoLock() {
	if a.publisher.Running == nil {
		return
	}
	select {
	case err, ok := <-a.publisher.Running.done:
		if ok {
			a.publisher.LastExit = publisherExitFromWait(err, a.publisher.Running.stderr.String())
		}
		a.publisher.Running = nil
	default:
	}
}

func (a *App) sessionCount() int {
	a.sessionsMu.RLock()
	defer a.sessionsMu.RUnlock()
	return len(a.sessions)
}

func (a *App) removeSession(sessionID string) {
	a.sessionsMu.Lock()
	delete(a.sessions, sessionID)
	a.sessionsMu.Unlock()
}

func (a *App) removeAndCloseSession(sessionID string) {
	var pc *webrtc.PeerConnection
	a.sessionsMu.Lock()
	if s, ok := a.sessions[sessionID]; ok {
		pc = s.PC
		delete(a.sessions, sessionID)
	}
	a.sessionsMu.Unlock()
	if pc != nil {
		_ = pc.Close()
	}
}

func (a *App) getSessionPC(sessionID string) *webrtc.PeerConnection {
	a.sessionsMu.RLock()
	defer a.sessionsMu.RUnlock()
	s := a.sessions[sessionID]
	if s == nil {
		return nil
	}
	return s.PC
}

func (a *App) touchSession(sessionID string) {
	a.sessionsMu.Lock()
	if s, ok := a.sessions[sessionID]; ok {
		s.LastSeen = time.Now()
	}
	a.sessionsMu.Unlock()
}

func (a *App) ensureOwner(r *http.Request) bool {
	token := r.URL.Query().Get("token")
	return token != "" && token == a.cfg.OwnerToken
}

func (a *App) publisherRunning() bool {
	a.publisherMu.Lock()
	defer a.publisherMu.Unlock()
	a.refreshPublisherStateNoLock()
	return a.publisher.Running != nil
}

func (a *App) publisherPID() int {
	a.publisherMu.Lock()
	defer a.publisherMu.Unlock()
	a.refreshPublisherStateNoLock()
	if a.publisher.Running == nil {
		return 0
	}
	return a.publisher.Running.pid
}

func (a *App) iceServersConfig() []webrtc.ICEServer {
	if len(a.cfg.IceServers) == 0 {
		return nil
	}
	s := webrtc.ICEServer{URLs: append([]string{}, a.cfg.IceServers...)}
	if a.cfg.IceUsername != "" {
		s.Username = a.cfg.IceUsername
		s.Credential = a.cfg.IceCredential
	}
	return []webrtc.ICEServer{s}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

func getenv(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func getenvInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func getenvBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func splitArgs(raw string) []string {
	fields := strings.Fields(raw)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func splitServers(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func strPtrOrNil(v string) *string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return &v
}

const indexHTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>FamilyCam Go + Pion PoC</title>
    <style>
      :root {
        --bg: #f8fafc;
        --card: #ffffff;
        --border: #dbe2ea;
        --text: #0f172a;
        --muted: #475569;
        --ok: #16a34a;
        --danger: #ef4444;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        background: radial-gradient(circle at top left, #e0f2fe 0%, var(--bg) 48%);
        color: var(--text);
        font-family: "Segoe UI", sans-serif;
      }
      .app {
        max-width: 1160px;
        margin: 0 auto;
        padding: 16px;
      }
      .layout {
        display: grid;
        grid-template-columns: 1.6fr 1fr;
        gap: 14px;
      }
      .card {
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 14px;
      }
      .row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 10px; }
      button {
        border: 0;
        border-radius: 10px;
        padding: 9px 12px;
        cursor: pointer;
        font-weight: 700;
      }
      .ok { background: var(--ok); color: #fff; }
      .danger { background: var(--danger); color: #fff; }
      .subtle { background: #e2e8f0; color: #111827; }
      input, select {
        border: 1px solid #cbd5e1;
        border-radius: 9px;
        padding: 8px 10px;
        min-height: 38px;
      }
      select { background: #fff; }
      .field { display: grid; gap: 6px; margin-bottom: 10px; }
      #video {
        width: 100%;
        border-radius: 12px;
        border: 1px solid #1e293b;
        background: #020617;
        aspect-ratio: 16 / 9;
      }
      #log {
        background: #0f172a;
        color: #e2e8f0;
        border-radius: 10px;
        padding: 10px;
        white-space: pre-wrap;
        min-height: 140px;
        max-height: 240px;
        overflow: auto;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      }
      .muted { color: var(--muted); }
      @media (max-width: 980px) {
        .layout { grid-template-columns: 1fr; }
      }
    </style>
  </head>
  <body>
    <div class="app">
      <h2>FamilyCam Go + Pion PoC</h2>
      <div class="layout">
        <section class="card">
          <h3>Viewer</h3>
          <div class="row">
            <button id="connect" class="ok">Connect</button>
            <button id="disconnect" class="danger">Disconnect</button>
          </div>
          <div class="muted"><strong>Session:</strong> <span id="session">-</span></div>
          <div class="muted"><strong>State:</strong> <span id="state">idle</span></div>
          <video id="video" autoplay playsinline muted></video>
        </section>
        <aside class="card">
          <h3>Publisher Control</h3>
          <div class="field">
            <label><strong>Owner Token</strong></label>
            <input id="ownerToken" type="password" placeholder="owner-dev-token" />
          </div>
          <div class="row">
            <button id="pubStatus" class="subtle">Publisher Status</button>
            <button id="pubStart" class="subtle">Start Test Pattern</button>
            <button id="pubStop" class="danger">Stop Publisher</button>
          </div>
          <div class="muted"><strong>Publisher:</strong> <span id="publisherState">unknown</span></div>
          <hr />
          <h4>Webcam</h4>
          <div class="row">
            <button id="cameraProbe" class="subtle">Probe Cameras</button>
            <button id="webcamStart" class="ok">Start Webcam</button>
          </div>
          <div class="field">
            <label for="cameraDevice"><strong>Device</strong></label>
            <select id="cameraDevice"></select>
          </div>
          <div class="field">
            <label for="cameraFormat"><strong>Format</strong></label>
            <select id="cameraFormat"></select>
          </div>
          <div class="field">
            <label for="cameraFPS"><strong>FPS</strong></label>
            <select id="cameraFPS"></select>
          </div>
          <div class="field">
            <label for="cameraResolution"><strong>Resolution</strong></label>
            <select id="cameraResolution"></select>
          </div>
          <hr />
          <div id="log"></div>
        </aside>
      </div>
    </div>

    <script>
      let pc = null;
      let sessionId = null;
      let iceServers = ["stun:stun.l.google.com:19302"];
      let rtpListenAddr = "127.0.0.1:6004";
      let probedCameras = [];
      const video = document.getElementById("video");
      const elState = document.getElementById("state");
      const elSession = document.getElementById("session");
      const elPublisherState = document.getElementById("publisherState");
      const elOwnerToken = document.getElementById("ownerToken");
      const elLog = document.getElementById("log");
      const elCameraDevice = document.getElementById("cameraDevice");
      const elCameraFormat = document.getElementById("cameraFormat");
      const elCameraFPS = document.getElementById("cameraFPS");
      const elCameraResolution = document.getElementById("cameraResolution");

      function log(msg) {
        const line = "[" + new Date().toISOString() + "] " + msg;
        elLog.textContent = (line + "\n" + elLog.textContent).slice(0, 7000);
        console.log(msg);
      }

      function ownerToken() {
        return elOwnerToken.value.trim();
      }

      function setSelectOptions(selectEl, options, fallbackText) {
        selectEl.innerHTML = "";
        if (!Array.isArray(options) || options.length === 0) {
          const opt = document.createElement("option");
          opt.value = "";
          opt.textContent = fallbackText;
          selectEl.appendChild(opt);
          return;
        }
        options.forEach((entry) => {
          const opt = document.createElement("option");
          opt.value = String(entry.value ?? "");
          opt.textContent = String(entry.label ?? entry.value ?? "");
          selectEl.appendChild(opt);
        });
      }

      function selectedCamera() {
        const dev = elCameraDevice.value;
        return probedCameras.find((c) => c.path === dev) || null;
      }

      function refreshCameraCapabilities() {
        const cam = selectedCamera();
        if (!cam) {
          setSelectOptions(elCameraFormat, [], "Auto");
          setSelectOptions(elCameraFPS, [{ value: "15", label: "15" }], "15");
          setSelectOptions(elCameraResolution, [{ value: "640x360", label: "640x360" }], "640x360");
          return;
        }

        const formatOptions = [{ value: "", label: "Auto (tanpa -input_format)" }];
        if (Array.isArray(cam.formats)) {
          cam.formats.forEach((f) => {
            if (!f) return;
            const code = f.code || "UNKNOWN";
            const ffmpegInput = f.ffmpeg_input || "";
            const label = ffmpegInput ? (code + " (" + ffmpegInput + ")") : code;
            formatOptions.push({ value: ffmpegInput, label });
          });
        }
        setSelectOptions(elCameraFormat, formatOptions, "Auto");

        let fpsOptions = [{ value: "10", label: "10" }, { value: "15", label: "15" }, { value: "30", label: "30" }];
        if (Array.isArray(cam.fps_options) && cam.fps_options.length > 0) {
          fpsOptions = cam.fps_options.map((v) => ({ value: String(v), label: String(v) }));
        }
        setSelectOptions(elCameraFPS, fpsOptions, "15");

        let resolutionOptions = [{ value: "640x360", label: "640x360" }, { value: "640x480", label: "640x480" }];
        if (Array.isArray(cam.resolutions) && cam.resolutions.length > 0) {
          resolutionOptions = cam.resolutions.map((v) => ({ value: v, label: v }));
        }
        setSelectOptions(elCameraResolution, resolutionOptions, "640x360");
      }

      async function refreshHealth() {
        try {
          const resp = await fetch("/healthz");
          const data = await resp.json();
          if (resp.ok) {
            if (Array.isArray(data.ice_servers)) {
              iceServers = data.ice_servers;
            }
            if (typeof data.rtp_listen === "string" && data.rtp_listen.trim()) {
              rtpListenAddr = data.rtp_listen.trim();
            }
          }
        } catch (_) {
          // ignore
        }
      }

      async function publisherRequest(path, method = "GET", body = null) {
        const token = ownerToken();
        if (!token) throw new Error("owner token belum diisi");
        const url = path + "?token=" + encodeURIComponent(token);
        const resp = await fetch(url, {
          method,
          headers: { "Content-Type": "application/json" },
          body: body ? JSON.stringify(body) : null,
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          throw new Error(data.error || ("HTTP " + resp.status));
        }
        return data;
      }

      function renderPublisherStatus(data) {
        const summary = data.running ? ("running pid=" + (data.pid || "-")) : "stopped";
        elPublisherState.textContent = summary;
      }

      async function connect() {
        if (pc) return;
        await refreshHealth();
        const cfg = iceServers.length > 0 ? { iceServers: iceServers.map((u) => ({ urls: u })) } : undefined;
        pc = new RTCPeerConnection(cfg);
        log("connect using ICE: " + (iceServers.join(",") || "(none)"));

        pc.addTransceiver("video", { direction: "recvonly" });
        pc.ontrack = (ev) => {
          if (ev.streams && ev.streams[0]) {
            video.srcObject = ev.streams[0];
            log("received remote video track");
          }
        };
        pc.onconnectionstatechange = () => {
          elState.textContent = pc.connectionState;
          log("pc state = " + pc.connectionState);
        };
        pc.onicecandidate = async (ev) => {
          if (!ev.candidate || !sessionId) return;
          try {
            await fetch("/webrtc/candidate", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                session_id: sessionId,
                candidate: ev.candidate.candidate,
                sdpMid: ev.candidate.sdpMid,
                sdpMLineIndex: ev.candidate.sdpMLineIndex,
                usernameFragment: ev.candidate.usernameFragment,
              }),
            });
          } catch (err) {
            log("candidate post error: " + err);
          }
        };

        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        const resp = await fetch("/webrtc/offer", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sdp: offer.sdp }),
        });
        const data = await resp.json();
        if (!resp.ok) {
          log("offer failed: " + JSON.stringify(data));
          await disconnect();
          return;
        }

        sessionId = data.session_id;
        elSession.textContent = sessionId;
        await pc.setRemoteDescription({ type: data.type, sdp: data.sdp });
        log("connected with session " + sessionId);
      }

      async function disconnect() {
        if (!pc) return;
        try {
          pc.close();
        } catch (_) {}
        pc = null;
        elState.textContent = "closed";
        if (sessionId) log("session " + sessionId + " closed locally");
        sessionId = null;
        elSession.textContent = "-";
      }

      async function pubStatus() {
        try {
          const data = await publisherRequest("/publisher/status");
          renderPublisherStatus(data);
          log("publisher status: " + (data.running ? "running" : "stopped"));
        } catch (err) {
          log("publisher status gagal: " + (err.message || err));
        }
      }

      async function pubStart() {
        try {
          const data = await publisherRequest("/publisher/start", "POST");
          renderPublisherStatus(data);
          log("publisher started pid=" + (data.pid || "-"));
        } catch (err) {
          log("publisher start gagal: " + (err.message || err));
        }
      }

      async function pubStop() {
        try {
          const data = await publisherRequest("/publisher/stop", "POST");
          renderPublisherStatus(data);
          log("publisher stopped");
        } catch (err) {
          log("publisher stop gagal: " + (err.message || err));
        }
      }

      async function probeCameras() {
        try {
          const data = await publisherRequest("/camera/probe");
          probedCameras = Array.isArray(data.cameras) ? data.cameras : [];
          const options = probedCameras.map((cam) => ({
            value: cam.path || "",
            label: (cam.name || "camera") + " (" + (cam.path || "-") + ")",
          }));
          setSelectOptions(elCameraDevice, options, "Tidak ada kamera");
          refreshCameraCapabilities();
          log("camera probe selesai: " + probedCameras.length + " device");
        } catch (err) {
          log("camera probe gagal: " + (err.message || err));
        }
      }

      async function startWebcam() {
        try {
          const device = elCameraDevice.value.trim();
          if (!device) throw new Error("device kamera belum dipilih");

          const inputFormat = elCameraFormat.value.trim();
          const fps = elCameraFPS.value.trim();
          const resolution = elCameraResolution.value.trim();

          const args = ["-f", "v4l2"];
          if (inputFormat) {
            args.push("-input_format", inputFormat);
          }
          if (fps) {
            args.push("-framerate", fps);
          }
          if (resolution) {
            args.push("-video_size", resolution);
          }
          args.push(
            "-i", device,
            "-an",
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-tune", "zerolatency",
            "-pix_fmt", "yuv420p",
            "-profile:v", "baseline",
            "-level", "3.1",
            "-g", "30",
            "-keyint_min", "30",
            "-sc_threshold", "0",
            "-f", "rtp",
            "rtp://" + rtpListenAddr
          );

          const data = await publisherRequest("/publisher/start", "POST", { args });
          renderPublisherStatus(data);
          log("webcam publisher started: " + device + " -> rtp://" + rtpListenAddr);
        } catch (err) {
          log("start webcam gagal: " + (err.message || err));
        }
      }

      document.getElementById("connect").addEventListener("click", connect);
      document.getElementById("disconnect").addEventListener("click", disconnect);
      document.getElementById("pubStatus").addEventListener("click", pubStatus);
      document.getElementById("pubStart").addEventListener("click", pubStart);
      document.getElementById("pubStop").addEventListener("click", pubStop);
      document.getElementById("cameraProbe").addEventListener("click", probeCameras);
      document.getElementById("webcamStart").addEventListener("click", startWebcam);
      elCameraDevice.addEventListener("change", refreshCameraCapabilities);
      refreshHealth();
      refreshCameraCapabilities();
    </script>
  </body>
</html>`
