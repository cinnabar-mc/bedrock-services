package fake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const sessionPath = "/serviceconfigs/00000000-0000-0000-0000-000000000007/sessionTemplates/MinecraftLobby/sessions/Fixture"

// WaitDirectoryConnection waits on an observed member binding instead of polling a clock.
func (s *Server) WaitDirectoryConnection(connection int) {
	for {
		s.mu.Lock()
		if s.directoryChanged == nil {
			s.directoryChanged = make(chan struct{}, 1)
		}
		changed := s.directoryChanged
		properties, _ := s.directoryMember["properties"].(map[string]any)
		system, _ := properties["system"].(map[string]any)
		current, _ := system["connection"].(string)
		s.mu.Unlock()
		if current == fmt.Sprintf("00000000-0000-0000-0000-%012d", connection) {
			return
		}
		<-changed
	}
}

// directoryAttrs preserves conditional writes and stable join intent without exposing random IDs.
func (s *Server) directoryAttrs(endpoint string, header http.Header, body []byte) []string {
	attrs := []string{"if-match=" + header.Get("If-Match")}
	var binding struct {
		Members map[string]struct {
			Properties struct{ System struct{ Connection string } }
		}
	}
	_ = json.Unmarshal(body, &binding)
	if connection := binding.Members["me"].Properties.System.Connection; connection != "" {
		attrs = append(attrs, "connection="+connection)
	}
	if endpoint == "mpsd.join" {
		var value any
		_ = json.Unmarshal(body, &value)
		canonical, _ := json.Marshal(value)
		key := "join:" + string(canonical)
		intent, ok := s.state.Labels[key]
		if !ok {
			intent = s.issue("intent")
			s.state.Labels[key] = intent
		}
		attrs = append(attrs, "intent="+intent)
	}
	return attrs
}

// directoryReply applies the caller's member patch and returns a complete original fixture snapshot.
func (s *Server) directoryReply(body []byte) Reply {
	var patch struct{ Members map[string]map[string]any }
	_ = json.Unmarshal(body, &patch)
	member := patch.Members["me"]
	if member, present := patch.Members["me"]; present && member == nil {
		s.directoryMember = nil
		return Reply{Status: 204, Header: http.Header{}}
	}
	if s.directoryMember == nil {
		s.directoryMember = map[string]any{}
	}
	mergeMember(s.directoryMember, member)
	s.state.Issued["directory"]++
	r := reply(200, map[string]any{"branch": "00000000-0000-0000-0000-000000000008", "changeNumber": s.state.Issued["directory"],
		"members": map[string]any{"me": s.directoryMember}, "membersInfo": map[string]any{"first": 0, "next": 1},
		"correlationId": "fixture", "constants": map[string]any{"system": map[string]any{}}, "properties": map[string]any{"system": map[string]any{}}})
	r.Header.Set("Content-Location", sessionPath)
	r.Header.Set("ETag", fmt.Sprintf("\"v%d\"", s.state.Issued["directory"]))
	if s.directoryChanged != nil {
		select {
		case s.directoryChanged <- struct{}{}:
		default:
		}
	}
	return r
}

// mergeMember preserves unrelated member fields when a reconnect patches only its connection.
func mergeMember(target, patch map[string]any) {
	for name, value := range patch {
		if object, ok := value.(map[string]any); ok {
			current, ok := target[name].(map[string]any)
			if !ok {
				current = map[string]any{}
			}
			mergeMember(current, object)
			target[name] = current
		} else if value == nil {
			delete(target, name)
		} else {
			target[name] = value
		}
	}
}

// isDirectory identifies only the finite handle and session routes used by this peer.
func isDirectory(host, path string) string {
	if host != "sessiondirectory.xboxlive.com" {
		return ""
	}
	if path == "/handles" {
		return "mpsd.activity"
	}
	if strings.HasPrefix(path, "/handles/") && strings.HasSuffix(path, "/session") {
		return "mpsd.join"
	}
	if path == sessionPath {
		return "mpsd.update"
	}
	return ""
}
