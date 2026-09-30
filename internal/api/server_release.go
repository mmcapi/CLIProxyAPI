package api

import "github.com/router-for-me/CLIProxyAPI/v8/internal/releasecontrol"

// SetReleaseController installs admission control before the listener starts.
func (s *Server) SetReleaseController(controller *releasecontrol.Controller) {
	if controller != nil {
		s.server.Handler = controller.Wrap(s.server.Handler)
	}
}
