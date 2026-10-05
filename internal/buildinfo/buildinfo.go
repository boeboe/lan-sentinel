// Package buildinfo holds version metadata stamped in at link time.
package buildinfo

import "runtime"

// Set with -ldflags "-X lan-sentinel/internal/buildinfo.Version=..." etc.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Info is the build metadata reported by `lan-sentinel version`.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get returns the build metadata of the running binary.
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}
