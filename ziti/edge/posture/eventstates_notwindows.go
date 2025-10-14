//go:build !windows
// +build !windows

package posture

// NewEvenState is a stand-in for actual non-Windows event watching
func NewEventState() EventState {
	return &NoOpEventState{}
}
