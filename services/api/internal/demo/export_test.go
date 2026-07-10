package demo

import "time"

// Test-only hooks for the live-inversion cost guards.

// LiveInvertMaxPerHourForTest exposes the rolling-hour cap to the external test package.
const LiveInvertMaxPerHourForTest = liveInvertMaxPerHour

// ForensicsMaxPerHourForTest exposes the shared agent budget cap to the external test package.
const ForensicsMaxPerHourForTest = forensicsMaxPerHour

// SetNowForTest injects a deterministic clock for the rate-limit test.
func (s *Service) SetNowForTest(now func() time.Time) {
	s.now = now
}
