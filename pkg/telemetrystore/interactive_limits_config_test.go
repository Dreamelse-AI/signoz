package telemetrystore

import "testing"

func TestInteractiveLimitsConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits InteractiveLimits
		fail   bool
	}{
		{"disabled", InteractiveLimits{}, false},
		{"enabled", InteractiveLimits{100, 2048, 1024, 30}, false},
		{"partial", InteractiveLimits{MaxMemoryUsage: 1024}, true},
		{"negative", InteractiveLimits{100, 2048, 1024, -1}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Clickhouse: ClickhouseConfig{InteractiveLimits: tc.limits}}
			if (c.Validate() != nil) != tc.fail {
				t.Fatal("unexpected validation result")
			}
		})
	}
}
