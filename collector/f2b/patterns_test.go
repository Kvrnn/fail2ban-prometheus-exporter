package f2b

import (
	"testing"
	"time"
)

// addBans feeds count bans for ip/jail/country into the detector, spaced one
// minute apart ending at now.
func addBans(pd *PatternDetector, ip, jail, country string, count int) {
	now := time.Now().Unix()
	for i := 0; i < count; i++ {
		pd.AddBan(ip, jail, now-int64(i*60), country)
	}
}

func TestDetectBruteForce(t *testing.T) {
	tests := []struct {
		name     string
		banCount int
		want     int
	}{
		{"below threshold", 2, 0},
		{"at threshold", 3, 1},
		{"above threshold", 5, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pd := NewPatternDetector()
			addBans(pd, "192.0.2.1", "sshd", "US", tt.banCount)

			patterns := pd.DetectBruteForce()
			if len(patterns) != tt.want {
				t.Fatalf("got %d patterns, want %d", len(patterns), tt.want)
			}
			if tt.want > 0 {
				p := patterns[0]
				if p.Type != "brute_force" || p.IP != "192.0.2.1" || p.Jail != "sshd" {
					t.Errorf("unexpected pattern attribution: %+v", p)
				}
				if p.Score != float64(tt.banCount)*10.0 {
					t.Errorf("score = %v, want %v", p.Score, float64(tt.banCount)*10.0)
				}
			}
		})
	}
}

func TestDetectBruteForceIPv6(t *testing.T) {
	pd := NewPatternDetector()
	addBans(pd, "2001:db8::1", "sshd", "US", 3)

	patterns := pd.DetectBruteForce()
	if len(patterns) != 1 {
		t.Fatalf("got %d patterns, want 1", len(patterns))
	}
	if patterns[0].IP != "2001:db8::1" || patterns[0].Jail != "sshd" {
		t.Errorf("IPv6 attribution parsed incorrectly: %+v", patterns[0])
	}
}

func TestDetectPortScan(t *testing.T) {
	tests := []struct {
		name    string
		ipCount int
		want    int
	}{
		{"below threshold", 4, 0},
		{"at threshold", 5, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pd := NewPatternDetector()
			now := time.Now().Unix()
			for i := 0; i < tt.ipCount; i++ {
				pd.AddBan("192.0.2."+string(rune('1'+i)), "sshd", now, "US")
			}

			patterns := pd.DetectPortScan()
			if len(patterns) != tt.want {
				t.Fatalf("got %d patterns, want %d", len(patterns), tt.want)
			}
			if tt.want > 0 {
				if patterns[0].Type != "port_scan" || patterns[0].Jail != "sshd" {
					t.Errorf("unexpected pattern attribution: %+v", patterns[0])
				}
			}
		})
	}
}

func TestDetectDistributed(t *testing.T) {
	pd := NewPatternDetector()
	now := time.Now().Unix()
	pd.AddBan("192.0.2.1", "sshd", now, "US")
	pd.AddBan("192.0.2.2", "sshd", now, "CN")
	pd.AddBan("192.0.2.3", "sshd", now, "RU")
	pd.AddBan("192.0.2.4", "pam-generic", now, "") // no country: ignored

	patterns := pd.DetectDistributed()
	if len(patterns) != 1 {
		t.Fatalf("got %d patterns, want 1", len(patterns))
	}
	if patterns[0].Type != "distributed" || patterns[0].Jail != "sshd" {
		t.Errorf("unexpected pattern attribution: %+v", patterns[0])
	}
	if patterns[0].Score != 3*8.0 {
		t.Errorf("score = %v, want %v", patterns[0].Score, 3*8.0)
	}
}

func TestAddBanPrunesOldEntries(t *testing.T) {
	pd := NewPatternDetector()
	now := time.Now().Unix()
	pd.AddBan("192.0.2.1", "sshd", now-(49*3600), "US") // older than 48h
	pd.AddBan("192.0.2.2", "sshd", now, "US")

	if len(pd.recentBans) != 1 {
		t.Fatalf("expected 1 retained ban, got %d", len(pd.recentBans))
	}
	if pd.recentBans[0].IP != "192.0.2.2" {
		t.Errorf("wrong ban retained: %+v", pd.recentBans[0])
	}
}

func TestDetectTemporalPattern(t *testing.T) {
	pd := NewPatternDetector()
	banTime := time.Now().Add(-time.Hour)
	pd.AddBan("192.0.2.1", "sshd", banTime.Unix(), "US")
	pd.AddBan("192.0.2.2", "sshd", banTime.Unix(), "US")

	hourCounts, dayCounts := pd.DetectTemporalPattern()
	if hourCounts[banTime.Hour()] != 2 {
		t.Errorf("hourCounts[%d] = %d, want 2", banTime.Hour(), hourCounts[banTime.Hour()])
	}
	if dayCounts[int(banTime.Weekday())] != 2 {
		t.Errorf("dayCounts[%d] = %d, want 2", int(banTime.Weekday()), dayCounts[int(banTime.Weekday())])
	}
}

func TestCalculateAttackVelocity(t *testing.T) {
	pd := NewPatternDetector()
	now := time.Now().Unix()
	pd.AddBan("192.0.2.1", "sshd", now-60, "US")     // within last hour
	pd.AddBan("192.0.2.2", "sshd", now-120, "US")    // within last hour
	pd.AddBan("192.0.2.3", "sshd", now-2*3600, "US") // outside last hour

	if v := pd.CalculateAttackVelocity(1); v != 2.0 {
		t.Errorf("velocity = %v, want 2.0", v)
	}
	if v := pd.CalculateAttackVelocity(0); v != 0.0 {
		t.Errorf("velocity with 0 hours = %v, want 0.0", v)
	}
}

func TestCalculateSuspiciousScore(t *testing.T) {
	pd := NewPatternDetector()
	if score := pd.CalculateSuspiciousScore(); score != 0.0 {
		t.Errorf("empty detector score = %v, want 0", score)
	}

	// Brute force (3 bans same IP/jail) also counts toward velocity
	addBans(pd, "192.0.2.1", "sshd", "US", 3)
	score := pd.CalculateSuspiciousScore()
	if score < 20.0 || score > 100.0 {
		t.Errorf("score = %v, want within [20, 100]", score)
	}
}

func TestGetCustomerLabels(t *testing.T) {
	labels := getCustomerLabels("cust-1", "Acme", "tenant-9")
	want := []string{"cust-1", "Acme", "tenant-9"}
	if len(labels) != len(want) {
		t.Fatalf("got %d labels, want %d", len(labels), len(want))
	}
	for i := range want {
		if labels[i] != want[i] {
			t.Errorf("labels[%d] = %q, want %q", i, labels[i], want[i])
		}
	}
}
