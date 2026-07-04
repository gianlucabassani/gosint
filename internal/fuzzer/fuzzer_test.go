package fuzzer

import "testing"

func boolPtr(b bool) *bool { return &b }

// newTestFuzzer builds a fuzzer with auto-filter state ready without running a scan.
func newTestFuzzer(autoFilter bool, threshold int) *Fuzzer {
	f := NewFuzzer(FuzzerConfig{
		Target:     "https://example.com",
		Mode:       ModeDirectory,
		MatchCodes: []int{200, 301, 403},
		AutoFilter: boolPtr(autoFilter),
	})
	f.threshold = threshold
	return f
}

func TestRecordAndDecideDisabledKeepsEverything(t *testing.T) {
	f := newTestFuzzer(false, 3)
	for i := 0; i < 100; i++ {
		save, _, _ := f.recordAndDecide(FuzzResult{StatusCode: 200, Size: 512})
		if !save {
			t.Fatalf("auto-filter disabled but result %d was suppressed", i)
		}
	}
	if f.found != 100 || len(f.results) != 100 {
		t.Fatalf("expected 100 kept, got found=%d results=%d", f.found, len(f.results))
	}
}

func TestRecordAndDecideFlagsNoiseCluster(t *testing.T) {
	f := newTestFuzzer(true, 3)

	// First `threshold` identical responses are kept optimistically.
	for i := 0; i < 3; i++ {
		save, flagged, _ := f.recordAndDecide(FuzzResult{StatusCode: 200, Size: 1024})
		if !save || flagged != "" {
			t.Fatalf("result %d should be kept before threshold, save=%v flagged=%q", i, save, flagged)
		}
	}

	// The one that crosses the threshold flags the signature and prunes the rest.
	save, flagged, count := f.recordAndDecide(FuzzResult{StatusCode: 200, Size: 1024})
	if save {
		t.Fatal("threshold-crossing result should not be saved")
	}
	if flagged != "200:1024" {
		t.Fatalf("expected signature 200:1024 flagged, got %q", flagged)
	}
	if count != 4 {
		t.Fatalf("expected 4 removed (3 pruned + current), got %d", count)
	}
	if f.found != 0 || len(f.results) != 0 {
		t.Fatalf("expected all noise pruned, got found=%d results=%d", f.found, len(f.results))
	}

	// Subsequent identical responses are silently suppressed.
	save, flagged, _ = f.recordAndDecide(FuzzResult{StatusCode: 200, Size: 1024})
	if save || flagged != "" {
		t.Fatalf("post-flag result should be silently suppressed, save=%v flagged=%q", save, flagged)
	}
	if f.suppressed != 5 {
		t.Fatalf("expected 5 suppressed total, got %d", f.suppressed)
	}
}

func TestRecordAndDecideKeepsDistinctResults(t *testing.T) {
	f := newTestFuzzer(true, 3)
	// Distinct sizes must never be filtered, even in large numbers.
	for i := 0; i < 50; i++ {
		save, _, _ := f.recordAndDecide(FuzzResult{StatusCode: 200, Size: i})
		if !save {
			t.Fatalf("distinct result %d wrongly suppressed", i)
		}
	}
	if f.found != 50 {
		t.Fatalf("expected 50 distinct results kept, got %d", f.found)
	}
}

func TestBaselineSuppression(t *testing.T) {
	f := newTestFuzzer(true, 100)
	f.baselineSigs["200:777"] = true
	f.baselineCodes[403] = true

	if save, _, _ := f.recordAndDecide(FuzzResult{StatusCode: 200, Size: 777}); save {
		t.Fatal("calibrated baseline signature should be suppressed")
	}
	if save, _, _ := f.recordAndDecide(FuzzResult{StatusCode: 403, Size: 12}); save {
		t.Fatal("calibrated baseline code should be suppressed regardless of size")
	}
	if save, _, _ := f.recordAndDecide(FuzzResult{StatusCode: 200, Size: 42}); !save {
		t.Fatal("non-baseline response should be kept")
	}
}
