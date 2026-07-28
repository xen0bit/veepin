//go:build race

package cisco

// raceEnabled is true under -race, where the detector's instrumentation perturbs
// allocation counts, so allocation-count assertions are skipped.
const raceEnabled = true
