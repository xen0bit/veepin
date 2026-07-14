//go:build !race

package esp

// raceEnabled is false in normal builds; allocation-count assertions run.
const raceEnabled = false
