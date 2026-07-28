//go:build !race

package cisco

// raceEnabled is false in normal builds; allocation-count assertions run.
const raceEnabled = false
