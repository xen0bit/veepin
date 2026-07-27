//go:build !race

package dataplane

// raceEnabled is false in normal builds; allocation-count assertions run.
const raceEnabled = false
