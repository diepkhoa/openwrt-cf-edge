//go:build !linux && !darwin && !freebsd

package state

func acquireFileLock(_ string) (func(), error) {
	return func() {}, nil
}
