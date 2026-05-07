package ptrutil

// DerefOr returns *p, or fallback if p is nil.
func DerefOr[T any](p *T, fallback T) T {
	if p == nil {
		return fallback
	}
	return *p
}
