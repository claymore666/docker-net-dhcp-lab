package sourceadapter

// ShapeNAReasoner is optionally implemented by an adapter whose source
// cannot be judged on some network shape: shape and scenario are the
// strings the verdict files carry. A non-empty answer makes that run N/A
// with the reason, never a FAIL read as a plugin fault (D1, lab #10).
type ShapeNAReasoner interface {
	NAShapeReason(shape, scenario string) string
}
