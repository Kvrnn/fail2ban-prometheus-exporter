package geo

// Provider interface for geo-tagging IP addresses
type Provider interface {
	// Annotate returns a map of labels for the given IP address
	// Returns nil if geo-tagging is not available or fails
	Annotate(ip string) map[string]string
	
	// GetLabels returns the list of label names this provider will return
	GetLabels() []string
}

