package inspect

type SdkInspectResponse struct {
	Errors  []string       `json:"errors"`
	Success bool           `json:"success"`
	Values  map[string]any `json:"values"`
}
