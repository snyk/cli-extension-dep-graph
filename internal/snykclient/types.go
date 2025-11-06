//nolint:tagliatelle // Allowing snake case for API response schemas
package snykclient

type ScanResultTarget struct {
	RemoteURL string `json:"remoteUrl"`
}

type ScanResultIdentity struct {
	Type       string            `json:"type"`
	TargetFile string            `json:"targetFile,omitempty"`
	Args       map[string]string `json:"args,omitempty"`
}

type ScanResultFact struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type ScanResult struct {
	Name            string             `json:"name"`
	Policy          string             `json:"policy,omitempty"`
	Facts           []*ScanResultFact  `json:"facts"`
	Target          ScanResultTarget   `json:"target"`
	Identity        ScanResultIdentity `json:"identity"`
	TargetReference string             `json:"targetReference,omitempty"`
}

type ConversionWarning struct {
	Type   string `json:"type"`
	BOMRef string `json:"bom_ref"`
	Msg    string `json:"msg"`
}

type SBOMConvertResponse struct {
	ScanResults       []*ScanResult        `json:"scanResults"`
	ConversionWarning []*ConversionWarning `json:"warnings"`
}
