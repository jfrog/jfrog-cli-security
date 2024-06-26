package formats

type Vulnerability struct {
	BomRef string `json:"bom-ref" xml:"bom-ref,attr"`
	ID     string `json:"id" xml:"id"`
}

type XMLVulnerability struct {
	Vulnerability []Vulnerability `xml:"vulnerability"`
}

type Vulnerabilities struct {
	Vulnerabilities XMLVulnerability `xml:"vulnerabilities"`
}
