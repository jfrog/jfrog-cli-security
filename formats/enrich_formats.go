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

type EnrichJson struct {
	Vulnerability []struct {
		BomRef string `json:"bom-ref,"`
		Id     string `json:"id"`
	} `json:"vulnerabilities"`
}

type Bom struct {
	Vulnerabilities struct {
		Vulnerability []struct {
			BomRef string `xml:"bom-ref,attr"`
			Id     string `xml:"id"`
		} `xml:"vulnerability"`
	} `xml:"vulnerabilities"`
}
