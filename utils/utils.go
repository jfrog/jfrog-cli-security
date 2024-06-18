package utils

const (
	ScaScan     SubScanType = "sca"
	IacScan     SubScanType = "iac"
	SastScan    SubScanType = "sast"
	SecretsScan SubScanType = "secrets"
)

type SubScanType string

func (s SubScanType) String() string {
	return string(s)
}

func GetAllSupportedScans() []SubScanType {
	return []SubScanType{ScaScan, IacScan, SastScan, SecretsScan}
}
