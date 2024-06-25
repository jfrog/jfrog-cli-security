package utils

const (
	NodeModulesPattern = "**/*node_modules*/**"
	JfMsiEnvVariable                          = "JF_MSI"
)

var (
	DefaultExcludePatterns = []string{"**/.git/**", "**/*test*/**", "**/*venv*/**", NodeModulesPattern, "**/target/**"}
)

const (
	ContextualAnalysisScan SubScanType = "contextual_analysis"
	ScaScan                SubScanType = "sca"
	IacScan                SubScanType = "iac"
	SastScan               SubScanType = "sast"
	SecretsScan            SubScanType = "secrets"
)

type SubScanType string

func (s SubScanType) String() string {
	return string(s)
}

func GetAllSupportedScans() []SubScanType {
	return []SubScanType{ScaScan, ContextualAnalysisScan, IacScan, SastScan, SecretsScan}
}
