package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	ioUtils "github.com/jfrog/jfrog-client-go/utils/io"
)

type AuditParams interface {
	DirectDependencies() *[]string
	AppendDependenciesForApplicabilityScan(directDependencies []string) *AuditBasicParams
	ServerDetails() (*config.ServerDetails, error)
	SetServerDetails(serverDetails *config.ServerDetails) *AuditBasicParams
	PipRequirementsFile() string
	SetPipRequirementsFile(requirementsFile string) *AuditBasicParams
	ExcludeTestDependencies() bool
	SetExcludeTestDependencies(excludeTestDependencies bool) *AuditBasicParams
	UseWrapper() bool
	SetUseWrapper(useWrapper bool) *AuditBasicParams
	InsecureTls() bool
	SetInsecureTls(insecureTls bool) *AuditBasicParams
	Technologies() []string
	SetTechnologies(technologies []string) *AuditBasicParams
	Progress() ioUtils.ProgressMgr
	SetProgress(progress ioUtils.ProgressMgr)
	Args() []string
	InstallCommandName() string
	InstallCommandArgs() []string
	SetNpmScope(depType string) *AuditBasicParams
	SetMaxTreeDepth(maxTreeDepth string) *AuditBasicParams
	MaxTreeDepth() string
	OutputFormat() format.OutputFormat
	DepsRepo() string
	SetDepsRepo(depsRepo string) *AuditBasicParams
	IgnoreConfigFile() bool
	SetIgnoreConfigFile(ignoreConfigFile bool) *AuditBasicParams
	IsMavenDepTreeInstalled() bool
	SetIsMavenDepTreeInstalled(isMavenDepTreeInstalled bool) *AuditBasicParams
	IsCurationCmd() bool
	SetIsCurationCmd(bool) *AuditBasicParams
	SetExclusions(exclusions []string) *AuditBasicParams
	Exclusions() []string
	SetIsRecursiveScan(isRecursiveScan bool) *AuditBasicParams
	IsRecursiveScan() bool
	SkipAutoInstall() bool
	AllowPartialResults() bool
}

type AuditBasicParams struct {
	serverDetails                    *config.ServerDetails
	outputFormat                     format.OutputFormat
	progress                         ioUtils.ProgressMgr
	useJas                           bool
	excludeTestDependencies          bool
	useWrapper                       bool
	insecureTls                      bool
	ignoreConfigFile                 bool
	isMavenDepTreeInstalled          bool
	isCurationCmd                    bool
	maxTreeDepth                     string
	pipRequirementsFile              string
	depsRepo                         string
	installCommandName               string
	technologies                     []string
	scansToPreform                   []SubScanType
	args                             []string
	installCommandArgs               []string
	dependenciesForApplicabilityScan []string
	exclusions                       []string
	isRecursiveScan                  bool
	skipAutoInstall                  bool
	allowPartialResults              bool
	xrayVersion                      string
	xscVersion                       string
}

func (abp *AuditBasicParams) DirectDependencies() *[]string {
	return &abp.dependenciesForApplicabilityScan
}

func (abp *AuditBasicParams) AppendDependenciesForApplicabilityScan(directDependencies []string) *AuditBasicParams {
	abp.dependenciesForApplicabilityScan = append(abp.dependenciesForApplicabilityScan, directDependencies...)
	return abp
}

func (abp *AuditBasicParams) ServerDetails() (*config.ServerDetails, error) {
	return abp.serverDetails, nil
}

func (abp *AuditBasicParams) SetServerDetails(serverDetails *config.ServerDetails) *AuditBasicParams {
	abp.serverDetails = serverDetails
	return abp
}

func (abp *AuditBasicParams) SetInstallCommandArgs(installCommandArgs []string) *AuditBasicParams {
	abp.installCommandArgs = installCommandArgs
	return abp
}

func (abp *AuditBasicParams) SetInstallCommandName(installCommandName string) *AuditBasicParams {
	abp.installCommandName = installCommandName
	return abp
}

func (abp *AuditBasicParams) SetUseJas(useJas bool) *AuditBasicParams {
	abp.useJas = useJas
	return abp
}

func (abp *AuditBasicParams) SetSkipAutoInstall(skipAutoInstall bool) *AuditBasicParams {
	abp.skipAutoInstall = skipAutoInstall
	return abp
}

func (abp *AuditBasicParams) SetAllowPartialResults(allowPartialResults bool) *AuditBasicParams {
	abp.allowPartialResults = allowPartialResults
	return abp
}

func (abp *AuditBasicParams) UseJas() bool {
	return abp.useJas
}

func (abp *AuditBasicParams) MaxTreeDepth() string {
	return abp.maxTreeDepth
}

func (abp *AuditBasicParams) SetMaxTreeDepth(maxTreeDepth string) *AuditBasicParams {
	abp.maxTreeDepth = maxTreeDepth
	return abp
}

func (abp *AuditBasicParams) PipRequirementsFile() string {
	return abp.pipRequirementsFile
}

func (abp *AuditBasicParams) SetPipRequirementsFile(requirementsFile string) *AuditBasicParams {
	abp.pipRequirementsFile = requirementsFile
	return abp
}

func (abp *AuditBasicParams) ExcludeTestDependencies() bool {
	return abp.excludeTestDependencies
}

func (abp *AuditBasicParams) SetExcludeTestDependencies(excludeTestDependencies bool) *AuditBasicParams {
	abp.excludeTestDependencies = excludeTestDependencies
	return abp
}

func (abp *AuditBasicParams) UseWrapper() bool {
	return abp.useWrapper
}

func (abp *AuditBasicParams) SetUseWrapper(useWrapper bool) *AuditBasicParams {
	abp.useWrapper = useWrapper
	return abp
}

func (abp *AuditBasicParams) InsecureTls() bool {
	return abp.insecureTls
}

func (abp *AuditBasicParams) SetInsecureTls(insecureTls bool) *AuditBasicParams {
	abp.insecureTls = insecureTls
	return abp
}

func (abp *AuditBasicParams) Technologies() []string {
	return abp.technologies
}

func (abp *AuditBasicParams) SetTechnologies(technologies []string) *AuditBasicParams {
	abp.technologies = technologies
	return abp
}

func (abp *AuditBasicParams) SetScansToPerform(scansToPerform []SubScanType) *AuditBasicParams {
	abp.scansToPreform = scansToPerform
	return abp
}

func (abp *AuditBasicParams) ScansToPerform() []SubScanType {
	return abp.scansToPreform
}

func (abp *AuditBasicParams) Progress() ioUtils.ProgressMgr {
	return abp.progress
}

func (abp *AuditBasicParams) SetProgress(progress ioUtils.ProgressMgr) {
	abp.progress = progress
}

func (abp *AuditBasicParams) Args() []string {
	return abp.args
}

func (abp *AuditBasicParams) InstallCommandName() string {
	return abp.installCommandName
}

func (abp *AuditBasicParams) InstallCommandArgs() []string {
	return abp.installCommandArgs
}

func (abp *AuditBasicParams) SetNpmScope(depType string) *AuditBasicParams {
	switch depType {
	case "devOnly":
		abp.args = []string{"--dev"}
	case "prodOnly":
		abp.args = []string{"--prod"}
	}
	return abp
}

func (abp *AuditBasicParams) SetConanProfile(file string) *AuditBasicParams {
	abp.args = append(abp.args, "--profile:build", file)
	return abp
}

func (abp *AuditBasicParams) OutputFormat() format.OutputFormat {
	return abp.outputFormat
}

func (abp *AuditBasicParams) SetOutputFormat(format format.OutputFormat) *AuditBasicParams {
	abp.outputFormat = format
	return abp
}

func (abp *AuditBasicParams) DepsRepo() string {
	return abp.depsRepo
}

func (abp *AuditBasicParams) SetDepsRepo(depsRepo string) *AuditBasicParams {
	abp.depsRepo = depsRepo
	return abp
}

func (abp *AuditBasicParams) IgnoreConfigFile() bool {
	return abp.ignoreConfigFile
}

func (abp *AuditBasicParams) SetIgnoreConfigFile(ignoreConfigFile bool) *AuditBasicParams {
	abp.ignoreConfigFile = ignoreConfigFile
	return abp
}

func (abp *AuditBasicParams) IsMavenDepTreeInstalled() bool {
	return abp.isMavenDepTreeInstalled
}

func (abp *AuditBasicParams) SetIsMavenDepTreeInstalled(isMavenDepTreeInstalled bool) *AuditBasicParams {
	abp.isMavenDepTreeInstalled = isMavenDepTreeInstalled
	return abp
}

func (abp *AuditBasicParams) IsCurationCmd() bool {
	return abp.isCurationCmd
}

func (abp *AuditBasicParams) SetIsCurationCmd(isCurationCmd bool) *AuditBasicParams {
	abp.isCurationCmd = isCurationCmd
	return abp
}

func (abp *AuditBasicParams) Exclusions() []string {
	return abp.exclusions
}

func (abp *AuditBasicParams) SetExclusions(exclusions []string) *AuditBasicParams {
	abp.exclusions = exclusions
	return abp
}

func (abp *AuditBasicParams) SetIsRecursiveScan(isRecursiveScan bool) *AuditBasicParams {
	abp.isRecursiveScan = isRecursiveScan
	return abp
}

func (abp *AuditBasicParams) IsRecursiveScan() bool {
	return abp.isRecursiveScan
}

func (abp *AuditBasicParams) SkipAutoInstall() bool {
	return abp.skipAutoInstall
}

func (abp *AuditBasicParams) AllowPartialResults() bool {
	return abp.allowPartialResults
}

func (abp *AuditBasicParams) SetXrayVersion(xrayVersion string) *AuditBasicParams {
	abp.xrayVersion = xrayVersion
	return abp
}

func (abp *AuditBasicParams) GetXrayVersion() string {
	return abp.xrayVersion
}

func (abp *AuditBasicParams) SetXscVersion(xscVersion string) *AuditBasicParams {
	abp.xscVersion = xscVersion
	return abp
}

func (abp *AuditBasicParams) GetXscVersion() string {
	return abp.xscVersion
}
