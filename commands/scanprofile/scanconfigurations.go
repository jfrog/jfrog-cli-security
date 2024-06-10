package scanprofile

import "github.com/jfrog/jfrog-cli-core/v2/utils/config"

type ScanProfileCommand struct {
	serverDetails                    *config.ServerDetails
}

func NewScanProfileCommand() *ScanProfileCommand {
	return &ScanProfileCommand{}
}

func (auditCmd *ScanProfileCommand) CommandName() string {
	return "scan-profile"
}

func (auditCmd *ScanProfileCommand) ServerDetails() (*config.ServerDetails, error) {
	return auditCmd.serverDetails, nil
}

func (spc *ScanProfileCommand) Run() error {
	_, err := spc.DetectScanProfileCommand()
	// Print output
	return err
}

// To be used internally by the CLI
func  (spc *ScanProfileCommand) DetectScanProfileCommand() (string, error) {
	// Get scan profile (TODO: when API ready)

	// Get local scan profile (if exists) and override

	// Create scan profile based on user input (remote, local, flags, env...)

	// Detect tech information and descriptors (+ detect modules if needed -> create config based on default profile)

	return "profile", nil
}