package technologies

import (
	"fmt"
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

var curationErrorMsgToUserTemplate = "Failed to retrieve the dependencies tree for the %s project. Please contact your " +
	"Artifactory administrator to verify pass-through for Curation audit is enabled for your project"

func SuspectCurationBlockedError(isCurationCmd bool, tech techutils.Technology, cmdOutput string) (msgToUser string) {
	if !isCurationCmd {
		return
	}
	switch tech {
	case techutils.Maven:
		if strings.Contains(cmdOutput, "status code: 403") || strings.Contains(strings.ToLower(cmdOutput), "403 forbidden") ||
			strings.Contains(cmdOutput, "status code: 500") {
			msgToUser = fmt.Sprintf(curationErrorMsgToUserTemplate, techutils.Maven)
		}
	case techutils.Pip:
		if strings.Contains(strings.ToLower(cmdOutput), "http error 403") {
			msgToUser = fmt.Sprintf(curationErrorMsgToUserTemplate, techutils.Pip)
		}
	}
	return
}
	