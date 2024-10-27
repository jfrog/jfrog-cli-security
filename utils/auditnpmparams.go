package utils

type AuditNpmParams struct {
	AuditParams
	npmOverwritePackageLock bool
}

func (anp AuditNpmParams) SetNpmOverwritePackageLock(overwritePackageLock bool) AuditNpmParams {
	anp.npmOverwritePackageLock = overwritePackageLock
	return anp
}

func (anp AuditNpmParams) NpmOverwritePackageLock() bool {
	return anp.npmOverwritePackageLock
}
