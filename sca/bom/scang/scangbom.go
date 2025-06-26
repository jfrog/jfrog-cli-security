package scang

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

type ScangBomGenerator struct {
}

func NewScangBomGenerator() *ScangBomGenerator {
	return &ScangBomGenerator{}
}

func (sbg *ScangBomGenerator) WithOptions(options ...bom.SbomGeneratorOption) bom.SbomGenerator {
	for _, option := range options {
		option(sbg)
	}
	return sbg
}

func (sbg *ScangBomGenerator) PrepareGenerator() (err error) {
	// No preparation needed for ScangBomGenerator
	return nil
}

func (sbg *ScangBomGenerator) CleanUp() (err error) {
	// No cleanup needed for ScangBomGenerator
	return nil
}

func (sbg *ScangBomGenerator) GenerateSbom(target results.ScanTarget) (sbom *cyclonedx.BOM, err error) {
	return
}
