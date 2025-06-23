package indexer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
	xrayClientUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-security/sca/bom"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

const (
	indexingCommand          = "graph"
	fileNotSupportedExitCode = 3
)

// IndexerBomGenerator is a BomGenerator that uses the Xray Indexer to generate a CycloneDX SBOM.
// It indexes a file and converts the resulting component graph to a CycloneDX SBOM.
type IndexerBomGenerator struct {
	BypassArchiveLimits bool

	xrayManager *xray.XrayServicesManager
	xrayVersion string

	indexerPath    string
	indexerTempDir string
}

func NewIndexerBomGenerator() *IndexerBomGenerator {
	return &IndexerBomGenerator{}
}

func WithXray(manager *xray.XrayServicesManager, xrayVersion string) bom.SbomGeneratorOption {
	return func(sg bom.SbomGenerator) error {
		generator, ok := sg.(*IndexerBomGenerator)
		if !ok {
			return nil
		}
		generator.xrayManager = manager
		generator.xrayVersion = xrayVersion
		return nil
	}
}

func WithBypassArchiveLimits(bypass bool) bom.SbomGeneratorOption {
	return func(sg bom.SbomGenerator) error {
		generator, ok := sg.(*IndexerBomGenerator)
		if !ok {
			return nil
		}
		generator.BypassArchiveLimits = bypass
		return nil
	}
}

func (ibg *IndexerBomGenerator) PrepareGenerator(options ...bom.SbomGeneratorOption) (err error) {
	// Parse the generator options to prepare it for use.
	for _, option := range options {
		if err = option(ibg); err != nil {
			return err
		}
	}
	if ibg.xrayManager == nil || ibg.xrayVersion == "" {
		return fmt.Errorf("Xray manager and version must be set using WithXray option")
	}
	if ibg.indexerPath, err = DownloadIndexerIfNeeded(ibg.xrayManager, ibg.xrayVersion); err != nil {
		return
	}
	// Create Temp dir for Xray Indexer, required for indexing files.
	ibg.indexerTempDir, err = fileutils.CreateTempDir()
	return
}

func (ibg *IndexerBomGenerator) CleanUp() error {
	if ibg.indexerTempDir == "" {
		return nil
	}
	return fileutils.RemoveTempDir(ibg.indexerTempDir)
}

func (ibg *IndexerBomGenerator) GenerateSbom(target results.ScanTarget) (sbom *cyclonedx.BOM, err error) {
	// Create the CycloneDX BOM
	sbom = CreateTargetEmptySbom(target)
	// Run the Xray Indexer to index the file
	graph, err := ibg.IndexFile(target.Target)
	if errorutils.CheckError(err) != nil || graph == nil {
		return nil, fmt.Errorf("failed to index file %s: %w", target.Target, err)
	}
	// In case of empty graph returned by the indexer,
	// for instance due to unsupported file format, continue without sending a
	// graph request to Xray.
	if graph.Id == "" {
		log.Debug(fmt.Sprintf("Empty component graph returned for file %s", target.Target))
		return
	}
	if graphSter, err := utils.GetAsJsonString(graph, false, true); err == nil {
		log.Debug(fmt.Sprintf("Component graph for file %s:\n%s", target.Target, graphSter))
	}
	// Convert the graph to CycloneDX SBOM format
	sbom.Components, sbom.Dependencies = results.CompTreeToSbom(graph)
	return
}

func CreateTargetEmptySbom(target results.ScanTarget) *cyclonedx.BOM {
	// Create an empty CycloneDX BOM for the target
	sbom := cyclonedx.NewBOM()
	binaryFileComponent := cdxutils.CreateFileOrDirComponent(target.Target)
	sbom.Metadata = &cyclonedx.Metadata{Component: &binaryFileComponent}
	return sbom
}

func (ibg *IndexerBomGenerator) IndexFile(filePath string) (*xrayClientUtils.BinaryGraphNode, error) {
	var indexerResults xrayClientUtils.BinaryGraphNode
	indexerCmd := exec.Command(ibg.indexerPath, indexingCommand, filePath, "--temp-dir", ibg.indexerTempDir)
	if ibg.BypassArchiveLimits {
		indexerCmd.Args = append(indexerCmd.Args, "--bypass-archive-limits")
	}
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	indexerCmd.Stdout = &stdout
	indexerCmd.Stderr = &stderr
	err := indexerCmd.Run()
	if err != nil {
		var e *exec.ExitError
		if errors.As(err, &e) {
			if e.ExitCode() == fileNotSupportedExitCode {
				log.Debug(fmt.Sprintf("File %s is not supported by Xray indexer app.", filePath))
				return &indexerResults, nil
			}
		}
		return nil, errorutils.CheckErrorf("Xray indexer app failed indexing %s with %s: %s", filePath, err, stderr.String())
	}
	if stderr.String() != "" {
		log.Info(stderr.String())
	}
	err = json.Unmarshal(stdout.Bytes(), &indexerResults)
	return &indexerResults, errorutils.CheckError(err)
}
