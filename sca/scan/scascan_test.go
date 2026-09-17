package scan

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

type barrierScanStrategy struct {
	ready *sync.WaitGroup
	start chan struct{}
}

func (s *barrierScanStrategy) WithOptions(...SbomScanOption) SbomScanStrategy { return s }
func (s *barrierScanStrategy) PrepareStrategy() error                         { return nil }

func (s *barrierScanStrategy) SbomEnrichTask(target *cyclonedx.BOM) (*cyclonedx.BOM, error) {
	_, err := s.DeprecatedScanTask(target)
	return target, err
}

func (s *barrierScanStrategy) DeprecatedScanTask(*cyclonedx.BOM) (services.ScanResponse, error) {
	s.ready.Done()
	select {
	case <-s.start:
		return services.ScanResponse{ScanId: "parallel-sca"}, nil
	case <-time.After(2 * time.Second):
		return services.ScanResponse{}, errScaTasksDidNotOverlap
	}
}

var errScaTasksDidNotOverlap = errors.New("SCA tasks did not overlap; ResultsMu likely serializes the scan")

func TestRunScaScanWithRunnerRunsTargetsInParallel(t *testing.T) {
	for _, tc := range []struct {
		name      string
		isNewFlow bool
	}{
		{name: "deprecated scan graph", isNewFlow: false},
		{name: "sbom enrich", isNewFlow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const targetCount = 2
			var ready sync.WaitGroup
			ready.Add(targetCount)
			start := make(chan struct{})
			strategy := &barrierScanStrategy{ready: &ready, start: start}

			cmdResults := results.NewCommandResults(utils.SourceCode)
			runner := utils.CreateSecurityParallelRunner(targetCount)
			for i := 0; i < targetCount; i++ {
				target := cmdResults.NewScanResults(results.ScanTarget{Target: t.Name() + string(rune('a'+i))})
				target.SetSbom(librarySbom())
				require.NoError(t, RunScaScan(strategy, ScaScanParams{
					ScanResults: target,
					TargetCount: targetCount,
					Runner:      runner,
					IsNewFlow:   tc.isNewFlow,
				}))
			}

			go func() {
				ready.Wait()
				close(start)
			}()
			runner.Start()

			for _, target := range cmdResults.Targets {
				require.Empty(t, target.GetNotSkippedErrors())
				require.NotNil(t, target.ScaResults)
				if tc.isNewFlow {
					require.NotNil(t, target.ScaResults.Sbom)
					continue
				}
				require.Len(t, target.ScaResults.DeprecatedXrayResults, 1)
				assert.Equal(t, "parallel-sca", target.ScaResults.DeprecatedXrayResults[0].ScanId)
			}
		})
	}
}

func librarySbom() *cyclonedx.BOM {
	sbom := cyclonedx.NewBOM()
	components := []cyclonedx.Component{{
		BOMRef: "pkg:npm/example@1.0.0",
		Name:   "example",
		Type:   cyclonedx.ComponentTypeLibrary,
	}}
	sbom.Components = &components
	return sbom
}
