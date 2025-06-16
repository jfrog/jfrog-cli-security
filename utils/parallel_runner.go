package utils

import (
	"github.com/jfrog/gofrog/parallel"
	"sync"
)

type SecurityParallelRunner struct {
	Runner        parallel.Runner
	ResultsMu     sync.Mutex
	ScaScansWg    sync.WaitGroup // Verify that the sca scan routines are done before running contextual scan
	JasScannersWg sync.WaitGroup // Verify that all scanners routines are done before cleaning temp dir
	JasWg         sync.WaitGroup // Verify that downloading analyzer manager and running all scanners are done

	onScanEndFunc func()
}

func NewSecurityParallelRunner(numOfParallelScans int) SecurityParallelRunner {
	return SecurityParallelRunner{Runner: parallel.NewRunner(numOfParallelScans, 20000, false)}
}

func CreateSecurityParallelRunner(numOfParallelScans int) *SecurityParallelRunner {
	securityParallelRunner := NewSecurityParallelRunner(numOfParallelScans)
	return &securityParallelRunner
}

func (spr *SecurityParallelRunner) OnScanEnd(funcToRunOnScanEnd func()) *SecurityParallelRunner {
	spr.onScanEndFunc = funcToRunOnScanEnd
	return spr
}

func (spr *SecurityParallelRunner) Start() {
	go func() {
		spr.ScaScansWg.Wait()
		spr.JasWg.Wait()
		spr.JasScannersWg.Wait()
		if spr.onScanEndFunc != nil {
			spr.onScanEndFunc()
		}
		spr.Runner.Done()
	}()
	spr.Runner.Run()
}
