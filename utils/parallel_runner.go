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
}

func NewSecurityParallelRunner(numOfParallelScans int) SecurityParallelRunner {
	return SecurityParallelRunner{Runner: parallel.NewRunner(numOfParallelScans, 20000, false)}
}

func CreateSecurityParallelRunner(numOfParallelScans int) *SecurityParallelRunner {
	securityParallelRunner := NewSecurityParallelRunner(numOfParallelScans)
	return &securityParallelRunner
}
