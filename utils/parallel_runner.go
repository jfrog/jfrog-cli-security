package utils

import (
	"github.com/jfrog/gofrog/parallel"
	"sync"
)

type SecurityParallelRunner struct {
	Runner      parallel.Runner
	ErrorsQueue chan error
	ResultsMu   sync.Mutex
	ScaScansWg  sync.WaitGroup // verify that the sca scan routines are done before running contextual scan
	ScannersWg  sync.WaitGroup // verify that all scanners routines are done before cleaning temp dir
	JasWg       sync.WaitGroup // verify that downloading analyzer manager and running all scanners are done
}

func NewSecurityParallelRunner(numOfParallelScans int) SecurityParallelRunner {
	return SecurityParallelRunner{
		Runner:      parallel.NewRunner(numOfParallelScans, 20000, false),
		ErrorsQueue: make(chan error, 100),
	}
}

func CreateSecurityParallelRunner(numOfParallelScans int) *SecurityParallelRunner {
	securityParallelRunner := NewSecurityParallelRunner(numOfParallelScans)
	return &securityParallelRunner
}

func (spr *SecurityParallelRunner) AddErrorToChan(err error) {
	spr.ErrorsQueue <- err
}
