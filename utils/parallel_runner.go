package utils

import (
	"github.com/jfrog/gofrog/parallel"
	"sync"
)

type AuditParallelRunner struct {
	Runner      parallel.Runner
	ErrorsQueue chan error
	Mu          sync.Mutex
	ScaScansWg  sync.WaitGroup // verify that the sca scan routines are done before running contextual scan
	ScannersWg  sync.WaitGroup // verify that all scanners routines are done before cleaning temp dir
	JasWg       sync.WaitGroup // verify that downloading analyzer manager and running all scanners are done
}

func NewAuditParallelRunner(numOfParallelScans int) AuditParallelRunner {
	return AuditParallelRunner{
		Runner:      parallel.NewRunner(numOfParallelScans, 20000, false),
		ErrorsQueue: make(chan error, 100),
	}
}

func CreateAuditParallelRunner(numOfParallelScans int) *AuditParallelRunner {
	auditParallelRunner := NewAuditParallelRunner(numOfParallelScans)
	return &auditParallelRunner
}

func (apr *AuditParallelRunner) AddErrorToChan(err error) {
	apr.ErrorsQueue <- err
}
