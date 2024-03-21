package utils

import (
	"github.com/jfrog/gofrog/parallel"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"sync"
)

type AuditParallelRunner struct {
	Runner      parallel.Runner
	ErrorsQueue clientutils.ErrorsQueue
	Mu          sync.Mutex
	ScaScansWg  sync.WaitGroup // verify that the sca scan routines are done before running contextual scan
	ScannersWg  sync.WaitGroup // verify that all scanners routines are done before cleaning temp dir
	JasWg       sync.WaitGroup // verify that downloading analyzer manager and running all scanners are done
}

func NewAuditParallelRunner() AuditParallelRunner {
	return AuditParallelRunner{
		Runner: parallel.NewRunner(3, 20000, false),
	}
}

func CreateAuditParallelRunner() *AuditParallelRunner {
	auditParallelRunner := NewAuditParallelRunner()
	return &auditParallelRunner
}
