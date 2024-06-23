package utils

import (
	"github.com/jfrog/gofrog/parallel"
	"sync"
)

const (
	maxTasks = 20000
)

type SecurityScansParallelRunner struct {
	// 
	TaskProducer parallel.Runner
	TaskConsumer parallel.Runner
}

func NewSecurityScansParallelRunner(numOfParallelScans int) SecurityScansParallelRunner {
	return SecurityScansParallelRunner{
		TaskProducer: parallel.NewRunner(numOfParallelScans, maxTasks, false),
		TaskConsumer: parallel.NewRunner(numOfParallelScans, maxTasks, false),
	}
}

func (spr *SecurityScansParallelRunner) Run() {
	go func() {
		spr.TaskProducer.Run()
		spr.TaskConsumer.Done()
	}()
	spr.TaskConsumer.Run()
}


type SecurityParallelRunner struct {
	Runner        parallel.Runner
	ErrorsQueue   chan error
	ResultsMu     sync.Mutex
	ScaScansWg    sync.WaitGroup // Verify that the sca scan routines are done before running contextual scan
	JasScannersWg sync.WaitGroup // Verify that all scanners routines are done before cleaning temp dir
	JasWg         sync.WaitGroup // Verify that downloading analyzer manager and running all scanners are done
	ErrWg         sync.WaitGroup // Verify that all errors are handled before finishing the audit func
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
