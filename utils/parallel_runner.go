package utils

import (
	"github.com/jfrog/gofrog/parallel"
	"github.com/jfrog/jfrog-client-go/utils/log"
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

// WrapTaskWithLoggerPropagation wraps a parallel task to propagate the current goroutine's logger
// to worker goroutines. This is needed when using BufferedLogger for isolated parallel logging -
// worker goroutines need to inherit the parent's logger so their logs are captured in the same buffer.
func WrapTaskWithLoggerPropagation(task parallel.TaskFunc) parallel.TaskFunc {
	currentLogger := log.GetLogger()
	return func(threadId int) error {
		log.SetLoggerForGoroutine(currentLogger)
		defer log.ClearLoggerForGoroutine()
		return task(threadId)
	}
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
