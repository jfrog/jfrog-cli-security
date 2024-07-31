package utils

import (
	"github.com/jfrog/gofrog/parallel"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

type SecurityCommandTaskProducer func(addTask func(task parallel.TaskFunc))

type SecurityCommandParallelRunner struct {
	taskProducerRunner parallel.Runner
	// TODO: more than one consumer?
	taskConsumerRunner parallel.Runner

	taskProducerFuncs []SecurityCommandTaskProducer
}

func NewSecurityCommandParallelRunner(numOfParallelTasks int) *SecurityCommandParallelRunner {
	return &SecurityCommandParallelRunner{
		taskProducerRunner: parallel.NewRunner(numOfParallelTasks, 20000, false),
		taskConsumerRunner: parallel.NewRunner(numOfParallelTasks, 20000, false),
	}
}

func (spr *SecurityCommandParallelRunner) AddTaskProducers(taskProducerFuncs ...SecurityCommandTaskProducer) {
	spr.taskProducerFuncs = append(spr.taskProducerFuncs, taskProducerFuncs...)
}

// Blocking call
func (spr *SecurityCommandParallelRunner) Run() (cmdResults *results.SecurityCommandResults) {
	spr.produceTasks()
	spr.consumeTasks()
	return
}

func (spr *SecurityCommandParallelRunner) produceTasks() {
	go func() {
		defer spr.taskProducerRunner.Done()
		// Produce tasks
		for _, taskProducerFunc := range spr.taskProducerFuncs {
			taskProducerFunc(getFuncAddTaskToProducerRunner(spr.taskProducerRunner))
		}
	}()
}

func getFuncAddTaskToProducerRunner(taskProducer parallel.Runner) (addTask func(task parallel.TaskFunc)) {
	return func(task parallel.TaskFunc) {
		_, _ = taskProducer.AddTask(task)
	}
}

func (spr *SecurityCommandParallelRunner) consumeTasks() {
	go func() {
		// Blocking until consuming is finished.
		spr.taskProducerRunner.Run()
		// After all task have been produced, notifies the consumer that no more tasks will be produced.
		spr.taskConsumerRunner.Done()
	}()
	// Blocking until consuming is finished.
	spr.taskConsumerRunner.Run()
}