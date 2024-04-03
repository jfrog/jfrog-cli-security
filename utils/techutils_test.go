package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTechnologyToLanguage(t *testing.T) {
	tests := []struct {
		name       string
		technology coreutils.Technology
		language   CodeLanguage
	}{
		{name: "Maven to Java", technology: coreutils.Maven, language: Java},
		{name: "Gradle to Java", technology: coreutils.Gradle, language: Java},
		{name: "Npm to JavaScript", technology: coreutils.Npm, language: JavaScript},
		{name: "Pnpm to JavaScript", technology: coreutils.Pnpm, language: JavaScript},
		{name: "Yarn to JavaScript", technology: coreutils.Yarn, language: JavaScript},
		{name: "Go to GoLang", technology: coreutils.Go, language: GoLang},
		{name: "Pip to Python", technology: coreutils.Pip, language: Python},
		{name: "Pipenv to Python", technology: coreutils.Pipenv, language: Python},
		{name: "Poetry to Python", technology: coreutils.Poetry, language: Python},
		{name: "Nuget to CSharp", technology: coreutils.Nuget, language: CSharp},
		{name: "Dotnet to CSharp", technology: coreutils.Dotnet, language: CSharp},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.language, TechnologyToLanguage(tt.technology), "TechnologyToLanguage(%v) == %v", tt.technology, tt.language)
		})
	}
}
