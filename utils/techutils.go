package utils

import "github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"

func TechnologyToLanguage(technology coreutils.Technology) CodeLanguage {
	languageMap := map[coreutils.Technology]CodeLanguage{
		coreutils.Npm:    JavaScript,
		coreutils.Pip:    Python,
		coreutils.Poetry: Python,
		coreutils.Pipenv: Python,
		coreutils.Go:     GoLang,
		coreutils.Maven:  Java,
		coreutils.Gradle: Java,
		coreutils.Nuget:  CSharp,
		coreutils.Dotnet: CSharp,
		coreutils.Yarn:   JavaScript,
		coreutils.Pnpm:   JavaScript,
	}
	return languageMap[technology]
}

type CodeLanguage string

const (
	JavaScript CodeLanguage = "javascript"
	Python     CodeLanguage = "python"
	GoLang     CodeLanguage = "go"
	Java       CodeLanguage = "java"
	CSharp     CodeLanguage = "C#"
)
