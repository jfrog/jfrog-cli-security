package resources

import (
	_ "embed"
)

const BaseResourcesUrl = "https://raw.githubusercontent.com/jfrog/jfrog-cli-security/main/resources"

//go:embed java/settings.xml
var SettingsXmlTemplate string

//go:embed java/maven-dep-tree.jar
var MavenDepTreeJar []byte