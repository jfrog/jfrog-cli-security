package resources

import (
	_ "embed"
)

//go:embed java/settings.xml
var SettingsXmlTemplate string

//go:embed java/maven-dep-tree.jar
var MavenDepTreeJar []byte