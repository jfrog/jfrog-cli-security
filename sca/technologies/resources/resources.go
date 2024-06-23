package resources

import _ "embed"

//go:embed settings.xml
var SettingsXmlTemplate string

//go:embed maven-dep-tree.jar
var MavenDepTreeJar []byte
