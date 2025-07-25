#!/bin/sh

# Please use this script to download the JAR files for maven-dep-tree and gradle-dep-tree into the directory utils/java/. 
# These JARs allow us to build Maven and Gradle dependency trees efficiently and without compilation.
# Learn more about them here:
# https://github.com/jfrog/gradle-dep-tree
# https://github.com/jfrog/maven-dep-tree

# Once you have updated the versions mentioned below, please execute this script from the root directory of the jfrog-cli-core to ensure the JAR files are updated.
GRADLE_DEP_TREE_VERSION="3.0.2"
# Changing this version also requires a change in mavenDepTreeVersion within utils/java/mvn.go.
MAVEN_DEP_TREE_VERSION="1.1.1"

curl -fL https://releases.jfrog.io/artifactory/oss-release-local/com/jfrog/gradle-dep-tree/${GRADLE_DEP_TREE_VERSION}/gradle-dep-tree-${GRADLE_DEP_TREE_VERSION}.jar -o sca/bom/buildinfo/technologies/java/resources/gradle-dep-tree.jar
curl -fL https://releases.jfrog.io/artifactory/oss-release-local/com/jfrog/maven-dep-tree/${MAVEN_DEP_TREE_VERSION}/maven-dep-tree-${MAVEN_DEP_TREE_VERSION}.jar -o sca/bom/buildinfo/technologies/java/resources/maven-dep-tree.jar
