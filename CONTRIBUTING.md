# Contribution Guide

Welcome to the contribution guide for our project! We appreciate your interest in contributing to the development of this project. Below, you will find essential information on local development, running tests, and guidelines for submitting pull requests.

## Table of Contents

- [🏠🏗️ Local development](#%EF%B8%8F-local-development)
- [🚦 Running Tests](#-running-tests)
- [📖 Submitting PR Guidelines](#-submitting-pr-guidelines)


## 🏠🏗️ Local Development

To run a command locally, use the following command template:

```sh
go run github.com/jfrog/jfrog-cli-security command [options] [arguments...]
```

---

This project heavily depends on the following modules:

- [github.com/jfrog/jfrog-client-go](https://github.com/jfrog/jfrog-client-go)
- [github.com/jfrog/jfrog-cli-core](github.com/jfrog/jfrog-cli-core)

During local development, if you come across code that needs to be modified in one of the mentioned modules, it is advisable to replace the dependency with a local clone of the module.

<details>
<summary>Replacing a dependency with a local clone</summary>

---

To include this local dependency, For instance, let's assume you wish to modify files from `jfrog-cli-core`, modify the `go.mod` file as follows:

```
replace github.com/jfrog/jfrog-cli-core/v2 => /local/path/in/your/machine/jfrog-cli-core
```

Afterward, execute `go mod tidy` to ensure the Go module files are updated. Note that Go will automatically adjust the version in the `go.mod` file.

---

</details>


## 🚦 Running Tests

When running tests, builds and repositories with timestamps like `cli-rt1-1592990748` and `cli-rt2-1592990748` will be created. The content of these repositories will be deleted once the tests are completed.

To run tests, use the following command:

```
go test -v github.com/jfrog/jfrog-cli-security [test-types] [flags]
```

### The available flags are:

| Flag                | Description                                                                                     |
| ------------------- | ----------------------------------------------------------------------------------------------- |
| `-jfrog.url`        | [Default: http://localhost:8081] JFrog platform URL                                             |
| `-jfrog.user`       | [Default: admin] JFrog platform username                                                        |
| `-jfrog.password`   | [Default: password] JFrog platform password                                                     |
| `-jfrog.adminToken` | [Optional] JFrog platform admin token                                                           |
| `-ci.runId`         | [Optional] A unique identifier used as a suffix to create repositories and builds in the tests. |
| `-jfrog.sshKeyPath`    | [Optional] Path to the SSH key file. Use this flag only if the Artifactory URL format is `ssh://[domain]:port`. |
| `-jfrog.sshPassphrase` | [Optional] Passphrase for the SSH key.                                                                          |

---


### The available test types are:

| Type                 | Description        |
| -------------------- | ------------------ |
| `-test.security`     | [Default: true] Security commands integration tests  |
| `-test.dockerScan`   | [Optional] Docker scan integration tests  |

### Docker Scan tests

<details>

#### Requirements

- Make sure the `RTLIC` environment variable is configured with a valid license.
- Before running the tests, wait for Artifactory to finish booting up in the container.

| Flag                      | Description                         |
| ------------------------- | ----------------------------------- |
| `-test.containerRegistry` | Artifactory Docker registry domain. |


</details>

## 📖 Submitting PR Guidelines

Once you have completed your coding changes, it is recommended to push the modifications made to the other modules first. Once these changes are pushed, you can update this project to resolve dependencies from your GitHub fork or branch.

<details>

<summary>Resolve dependencies from GitHub fork or branch</summary>

---

To achieve this, modify the `go.mod` file to point the dependency to your repository and branch, as shown in the example below:

```
replace github.com/jfrog/jfrog-cli-core/v2 => github.com/jfrog/jfrog-cli-core/v2 dev
```

Finally, execute `go mod tidy` to update the Go module files. Please note that Go will automatically update the version in the `go.mod` file.

---

</details>

### Before submitting the pull request, ensure:

- Your changes are covered by `unit` and `integration` tests. If not, please add new tests.
- The code compiles, by running `go vet ./...`.
- To format the code, by running `go fmt ./...`.
- The documentation covers the changes, if not please add and make changes at [The documentation repository](https://github.com/jfrog/documentation)

### When creating the pull request, ensure:

- The pull request is on the `dev` branch.
- The pull request description describes the changes made.