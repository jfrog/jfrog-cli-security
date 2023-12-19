# Table of Contents

- [📖 Guidelines](#-guidelines)
- [🆕 Adding Command](#-adding-command)
- [⚒️ Building the Sources](#-building-and-testing-the-sources)
- [🧪 Testing the Sources](#-testing-the-sources)

---

<br>

# 📖 Guidelines

- This project heavily depends on [github.com/jfrog/jfrog-cli-core](github.com/jfrog/jfrog-cli-core) module, before adding new capability make sure to check if it exists there and can be used.
- Ensure that your changes are covered by existing tests. If not, please add new tests.
- Create pull requests on the `dev` branch.
- Before submitting the pull request, format the code by running `go fmt ./...`.
- Before submitting the pull request, ensure the code compiles by running `go vet ./...`.

<br>

# 🆕 Adding Command

Embedded Plugin `Command` can be defined as defined at:

[plugins/components/structure.go](github.com/jfrog/jfrog-cli-core/plugins/components/structure.go)

When defining the Action of the command the CLI will pass you a `Context` with all the related command information to be parsed and executed as defined at:

[plugins/components/commandcomp.go](github.com/jfrog/jfrog-cli-core/plugins/components/commandcomp.go)

### NOTE

> Before adding any new general logic to handle any attributes from `Context` make sure to first checkout: [plugins/commonutils.go](github.com/jfrog/jfrog-cli-core/plugins/commonutils.go)

> Before adding any new CLI related constants (Flags, Env vars...) please make sure they are not defined already at: [cliutils](github.com/jfrog/jfrog-cli-core/cliutils)


<br>

# ⚒️ Building the Sources



<br>

# 🧪 Testing the Sources

To run the tests, execute the following command from within the root directory of the project:

```sh
go test -v github.com/jfrog/jfrog-cli-security/tests -timeout 0 -race
```