/* eslint-disable */
// `yarn jfrog-yarn-resolve-lockfile`: resolves the full dependency graph from
// registry metadata and writes a complete yarn.lock WITHOUT fetching tarballs,
// so a curation 403 on a blocked tarball can't abort the lockfile build.
// Used only by `jf curation-audit` (mirrors npm's --package-lock-only).
module.exports = {
  name: `plugin-jfrog-yarn-resolve-lockfile`,
  factory: (require) => {
    const { BaseCommand } = require(`@yarnpkg/cli`);
    const { Cache, Configuration, Project, StreamReport } = require(`@yarnpkg/core`);

    class JfrogYarnResolveLockfileCommand extends BaseCommand {
      static paths = [[`jfrog-yarn-resolve-lockfile`]];

      async execute() {
        const configuration = await Configuration.find(
          this.context.cwd,
          this.context.plugins,
        );
        const { project } = await Project.find(configuration, this.context.cwd);
        const cache = await Cache.find(configuration);

        const report = await StreamReport.start(
          {
            configuration,
            stdout: this.context.stdout,
            includeFooter: false,
          },
          async (report) => {
            // Resolve only (no fetchEverything = no tarball downloads).
            // Don't pass lockfileOnly:true — it refuses to resolve packages
            // absent from the lockfile (YN0020).
            await project.resolveEverything({ cache, report });
            await project.persistLockfile();
          },
        );

        return report.exitCode();
      }
    }

    return {
      commands: [JfrogYarnResolveLockfileCommand],
    };
  },
};
