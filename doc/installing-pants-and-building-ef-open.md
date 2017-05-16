## Installing pants and building ef-open tools
To build the ef-open tools, you will need to...
 - INSTALL: install pants "at the top directory of the workspace"
   - do this once on every system that will build with pants (your laptop, Jenkins, ...)
 - CUSTOMIZE: create and configure "ef_site_config.py" file and accompanying BUILD.siteconfig file in your infrastructure repo
   - do this just once per repo
 - BUILD: export an environment variable to tell pants where ef_site_config.py is, and build
   - do this every time you build the tools
   - ef-open also provides a simple helper script to check the setup and perform the pants build

### Preliminaries
From the pants documentation:
> To set up pants in your repo, we recommend installing our self-contained pants bash script
> in the root (ie, "buildroot") of your repo. In this example, ~/workspace is the
top of all repos. Pants is installed there.

For full details and the latest instructions, see
- [Installing Pants](http://www.pantsbuild.org/install.html) at pantsbuild.org
- [Python Projects with Pants](https://pantsbuild.github.io/python-readme.html) at pandsbuild.github.io<br>

#### Assumptions in all examples and instructions below
- Common directory above all repos is <code>~/workspace</code>
- The ef-open repo is called <code>ef-open</code> at <code>~/workspace/ef-open</code>
- The company or project's Cloudformation Infrastructure repo is already set up (possibly empty, but it's ready to use) at <code>~/workspace/&lt;REPO&gt;</code>.
Call it whatever you like. This documentation refers to it as <code>&lt;REPO&gt;</code>.
- Overall structure of stuff discussed here is:<br>
<code>  ~/workspace <--- Common top-level directory above all repos (pants will be installed here)</code><br>
<code>  ~/workspace/ef-open <--- ef-open repo, sync'd with ef-open at github</code><br>
<code>  ~/workspace/&lt;REPO&gt; <--- your infrastructure repo with localized /ef_site_config.py</code><br>
<code>  &lt;REPO&gt;/ef_site_config.py <--- your project/company-specific ef-open configuration file</code><br>
- To get you started, ef-open provides:<br>
  <code>ef-open/getting-started/ef_site_config.py <--- starter site config file to copy to &lt;REPO&gt;/ef_site_config.py</code><br>
  <code>ef-open/getting-started/BUILD.ef_site_config <--- ready-to-go build file to copy to &lt;REPO&gt;/BUILD.ef_site_config</code>

### INSTALL: install pants
*Do this on any system that will build the tools, such as tool maintainers' laptops, and Jenkins*

<code>cd</code> to the directory above all the repos, which in these examples is <code>~/workspace</code>, then
download and install pants:
```bash
$ cd ~/workspace
$ curl -L -O https://pantsbuild.github.io/setup/pants && chmod +x pants && touch pants.ini
```

Check that pants runs and get the installed version:
```
$ ./pants -V
1.1.0
```

Edit ~/workspace/pants.ini to pin the pants version by adding these lines, using the pants version from the previous step
```
[GLOBAL]
pants_version: 1.1.0
```

Pants is now installed.


### CUSTOMIZE: configure ef-open for your AWS environment<BR>
*Do this once for each infrastructure repo*

Copy the ef_site_config.py template from ef-open/getting-started
```bash
$ cp ~/workspace/ef-open/getting-started/ef_site_config.py ~/workspace/<REPO>/ef_site_config.py
```
Define custom values for your tooling
- edit <code>~/workspace/&lt;REPO&gt;/ef_site_config.py</code>
- localize all values for the company/project following the examples in comments there
- save the updated <code>~/workspace/&lt;REPO&gt;/ef_site_config.py</code>

Copy in the BUILD file so pants can use your <code>&lt;REPO&gt;/ef_site_config.py</code>
```bash
$ cp ~/workspace/ef-open/getting-started/BUILD.ef_site_config ~/workspace/<REPO>/BUILD.ef_site_config
```

Merge and commit <code>ef_site_config.py</code> and <code>BUILD.ef_site_config</code> to your repo.

You're customized and ready to build.


### BUILD: Build all the ef-open tools
```bash
$ cd ~/workspace
$ export EF_SITE_REPO=<REPO>
$ ./pants binary ef-open/src:
```

Tools will be built in ef-open/dist:<br>
```
  ef-cf.pex
  ef-check-config.pex
  ef-generate.pex
  ef-resolve-config.pex
  ef-version.pex
```

ef-open also provides the script "build-ef-open" to automate the above with some parameter checking<br>
After a successful build, the build-ef-open script also removes the '.pex' extension from all the built files.

Syntax:
```
cd <directory_above_repos>
ef-open/tools/build-ef-open <REPO>
```

Example:
```bash
$ MY_REPO=our_infra_repo  # infra repo must be at ~/workspace/$MY_REPO
$ cd ~/workspace
~/workspace:$ ef-open/tools/build-ef-open $MY_REPO

$ ef-open/tools/build-ef-open my-repo
fatal: Not a git repository (or any of the parent directories):

15:28:37 00:00 [main]
               (To run a reporting server: ./pants server)
15:28:37 00:00   [setup]
15:28:37 00:00     [parse]fatal: Not a git repository (or any of the parent directories): .git

               Executing tasks in goals: bootstrap -> imports -> unpack-jars -> deferred-sources -> gen -> jvm-platform-validate -> resolve -> compile -> resources -> binary
15:28:37 00:00   [bootstrap]
15:28:37 00:00     [substitute-aliased-targets]
15:28:37 00:00     [jar-dependency-management]
15:28:37 00:00     [bootstrap-jvm-tools]
15:28:37 00:00     [provide-tools-jar]
15:28:37 00:00   [imports]
15:28:37 00:00     [ivy-imports]
15:28:37 00:00   [unpack-jars]
15:28:37 00:00     [unpack-jars]
15:28:37 00:00   [deferred-sources]
15:28:37 00:00     [deferred-sources]
15:28:37 00:00   [gen]
15:28:37 00:00     [thrift]
15:28:37 00:00     [protoc]
15:28:37 00:00     [antlr]
15:28:37 00:00     [ragel]
15:28:37 00:00     [jaxb]
15:28:37 00:00     [wire]
15:28:37 00:00   [jvm-platform-validate]
15:28:37 00:00     [jvm-platform-validate]
15:28:37 00:00   [resolve]
15:28:37 00:00     [ivy]
15:28:37 00:00   [compile]
15:28:37 00:00     [compile-jvm-prep-command]
15:28:37 00:00       [jvm_prep_command]
15:28:37 00:00     [compile-prep-command]
15:28:37 00:00     [compile]
15:28:37 00:00     [zinc]
15:28:37 00:00     [jvm-dep-check]
15:28:37 00:00   [resources]
15:28:37 00:00     [prepare]
15:28:37 00:00     [services]
15:28:37 00:00   [binary]
15:28:37 00:00     [binary-jvm-prep-command]
15:28:37 00:00       [jvm_prep_command]
15:28:37 00:00     [binary-prep-command]
15:28:37 00:00     [python-binary-create]
                   created pex copy dist/ef-cf.pex
                   created pex copy dist/ef-check-config.pex
                   created pex copy dist/ef-generate.pex
                   created pex copy dist/ef-resolve-config.pex
                   created pex copy dist/ef-version.pex
15:28:37 00:00     [jvm]
15:28:37 00:00     [dup]
15:28:38 00:01   [complete]
               SUCCESS


~/workspace:$ ls dist/
ef-cf			ef-check-config		ef-generate		ef-resolve-config	ef-version
```
