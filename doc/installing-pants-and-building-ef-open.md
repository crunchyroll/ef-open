## Installing pants and building ef-open tools
To build the ef-open tools, you will need to...

| What | Where | When |
| --- | --- | --- |
| INSTALL:<br>install pants | on every system that will use pants to build (your laptop, Jenkins, ...) | once per system |
| CUSTOMIZE:<br>configure "ef_site_config.py"<br>copy in the provided BUILD.siteconfig | your infrastructure repo(s) | once per repo initially (and later to change a value in ef_site_config.py) |
| BUILD:<br>export an environment variable to tell pants where ef_site_config.py is, then run pants<br>_or_<br>use the example script, <code>tools/build-ef-open</code> that checks setup and runs pants | any pants-capable system | every time you build ef-open<br>(whenever there's an update to /src or your revise your ef_site_config.py) |

### Preliminaries

Below are tl;dr instructions that have worked for the ef-open maintainers.<br>
For full details and the latest instructions, see:
- [Installing Pants](http://www.pantsbuild.org/install.html) at pantsbuild.org
- [pantsbuild/README.md](https://github.com/pantsbuild/pants/blob/master/README.md) at github.com/pantsbuild
- [Python Projects with Pants](https://pantsbuild.github.io/python-readme.html) at pantsbuild.github.io

#### Assumptions in the examples and instructions below
- The common directory above all repos is <code>~/workspace</code>
  - Pants has a <code>pants.ini</code> file there, and will make some visible and invisible (dot-file) directories inside it.
- The ef-open repo is called <code>ef-open</code> at <code>~/workspace/ef-open</code>
- Your company or project's Cloudformation infrastructure repo is already set up (possibly empty, but ready to use) at <code>~/workspace/&lt;REPO&gt;</code>.<br>
Call it whatever you like. This documentation refers to it as <code>&lt;REPO&gt;</code>.
- Overall structure of stuff discussed here is:<br>
<code>  ~/workspace</code> <--- Common top-level directory above all repos (Install pants here; cd to here to build)<br>
<code>  ~/workspace/ef-open</code> <--- ef-open repo, sync'd with ef-open at github<br>
<code>  ~/workspace/&lt;REPO&gt;</code> <--- your infrastructure repo where CloudFormation templatesa and other ef-open files go<br>
<code>  ~/workspace/&lt;REPO&gt;/ef_site_config.py</code> <--- your project/company-specific ef-open configuration file<br>
- To get you started, ef-open provides:<br>
  <code>ef-open/getting-started/ef_site_config.py</code> <--- starter site config file to copy to <code>&lt;REPO&gt;/ef_site_config.py</code> and then customize<br>
  <code>ef-open/getting-started/BUILD.ef_site_config</code> <--- ready-to-go build file to copy to <code>&lt;REPO&gt;/BUILD.ef_site_config</code>

### INSTALL: install pants
*Do this on any system that will build the ef-open tools, such as tool maintainers' laptops, and Jenkins*

<code>cd</code> to the directory above all the repos, which in these examples is <code>~/workspace</code>, then
install pants there following the instructions below... or use chef or other configuration tool to install it on
a build server.

The maintainers of ef-open currently build ef-open with version 1.2.1 of pants. The BUILD files for ef-open are not complex,
and will probably work with other versions of pants. You can also install pants elsewhere (such as to /usr/local/bin). In
this document, it's installed into <code>~/workspace</code>.

```bash
$ cd ~/workspace
$ curl -L -O https://pantsbuild.github.io/setup/pants && chmod +x pants && touch pants.ini
```

Run pants the first time, and it will self-update to the latest version.<br>
If this returns a message like "No goals specified." then your copy of pants is current.
```bash
$ ./pants
```

Get the pants version number
```
$ ./pants -V
1.2.1
```

Edit <code>~/workspace/pants.ini</code> to add these lines to pin the pants version, using the version number from the previous step.<br>
Note: When pants_version is changed in pants.ini, pants will self-update if necessary to the desired version and stay there.
```
[GLOBAL]
pants_version: 1.2.1
```

Pants is now installed.

### CUSTOMIZE: configure ef-open for your AWS environment<BR>
*Do this once for each infrastructure repo*

Copy the ef_site_config.py template from ef-open/getting-started
```bash
$ cp ~/workspace/ef-open/getting-started/ef_site_config.py ~/workspace/<REPO>/ef_site_config.py
```
Define custom values for your AWS account and configuration
- edit <code>~/workspace/&lt;REPO&gt;/ef_site_config.py</code>
- localize all values for the company/project following the examples in comments in the file
- save the updated <code>~/workspace/&lt;REPO&gt;/ef_site_config.py</code>

Copy in the BUILD file so pants can use your <code>&lt;REPO&gt;/ef_site_config.py</code>
```bash
$ cp ~/workspace/ef-open/getting-started/BUILD.ef_site_config ~/workspace/<REPO>/BUILD.ef_site_config
```

Merge and commit <code>ef_site_config.py</code> and <code>BUILD.ef_site_config</code> to your infrastructure repo.

You're customized and ready to build.


### BUILD: Build all the ef-open tools
#### Run pants directly...
```
$ cd ~/workspace
$ export EF_SITE_REPO=<REPO>
$ pants binary ef-open/src:
```

Tools will be built in ef-open/dist:<br>
```
  ef-cf.pex
  ef-check-config.pex
  ef-generate.pex
  ef-resolve-config.pex
  ef-version.pex
```

#### ... or use the helper script, "build-ef-open"
ef-open also provides the script "build-ef-open" to automate the above with some parameter checking<br>
After a successful build, the build-ef-open script also removes the '.pex' extension from all the built files.

Syntax:
```
cd <directory_above_repos>
ef-open/tools/build-ef-open <REPO>
```

Example:
```bash
$ cd ~/workspace
$ ef-open/tools/build-ef-open our_infra_repo
```
(ignore the fatal message below)
```
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
