## Installing pants and building ef-open tools
To build the ef-open tools, you will need to...
 - INSTALL: install pants "at the top directory of the workspace"
   - do this once on every system that will build with pants (your laptop, Jenkins, ...)
 - CUSTOMIZE: configure "ef_site_config.py" in your infrastructure repo, and copy in the provided BUILD.siteconfig
   - do this just once per repo
 - BUILD: export an environment variable to tell pants where ef_site_config.py is, and run pants
   - do this every time you build the tools
   - ef-open also provides a simple example helper script to check the setup and build with pants

### Preliminaries
These instructions use pip to install pants from Pypi to /usr/local/bin

In the instructions and examples below, <code>~/workspace</code> is the common directory
above all repos. Pants has a .ini file there, and will make some visible and invisible (dot-file)
directories inside this directory.

For full details and the latest instructions, see
- [Installing Pants](http://www.pantsbuild.org/install.html) at pantsbuild.org
- [Python Projects with Pants](https://pantsbuild.github.io/python-readme.html) at pandsbuild.github.io<br>
- tl;dr-style instructions appear below

#### Assumptions in all examples and instructions below
- The common directory above all repos is <code>~/workspace</code>
- The ef-open repo is called <code>ef-open</code> at <code>~/workspace/ef-open</code>
- The company or project's Cloudformation infrastructure repo is already set up (possibly empty, but ready to use) at <code>~/workspace/&lt;REPO&gt;</code>.<br>
Call it whatever you like. This documentation refers to it as <code>&lt;REPO&gt;</code>.
- Overall structure of stuff discussed here is:<br>
<code>  ~/workspace</code> <--- Common top-level directory above all repos (Installed pants here and cd to here to build)<br>
<code>  ~/workspace/ef-open</code> <--- ef-open repo, sync'd with ef-open at github<br>
<code>  ~/workspace/&lt;REPO&gt;</code> <--- your infrastructure repo with localized /ef_site_config.py<br>
<code>  &lt;REPO&gt;/ef_site_config.py</code> <--- your project/company-specific ef-open configuration file<br>
- To get you started, ef-open provides:<br>
  <code>ef-open/getting-started/ef_site_config.py</code> <--- starter site config file to copy to &lt;REPO&gt;/ef_site_config.py<br>
  <code>ef-open/getting-started/BUILD.ef_site_config</code> <--- ready-to-go build file to copy to &lt;REPO&gt;/BUILD.ef_site_config

### INSTALL: install pants
*Do this on any system that will build the tools, such as tool maintainers' laptops, and Jenkins*

<code>cd</code> to the directory above all the repos, which in these examples is <code>~/workspace</code>, then
Use pip to install pants locally, or chef or other configuration tool to install it on a build server.
The maintainers of ef-open presently use version 1.2.1 of pants. The BUILD files for ef-open are not complex,
and will probably work ok with other versions of pants.
```bash
# to install version 1.2.1 specifically:
$ cd ~/workspace
$ sudo pip install pantsbuild.pants==1.2.1
$ touch pants  # pants demands a file with this name in the cwd, even if the binary is really somewhere else

# or to install the latest version:
$ cd ~/workspace
$ sudo pip install pantsbuild.pants
$ touch pants  # pants demands a file with this name in the cwd, even if the binary is really somewhere else
```

Check that pants runs, and get the version number of what was just installed
```
$ which pants
/usr/local/bin/pants

pants -V
1.2.1
```

Edit ~/workspace/pants.ini to pin the pants version by adding these lines, using the pants version from the previous step
```
[GLOBAL]
pants_version: 1.2.1
```

Pants is now installed. It should be on your path, so in the examples below we'll
call it without literally including the path. On a server, you may need or prefer
to specify the full path to the binary when running pants.

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
