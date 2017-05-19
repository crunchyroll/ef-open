## Installing pants and building ef-open tools
To build the ef-open tools, you will need to...

| What | Where | When |
| --- | --- | --- |
| INSTALL:<br>install pants | on every system that will use pants to build (your laptop, Jenkins, ...) | once per system |
| CUSTOMIZE:<br>configure "ef_site_config.py" and copy in the provided BUILD.siteconfig | your infrastructure repo(s) | once per repo initially (and any time you need to change a config value in ef_site_config.py) |
| BUILD:<br>export an environment variable to tell pants where ef_site_config.py is, then run pants<br>_or_<br>use the example script, <code>tools/build-ef-open</code> that checks setup and runs pants | any pants-capable system | every time you build ef-open (whenever there's an update to /src or your revise your ef_site_config.py) |

### Preliminaries
As the time this was written, the pants installation instructions at [http://www.pantsbuild.org/install.html](http://www.pantsbuild.org/install.html)
were not in sync with the newer instructions in the pants repo at [https://github.com/pantsbuild/pants/blob/master/README.md](https://github.com/pantsbuild/pants/blob/master/README.md) and will install an old version of pants.

Accordingly, these instructions use pip to install pants from PyPI to <code>/usr/local/bin</code> per the PyPI reference in [pantsbuild/README.md](https://github.com/pantsbuild/pants/blob/master/README.md).

In the instructions and examples below, <code>~/workspace</code> is the common directory above all repos.<br>
Pants has a .ini file there, and will make some visible and invisible (dot-file) directories inside it.

For full details and the latest instructions, see
- [Installing Packages](http://www.pantsbuild.org/install.html) at python.org (for pip, if you don't have it)
- [pantsbuild/README.md](https://github.com/pantsbuild/pants/blob/master/README.md)
- [Python Projects with Pants](https://pantsbuild.github.io/python-readme.html) at pandsbuild.github.io

#### Assumptions in all examples and instructions below
- The common directory above all repos is <code>~/workspace</code>
- The ef-open repo is called <code>ef-open</code> at <code>~/workspace/ef-open</code>
- Your company or project's Cloudformation infrastructure repo is already set up (possibly empty, but ready to use) at <code>~/workspace/&lt;REPO&gt;</code>.<br>
Call it whatever you like. This documentation refers to it as <code>&lt;REPO&gt;</code>.
- Overall structure of stuff discussed here is:<br>
<code>  ~/workspace</code> <--- Common top-level directory above all repos (Installed pants here and cd to here to build)<br>
<code>  ~/workspace/ef-open</code> <--- ef-open repo, sync'd with ef-open at github<br>
<code>  ~/workspace/&lt;REPO&gt;</code> <--- your infrastructure repo containing the localized <code>/ef_site_config.py</code><br>
<code>  &lt;REPO&gt;/ef_site_config.py</code> <--- your project/company-specific ef-open configuration file<br>
- To get you started, ef-open provides:<br>
  <code>ef-open/getting-started/ef_site_config.py</code> <--- starter site config file to copy to <code>&lt;REPO&gt;/ef_site_config.py</code> and then customize<br>
  <code>ef-open/getting-started/BUILD.ef_site_config</code> <--- ready-to-go build file to copy to <code>&lt;REPO&gt;/BUILD.ef_site_config</code>

### INSTALL: install pants
*Do this on any system that will build the tools, such as tool maintainers' laptops, and Jenkins*

<code>cd</code> to the directory above all the repos, which in these examples is <code>~/workspace</code>, then
use pip to install pants... or use chef or other configuration tool to install it on a build server.

The maintainers of ef-open currently build ef-open with version 1.2.1 of pants. The BUILD files for ef-open are not complex,
and will probably work with other versions of pants.
```bash
# to install version 1.2.1 specifically, using pip:
$ cd ~/workspace
$ sudo pip install pantsbuild.pants==1.2.1
$ touch pants  # pants requires a file with this name in the cwd, even if the binary is really somewhere else

# or to install the latest version, using pip:
$ cd ~/workspace
$ sudo pip install pantsbuild.pants
$ touch pants  # pants requires a file with this name in the cwd, even if the binary is really somewhere else
```

Check that pants runs, and get its version number
```
$ which pants
/usr/local/bin/pants
```

It's on the search path so you shouldn't need to call it out explicitly if this is the only copy you have
```
$ pants -V
1.2.1
```
If pants won't run on your OS/X installation, take a look at the discussion here:
[https://apple.stackexchange.com/questions/209572/how-to-use-pip-after-the-os-x-el-capitan-upgrade](https://apple.stackexchange.com/questions/209572/how-to-use-pip-after-the-os-x-el-capitan-upgrade)

For us, this step from the conversation above solved a versioning issue (old version found first) caused by a python path problem in OS/X:<br>
<code>$ sudo cat > /Library/Python/2.7/site-packages/fix_mac_path.pth</code><br>
<code>import sys; std_paths=[p for p in sys.path if p.startswith('/System/') and not '/Extras/' in p]; sys.path=[p for p in sys.path if not p.startswith('/System/')]+std_paths</code><br>
<code>^D</code><br>

Edit ~/workspace/pants.ini to pin the pants version by adding these lines, using the pants version found in the previous step
```
[GLOBAL]
pants_version: 1.2.1
```

Pants is now installed. If you installed with pip, it's on probably your path, so in the examples below we'll
call it without a path.<br>
On a build server, you may need or prefer to always specify the full path to the pants binary.

### CUSTOMIZE: configure ef-open for your AWS environment<BR>
*Do this once for each infrastructure repo*

Copy the ef_site_config.py template from ef-open/getting-started
```bash
$ cp ~/workspace/ef-open/getting-started/ef_site_config.py ~/workspace/<REPO>/ef_site_config.py
```
Define custom values for your tooling
- edit <code>~/workspace/&lt;REPO&gt;/ef_site_config.py</code>
- localize all values for the company/project following the examples in comments in the file
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
