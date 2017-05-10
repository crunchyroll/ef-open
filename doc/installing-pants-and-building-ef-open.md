## Installing pants and building ef-open tools
To build the ef-open tools, you will need to:
 - install pants on the path above the repos, typically "at the top directory of the workspace"
 - create and configure "ef_site_config.py" file and accompanying BUILD.siteconfig file in a repo you control
 - export an environment variable to tell pants where ef_site_config.py is

### Preliminaries
From the pants documentation:
> To set up pants in your repo, we recommend installing our self-contained pants bash script
> in the root (ie, "buildroot") of your repo. In this example, ~/workspace is the
top of all repos. Pants is installed there.

For full details and the latest instructions, see [Installing Pants](http://www.pantsbuild.org/install.html) at pantsbuild.org

#### Assumptions in all examples below
- Common directory above all repos is "~/workspace"
- The ef-open repo is called "ef-open"
- The company or project's Cloudformation repo (holding templates and other things) is named "my-repo"
- The company or project's Cloudformation repo is already set up (maybe empty, but it's ready to go)
- Overall structure of stuff discussed here is:<br>
<code>  ~/workspace <--- Common top-level directory above all repos (pants will be installed here)</code><br>
<code>  ~/workspace/ef-open <--- ef-open repo, sync'd with ef-open at github</code><br>
<code>  ~/workspace/my-repo <--- Cloudformation template repo with localized /ef_site_config.py</code><br>
<code>  my-repo/ef_site_config.py <--- project-specific configuration file</code><br>
- To get you started, this project provides:<br>
<code>  ef-open/examples/ef_site_config.py <--- example site config file to copy to my-repo/ef_site_config.py</code>
<code>  ef-open/examples/BUILD.ef_site_config <--- build file to copy to my-repo/BUILD.ef_site_config</code>

### 0. Prerequisites
The examples below refer to this env var for easier copy-paste of the scripts below.<br>
Set MYREPO to your infrastructure repo, where the Cloudformation templates, site config, other local files will be.<br>
```bash
export MY_REPO=my-repo
```
Change to the directory above all your repos.
Under this directory should be: ef-open/ and $MY_REPO/
```bash
$ cd ~/workspace
```

### 1. Install pants

```bash
$ curl -L -O https://pantsbuild.github.io/setup/pants && chmod +x pants && touch pants.ini
```

Check that pants runs and get the current version
```
$ ./pants -V
1.1.0
```

Edit ~/workspace/pants.ini to pin pants by adding these lines, using the pants version found in the previous step
```
[GLOBAL]
pants_version: 1.1.0
```

### 2. Copy and localize ef_site_config.py; copy in the pants BUILD file

Copy the ef_site_config.py template from ef-open/examples
```bash
$ cp ~/workspace/ef-open/examples/ef_site_config.py ~/workspace/$MY_REPO/ef_site_config.py
```
Define custom values for your tools to use
- edit <code>~/workspace/$MY_REPO/ef_site_config.py</code>
- localize all values for the company/project
- save the updated <code>~/workspace/$MY_REPO/ef_site_config.py</code>

Copy in the BUILD file so pants can see your <code>$MY_REPO/ef_site_config.py</code>
```bash
$ cp ~/workspace/ef-open/examples/BUILD.ef_site_config ~/workspace/$MY_REPO/BUILD.ef_site_config
```

Merge and commit <code>ef_site_config.py</code> and <code>BUILD.ef_site_config</code> to your repo.

You're customized and ready to build.


### 3. Build all the tools defined in ef-open/src/BUILD
```bash
$ cd ~/workspace
$ export EF_SITE_REPO=$MY_REPO
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

There's an example script to automate the 3-step build.<br>
Copy it to wherever you want, maybe to a /tools dir in your infra repo:
```bash
$ mkdir ~/$MY_REPO/tools
$ cp ~/workspace/ef-open/examples/misc/build-ef-open ~/workspace/$MY_REPO/tools/build-ef-open
```
- edit <code>~~/workspace/$MY_REPO/tools/build-ef-open</code> to set the REPO_NAME constant
- save, merge, and commit



### Pants references
[https://pantsbuild.github.io/python-readme.html](https://pantsbuild.github.io/python-readme.html)<br>
[https://pantsbuild.github.io/install.html](https://pantsbuild.github.io/install.html)

