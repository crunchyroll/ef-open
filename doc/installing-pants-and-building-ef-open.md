## Installing pants and building ef-open tools
To build the ef-open tools, you will need to:
 - install pants on the path above the repos, typically "at the top directory of the workspace"
 - create and configure "ef_site_config.py" file and accompanying BUILD.siteconfig file in a repo you control
 - export an environment variable to tell pants where ef_site_config.py is

### Installing pants
From the pants documentation:
> To set up pants in your repo, we recommend installing our self-contained pants bash script
> in the root (ie, "buildroot") of your repo. In this example, ~/workspace is the
top of all repos. Pants is installed there.

For full details and the latest instructions, see [Installing Pants](http://www.pantsbuild.org/install.html) at pantsbuild.org

#### Assumptions in all examples below
- Common directory above all repos is "~/workspace"
- The ef-open repo is called "ef-open"
- The company or project's Cloudformation repo (holding templates and other things) is "my-repo"
- The company or project's repo is already set up (maybe empty, but it's ready to go)
- Overall structure of stuff discussed here is:<br>
<code>  ~/workspace <--- Common top-level directory above all repos (pants will be installed here)</code><br>
<code>  ~/workspace/ef-open <--- ef-open repo, sync'd with ef-open at github</code><br>
<code>  ~/workspace/my-repo <--- Cloudformation template repo with the project-specific config file my-repo/ef_site_config.py</code><br>
<code>  ~/workspace/my-repo/ef_site_config.py <--- project-specific configuration file</code><br>
- Also:<br>
<code>
  ~/workspace/examples/ef_site_config.py <--- example site config file to copy to my-repo/ef_site_config.py
</code>

#### 1. Install pants

```
#1. install pants
$ cd ~/workspace
$ curl -L -O https://pantsbuild.github.io/setup/pants && chmod +x pants && touch pants.ini
```

Check that pants runs and get the current version
```
$ ./pants -V
1.1.0
```

Edit ~/workspace/pants.ini to pin the pants version
```
[GLOBAL]
pants_version: 1.1.0
```

#### Define custom values for your tools to use
```

$ cp ~/workspace/examples/ef_site_config.py ~/workspace/my-repo/ef_site_config.py
# edit ~/workspace/my-repo/ef_site_config.py and set all values as appropriate for the company/project

```




## to build all the tools defined in src/BUILD
```
$ cd ~/workspace
$ export EF_SITE_CONFIG=<relpath>
$ ./pants binary ef-open/src:
```
### example building all the tools defined in src/BUILD
In this example, the directory structure is:
  workspace/
    ef_open/
    my_repo/

The ef_site_config file is in my_repo
```
$ cd ~/workspace
$ export EF_SITE_CONFIG=my_repo
./pants binary ef-open/src:
```


Pants references:<br>
[https://pantsbuild.github.io/python-readme.html](https://pantsbuild.github.io/python-readme.html)<br>
[https://pantsbuild.github.io/install.html](https://pantsbuild.github.io/install.html)

