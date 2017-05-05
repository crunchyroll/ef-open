## Installing pants
To build the ef-open tools, you will need to install pants on the path
above the repos, typically "at the top directory of the workspace"

See:<br>
[https://pantsbuild.github.io/python-readme.html](https://pantsbuild.github.io/python-readme.html)<br>
[https://pantsbuild.github.io/install.html](https://pantsbuild.github.io/install.html)


> To set up pants in your repo, we recommend installing our self-contained pants bash script
> in the root (ie, "buildroot") of your repo. In this example, ~/workspace is the
top of all repos. Pants is installed there.

```
$ cd ~/workspace
$ curl -L -O https://pantsbuild.github.io/setup/pants && chmod +x pants && touch pants.ini
```

Pin the version of pants
```
$ ./pants -V
1.1.0
```

... by placing the version number in ~/workspace/pants.ini:
```
[GLOBAL]
pants_version: 1.1.0
```

## to build ef-cf as a frestanding binary
```
$ cd ~/workspace
# copy the site config file into the repo (later, pants BUILD will find it)
$ cp /path/to/ef_site_config.py ./ef-open/src
# build all the binaries
./pants binary ef-open/src:
```
