## Contributing to YAWAST

First of all, thanks for your interest in contributing to YAWAST! This document will provide you with useful information to make it as easy as possible.

### Core Contributors

* [Adam Caudill](https://github.com/adamcaudill)
  * Project Maintainer
  * macOS & Linux Build Maintainer
* [Brandon Wilson](https://github.com/brandonlw)
  * Windows Build Maintainer

### Code Changes & Pull Requests

Here are some key points to keep in mind when it comes to contributing code. If you have any questions, feel free to ask.

* All changes to YAWAST must be made via Pull Request, and reviewed by one of the core contributors.
* Unit tests covering as many scenarios as possible are strongly encouraged. If you are unable to supply unit tests that cover at least 80% of your change, please explain why as part of your pull request.
* Please include "WIP" in the title of your pull request until you feel it's ready to be reviewed.
* No pull request will be merged if the CI build fails.
* All changes must work properly on the latest version of macOS, Windows, and Kali Linux. New *features* that only work on one platform will not be considered; however, fixes or improvements that are platform specific are fine.
* Code is formatted using [Black](https://github.com/psf/black); while not required, we do request that you format the code with Black before opening your pull request.
* The use of [pipenv](https://docs.pipenv.org/en/latest/) to build and maintain a clean environment is strongly recommended.
* The core contributors use [PyCharm](https://www.jetbrains.com/pycharm/) as our IDE of choice; it's the best option we have found for working with this code.
* Care should be taken to avoid violating the plugins abstraction layer - plugins should not directly interact with a UI of any type.
* You should include a change to the [CONTRIBUTORS.md](https://github.com/adamcaudill/yawast/blob/master/CONTRIBUTORS.md) file to add your name.

### Building Windows Executable

In order to build an executable version on Windows, first ensure you have installed cx_Freeze 6.x+. As of this writing, you can do this via:

```
pip install --upgrade git+https://github.com/anthony-tuininga/cx_Freeze.git@master
```

You can then build the executable with:

```
python setup.py build_exe
```

#### Git Branches

YAWAST uses two main branches, `master` and `develop`, which are defined as follows:

* `develop` - This is where the bulk of the work goes on. Changes are made to this branch via Pull Requests. When a change is deemed as production ready, a pull request is made to add the code to `master`.
* `master` - This is where releases are built, and the source for our Docker image (which is updated with every commit). Code in this branch MUST never be broken. Do not open a Pull Request against `master`; all Pull Requests must be against `develop`.

To ensure that `master` remains usable, we use a simplified form of [gitflow](https://nvie.com/posts/a-successful-git-branching-model/).

#### New Dependencies

All dependencies must be released under an OSI approved license. Any change that adds code without an [OSI approved](https://opensource.org/licenses/alphabetical) license (except for code explicitly placed into the public domain) will be rejected.

Due to the cross platform nature of YAWAST, adding a new dependency can present unexpected complications. This is especially true for Windows, as we release an EXE build of YAWAST, and not all Python libraries handle that well. While not automatically rejected, please understand that this leads to additional testing and work by the core contributors.

Changes that require a new library be included may be rejected if the library does not work properly on any of the supported platforms or if it becomes too complex to include in the compiled Windows version.

#### Documentation Updates

All documentation is housed on the [YAWAST.org](https://yawast.org/) web site, which is hosted via Github Pages and stored in the `/docs` directory of the `master` branch. Corrections, improvements, and updates to the YAWAST documentation are very welcome.

#### Guest Blog Posts

If you would like to contribute a blog post that discusses how YAWAST can be used, how it has found something interesting, or is otherwise useful to YAWAST users, please open an issue with a brief overview of your planned post. If it appears to fit, we will ask you to draft the post and open a pull request.

Please note that the core contributors have final authority over the blog and may reject a post for any reason. The core contributors also reserve the right to edit a post as they see fit.

#### Copyright

It is not required of you to assign the copyright of your contributions; you retain the copyright. However, it is required that you make your contributions available under the MIT license in order for it be included.

All Python files (except those in the `yawast\external` directory) should include the following header:

```
# Copyright (c) 2013 - 2020 Adam Caudill and Contributors.
# This file is part of YAWAST which is released under the MIT license.
# See the LICENSE file or go to https://yawast.org/license/ for full license details.
```

### Opening Issues

Here is a high-level guide to opening issues, to save everyone time and make the process as effective as possible. Github issues are used to manage the project, from discussing changes to maintaining a list of planned and desired work. In general, issues are what drive everything.

#### Feature Requests

Any feature requests should contain as much detail as possible, including sample payloads when possible. The more detail that is added, the easier it is to add a new feature.

Before opening an issue for a feature request, please check to see if one already exists. If so, comment on it to indicate your interest - this will help us determine the interest in a change, and prioritize the most popular requests. The core contributors use issues as a "wish list" of sorts to document things that we would like to see done, so it's quite possible that we have already opened an issue for an idea.

#### Bug Reports

If you find a bug, please do open an issue so that we can address it. Please include all of the console output, as it contains important information (feel free to redact target information). If possible, run YAWAST with the `--output` option to generate a JSON file - this file contains debug output, which can help track the issue down. You can send this file privately to `bugs@yawast.org` for review.

Bug reports are given the highest priority, and whenever possible will be addressed in the next release.

#### Labels

One of the core contributors will apply the proper labels to new issues. This helps us to prioritize work, and make sure issues are handled efficiently.

Important Labels:

* bug - This is for a flaw in the YAWAST code, or a dependency issue that YAWAST needs to work around.
* enhancement - These are requests or suggestions for new or improved features. These will be considered for a future version, and will be addressed as time allows.
* help wanted - These are issues that are not currently being worked on, and are available for anyone that would like to help. If there's an issue with this status that you would like to work on, just reply and let us know. We will update the status of the issue so we don't run into duplicated effort.
* beginner - These are issues that are less complex, and great for becoming familiar with working on YAWAST.
* blocked - These are issues that are blocked by some other issue, and can't be addressed until the other is handled.
* blocker - These are issues that are preventing others from being addressed.

#### Milestones

If an issue will be addressed with a code change, it will be assigned to a milestone. Milestones are generally one of the following:

* Version Under Development
* Next Version
* Future (no specific version)

Assigning an issue to a milestone is an indication that we would like to address it, and an indication of when we think it might happen - but it is not a commitment. As this project is run on a volunteer basis, there may or may not be time to complete the work planned during a release window. As such, an issue may be moved (more than once) to the next version's milestone.

If you would like to see an issue addressed more quickly, feel free to open a pull request that addresses it - this is the fastest way for something to be dealt with.

### Releases & Versions

YAWAST uses the following versioning scheme:

`0.<release-number>.<bug-fix-number>`

For example, a version of `0.8.2` means that it is the 2nd bug release of the 8th major release. The leading digit is currently fixed at `0` and will remain fixed for the foreseeable future. 

The planned release cycle is to release a major version (i.e. `0.8.2` to `0.9.0`) at the last day of each month. While this is the current planned release cycle, it depends on completion of any large changes and the time available by the core contributors. Release of a minor version (i.e. `0.8.2` to `0.8.3`) will contain all new features and changes up to that point in time (it will not be limited to only including the bug fix); as such, a minor release may reset the schedule for the next major release, pushing it to the end of the next month.

Breaking interface changes will be avoided as much as possible, though if necessary, will only occur with a major version change (i.e. `0.8.0` to `0.9.0`).

Users are encouraged to always use the latest version, as it will include the latest fixes and features. Issues opened related to anything other than the latest version may be closed without action. 
