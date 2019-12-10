---
layout: post
title:  "YAWAST 0.9 Released"
date:   2019-09-04 12:57:00 -0400
author: 'Adam Caudill'
---

Today we are pleased to announce the immediate release of YAWAST v0.9.0 - this is a regular monthly release, as part of our normal beginning of the month release cadence. This is a feature and bug-fix release, addressing an uncommon bug, and adding a few new features.

The most important new feature is the addition of the `--header='name=value'` parameter, which allows you to specify a header (such as a bearer token) that will be include in each request. This allows you to perform authenticated scans of applications that don't use session cookies.

### Change Log

* [#20](https://github.com/adamcaudill/yawast/issues/20) - Check for common backup files
* [#207](https://github.com/adamcaudill/yawast/issues/207) - Specify JWT Similar To Cookie
* [#235](https://github.com/adamcaudill/yawast/issues/235) - WordPress Plugin Local Path Disclosure
* [#244](https://github.com/adamcaudill/yawast/issues/244) - Check for common files with phpinfo()
* [#264](https://github.com/adamcaudill/yawast/issues/264) - Add new version command
* [#237](https://github.com/adamcaudill/yawast/issues/237) - Bug: Connection error in check_local_ip_disclosure

### Feedback & Support

As always, if you discover any issues or have a feature request, please open an [issue](https://github.com/adamcaudill/yawast/issues/new) and provide as much information as possible.
