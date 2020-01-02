---
layout: post
title:  "YAWAST 0.11 Released"
date:   2020-01-02 12:57:00 -0400
author: 'Adam Caudill'
---

Today we are pleased to announce the immediate release of YAWAST v0.11.0 - this is a regular release, as part of our normal release cadence. This is a feature and bug-fix release, adding a few new features and improving efficiency.

This version also includes a breaking change to the JSON file output; this changes the file to reference the hash of a HTTP request and response, and stores the actual value separately. This results in a drastic file size reduction for most web applications, as it is not uncommon for a single response to trigger multiple findings. While this does require any code that was written to parse YAWAST's JSON output to be updated, we believe that the improved efficiency to justify this cost. 

### Change Log

* [#164](https://github.com/adamcaudill/yawast/issues/164) - Apache Tomcat Version Detection via 406 Not Acceptable
* [#181](https://github.com/adamcaudill/yawast/issues/181) - HSTS Preload Checking (via HSTSPreload.com API) 
* [#192](https://github.com/adamcaudill/yawast/issues/192) - Check for Missing Cache Control Headers 
* [#306](https://github.com/adamcaudill/yawast/issues/306) - External JavaScript Lacks SRI
* [#308](https://github.com/adamcaudill/yawast/issues/308) - Telerik UI for ASP.NET AJAX RadAsyncUpload Enabled
* [#312](https://github.com/adamcaudill/yawast/issues/312) - Make JSON Storage More Efficient
* [#313](https://github.com/adamcaudill/yawast/issues/313) - Improve File Search for Misconfigured Servers
* [#319](https://github.com/adamcaudill/yawast/issues/319) - Enumerate HTTP Methods

### Feedback & Support

As always, if you discover any issues or have a feature request, please open an [issue](https://github.com/adamcaudill/yawast/issues/new) and provide as much information as possible.
