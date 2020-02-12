---
layout: default
title: FAQs
permalink: /faq/
---

This page is a collection of common questions about YAWAST.

### Can I use YAWAST commercially?

This can mean one of two things, which will be answered separately:

*Can I use YAWAST as part of paid work?*

Absolutely. That's really what it's for. The goal of YAWAST is to make professionals more productive and allow them to spend more time on manual testing, instead of spending so much time on things that could be automated.

*Can I integrate YAWAST into a commercial product?*

This is a complicated question. While YAWAST itself is [licensed](https://github.com/adamcaudill/yawast/blob/master/LICENSE) under the MIT license which is very permissive, YAWAST also uses a number of third-party libraries which have various [OSI](https://opensource.org/) licenses. These licenses have different terms which may impact you, and may limit how you can integrate YAWAST. Given the number of licenses involved, we do not take a position on your ability to integrate YAWAST into a commercial product. If this is your intention, you will need to review all dependencies, and likely consult with an attorney to determine what you are and aren't able to do within the various licenses.

### What does the name mean?

When this project was started, the original name was "Yet Another Web Application Security Tool" - as the project became more serious, the name was changed to "YAWAST Antecedent Web Application Security Toolkit." The current name better reflects the role of the tool, and its place in the penetration tester's workflow. It's meant to be a first step, to come before the serious manual work, and provide information to allow a tester to be up and running more quickly. The tests that are performed are based on that goal, as well as the availability and complexity of tests in other tools. If another common tool can do a given task better, it won't be done here.

### What is yawast.dev?

In the unlikely event that you see traffic originating from `yawast.dev`, that is a server used by the YAWAST core contributors for testing the application. If you see traffic from this server, it is likely in response to a bug report.

### Why did YAWAST change from Ruby to Python?

YAWAST was started in 2013, and at the time Ruby was a preferred language in the security community, at least in part due to Metasploit Framework being written in Ruby. Fast forward six years, and Ruby has fallen out of favor in the community. In a poll of those in the community that are likely to contribute to a project like YAWAST, we found that the vast majority were more likely to contribute if the application was written in Python; in fact, Ruby scored as the language least likely to lead people to contribute.

Based on the popularity of Python and the poll indicating that being written in Python would make contributions more likely, the decision was made to completely rewrite YAWAST. With the rewrite, we believe that it will lead to more participation and provide a healthier future for the project.

### Does YAWAST receive financial support?

No.
