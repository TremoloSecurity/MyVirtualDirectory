# MyVirtualDirectory
Open Source LDAP Virtual Directory

[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/514/badge)](https://bestpractices.coreinfrastructure.org/projects/514)

Applications need to know who users are and what permissions they have.  While most enterprises have some form of an LDAP directory and most applications support LDAP the gap between what an enterprise has and what an application can integrate with.  Some common issues a virtual directory can solve:

* Multiple Active Directory Forests - Most apps only know how to talk to a single directory, a virtual directory can combine them in real time transparently
* Authenticate against one directory, authorize against another - The people who own your enterprise's directory aren't generally responsible for your application.  Getting groups and authorizations into the enterprise directory isn't their priority.  Use a virtual directory you can control authorizations without involving the enterprise directory.
* Additional Attributes - Just like with authorizations, storing additional attributes in an enterprise directory can lead to conflicts with the enterprise directory's owners.  A virtual directory can store additional attributes outside of your enterprise directory transparently to your application.
* Data Transformation - Your application was probably written for a specific brand of directory, slight variances between vendors can be difficult to manage.  A virtual directory can map this data easily.

## Feedback and Bugs

All feedback, bugs and support requests must be submitted through this GitHub project's issues

## Contributions

All contributions should be submitted as pull requests.  All pull requests must include test cases that verify the functionality changes.

## Submitting Vulnerabilities

Please send all vulnerabilities to security@tremolosecurity.com.  Tremolo Security maintains an internal GitLab deployment where we will track vulnerabilities until a patch is released at which point the issue will be posted to the public GitHub repository with full credit given to the discoverer of the vulnerability.  We will respond to any vulnerability reports within 14 days of receipt.
