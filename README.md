# MyVirtualDirectory
Open Source LDAP Virtual Directory

[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/514/badge)](https://bestpractices.coreinfrastructure.org/projects/514)

Applications need to know who users are and what permisions they have.  While most enterprises have some form of an LDAP directory and most applications support LDAP the gap between what an enterprise has and what an application can integrate with.  Some common issues a viretual directory can solve:

* Multiple Active Directory Forests - Most apps only know how to talk to a single directory, a virtual directory can combine them in real time transparently
* Authenticate against one directory, authorize againat another - The people who own your enterprise's directory aren't generally responsible for your application.  Getting groups and authorizations into the enterprise directory isn't their priority.  Use a virtual directory you can control authorizations without involving the enterprise directory.
* Additional Attributes - Just like with authorizations, storing additional attributes in an enterprise directory can lead to conflicts with the enterprise directory's owners.  A virtual directory can store additional attributes outside of your enterprise directory transparently to your application.
* Data Transformation - Your application was probably written for a specific brand of directory, slight variances between vendors can be difficult to manage.  A virtual directory can map this data easily.

## Feedback and Bugs

All feedback, bugs and support requests must be submiteed through this github project's issues

## Contributions

All contributions should be submnitted as pull requests.  All pull requests must include test cases that verify the functionality changes.

## Submitting Vulnerabilites

Please send all vulnerabilities to security@tremolosecurity.com.  Tremolo Security maintains an internal GitLab deployment where we will track vulnerabilities until a patch is released at which point the issue will be posted to the public GitHub repo with full credit given to the discoverer of the vulnerability.  We will respond to any vulnerability reports within 14 days of receipt.

## Building Without Unit Tests

To build MyVirtualDirectory without the unit tests, run `mvn package -DskipTests=true`

## Building With Unit Tests

In order to run the unit tests OpenLDAP's slapd must be installed *NOTE* MacOS' OpenLDAP server will not work.  If you're using MacOS use either brew or macports to run slapd.  Once slapd is installed, create the following environment variabls:

| Environment Variable | Example | Description |
| -------------------- | ------- | ----------- |
| PROJ_DIR             | /path/to/MyVirtualDirectory | The path to the MyVirtualDirectory project |
| SCHEMA_DIR           | /etc/openldap | Path to OpenLDAP's pre-build schemas |
| SLAPD_PATH | /usr/sbin | Directory containing the `slapd` binary |
| TMP_DIR | /tmp/ldap | A temporary directory used for creating local ldap servers *NOTE* this directory must exist before running tests |


