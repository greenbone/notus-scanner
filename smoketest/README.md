# Notus Smoketests

Notus smoketests are very simple test cases to verify the core functionality of Notus.

It is not meant to be fine granular tests but rather if the overall flow:
```
ospd-openvas -> openvas -> gatherpackagelist.nasl -> notus
```

is functioning.

Currently this is tested for

- Slackware 15

## How to add new images as a target

To add new images as a target you have to

- create a new target in the Makefile to spwan the new host
- create a new target to delete the new host
- adapt hosts.txt with the hostname username and password in the form us: `user:pass@host` in a new line

There are some requirements for a test image:

1. the image must have advisories and products defined in `/var/lib/notus` for the vulnerabilities of the image
1. the image must start an ssh server with a known username and password to login
