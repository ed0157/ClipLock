# Security policy

ClipLock handles things people copy, including passwords and keys, so security reports are welcome.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private reporting instead: open the **Security** tab of this repository and choose **Report a vulnerability**. Include the ClipLock version, your macOS version, and the steps to reproduce.

This is a small project maintained in spare time. Reports are handled on a best-effort basis, with no guaranteed response time.

## What is in scope

- Ways to read saved history without the encryption key.
- Secrets being saved or shown when the settings say they should not be.
- Problems in the build or release pipeline that could change what users download.

## Known limits (not vulnerabilities)

These are described in the README: the app is not notarized or sandboxed, hiding a secret in the menu is not protection against someone who can use your Mac with your login password, and secret detection is best-effort.
