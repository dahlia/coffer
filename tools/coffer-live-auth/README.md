coffer-live-auth
================

`coffer-live-auth` is the developer-only harness that runs one live Apple
Account authentication through the Coffer crates. It is an engineering check
for Milestone 1, not part of the Coffer application, and it is deliberately
excluded from `mise run test` and `mise run ci`.

Run it only on a machine and with an account you control:

~~~~ sh
mise run test-live-auth
~~~~

The task builds `coffer-anisette-helper` and the harness in the same graph and
then starts the harness, which locates the helper beside itself.


What one run does
-----------------

1.  Resolves or creates the opaque profile slot under
    *$XDG\_STATE\_HOME/coffer/live-auth/profile-slot* (0700 directory, 0600
    file, symbolic links refused, corrupt state never replaced).
2.  Checks that Secret Service is reachable and unlocked before anything
    else, so a missing keyring never costs an authentication attempt.
3.  Runs the Apple support-library bootstrap, reusing a verified install or
    downloading once from Apple's pinned URL.
4.  Generates local anisette headers. If the machine is not provisioned, it
    asks you to type `provision` and then runs exactly one provisioning
    attempt.
5.  Asks for the account name and the password, both without echo, on
    */dev/tty* and runs the initial SRP exchange once.
6.  If a trusted-device code is required, requests one push, asks for the
    code once, submits it once, asks for the password again, and runs the
    post-2FA exchange once.
7.  Writes the reusable session to Secret Service under the slot, reloads it
    over a new connection, and compares.

Every step runs once. Any failure stops the run with a static, stage-labelled
message. Nothing is retried, no redirect or proxy is followed, and there is no
remote anisette or plaintext fallback anywhere in the graph.


Human interaction points
------------------------

In order: possibly the word `provision` (only on an unprovisioned machine,
before any account prompt), the account name, the password, and, only if the
account requires a trusted-device code, the verification code and the password
a second time. Everything is read from the controlling terminal with echo off,
except the one-word provisioning confirmation. The binary refuses to start if
it is given any argument, and nothing it prints contains an account, token,
code, header, body, slot, or path.

If a hidden prompt is interrupted with Ctrl-C, the terminal mode is restored
and the run stops once the line ends; a `SIGTERM` or `SIGHUP` that arrives
during a hidden prompt is likewise deferred until the mode is restored and
then takes its default effect.


What the success report means
-----------------------------

The report lists static verdicts: local anisette, the initial SRP exchange,
whether the trusted-device and post-2FA branches ran, the Secret Service store
and reload, and the absence of a remote fallback. The two-factor lines are
marked verified only if the account actually required a code during the run.
The Secret Service line means persistence and reload only: the protocol crate
has no service-token refresh yet, so no stored session is used to talk to Apple
again.
