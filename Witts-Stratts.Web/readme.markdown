# Witts & Stratts Backend Developer Task

## Overview

According to wikipedia, TOTP (Time-based one-time password; RFC 6238) is a means of generating unique one-time password, by taking its uniqueness from the current time. TOTP is an extension of HOTP, a one-time password (OTP) algorithm based on HMAC (RFC 4226).

The basic idea of TOTP is to generate a token that will serve as an extra means of security for internet applications. An example is your GTB app that requires the use of a hardware (or _\*737#_ service) to generate a token to validate a transaction or Github.com that uses a validator app or SMS to provide a token for 2-factor authentication.

TOTP uses a shared secret, which is available to both the server and the token generating device/platform.

<img src="https://www.microcosm.com/images/smartsign/otp.png" width="400"/>

<img src="https://www.telesign.com/wp-content/uploads/2015/09/sms_verify_graph.png" width="400" />

## Task

Create a simple web app that generates a TOTP using the secret key (MKBSWN3DPEHPK2PXZ) and a time cut-off of 30 seconds. Also provide a means of validating a provided TOTP token generated from your application.

A web interface is provided for you. All you need to do is to hook your endpoints to the various button interface.

You can use any library, programming language and framework of your choice.

To submit your answers, please upload it to github.com and send the link to us.

PS: To test the validity of your tokens and your program, you can use an app like authy (https://authy.com)

### What we are looking for:

- Your ability to read technical requirements and translate them in to working code
- Your code organisational structure and attention to detail
- Your affinity for test-driven development and acknowledgment of edge-cases

### Appendix

**RFC 4226:** <a href="https://tools.ietf.org/html/rfc4226" title="RFC4226">RFC4226</a>

**RFC 6238:** <a href="https://tools.ietf.org/html/rfc6238" title="RFC6238">RFC6238</a>

**TOTP on wikipedia:** <a href="https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm" title="TOTP">TOTP</a>

**Secret Key:** MKBSWN3DPEHPK2PXZ
