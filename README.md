acme-cli
========

acme-cli is a shell script interface to the
[acme-go](https://github.com/tommie/acme-go) library. It provides a
high-level API to automate
[ACME](https://tools.ietf.org/html/draft-ietf-acme-acme-01)
interactions, but is not intended as an end-user interface.

Distributed under the MIT license.

Building
--------

```sh
go get github.com/tommie/acme-cli
go build src/github.com/tommie/acme-cli/acmeclient/*.go
```

Examples
--------
Some use-cases for letsencrypt.org.

### Setup

The code below assumes the following variables are set to something
sensible. Sensible example values given.

```sh
CONTACT=me@example.com
DIR=https://acme-v01.api.letsencrypt.org/directory
KEY=myaccount.key
REG=myaccount.txt
CSR=mycert.csr
CERTKEY=mycert.key
CERTBUDNLE=mycertbundle.pem
set -e
```

### Create a new account

To create an account, first create an RSA key:

```sh
openssl genrsa -out "$KEY" 2048
```

Then register is as an account key:

```sh
acmeclient -dir="$DIR" -key="$KEY" newreg -contact="$CONTACT" >"$REG"
```

The ACME server may require you to accept the terms of service,
indicated by the existence of a Terms-Of-Service header in the
registration output. If you see one, you read it and set it as the agreement:

```sh
reg=$(sed 's/^URI: *\(.*\)/\1/ p ; d' <"$REG")
tos=$(sed 's/^Terms-Of-Service: *\(.*\)/\1/ p ; d' <"$REG")
acmeclient -dir="$DIR" -reg="$reg" -key="$KEY" \
  -agreement="$tos" updatereg
```

Now you have a registered account ready for use.

### Issue a certificate

This snippet issues a signed certificate. First create a key and signing request:

```sh
openssl req -new -sha256 -nodes -newkey rsa:2048 -keyout "$CERTKEY" -outform DER -out "$CSR"
```

Then pass it to the ACME server for authorization and signing:

```sh
reg=$(sed 's/^URI: (.*)/\1/ p ; d' <"$REG")
acmeclient -dir="$DIR" -reg="$reg" -key="$KEY" \
  -certformat=chain:pem \
  issuecert "$CSR" ./solver/apachesolver >"$CERTBUNDLE"
```

We assume the existence of a program called
[`apachesolver`](solver/apachesolver). This program must support the API
described in `issuecert` below. Other possible solvers include
setting up a proxy for TCP ports 80 and/or 443, configuring another
web server or using firewall rules to redirect the TCP ports.

Now you can use `$KEY` as your server private key and `$CERTBUNDLE` as
your certificate (which includes the full chain of CA
certificates). Some programs may require you to split off you
certificate from the CA chain. This can be accomplished with `openssl`
(see [source
post](http://openssl.6102.n7.nabble.com/Convert-pem-to-crt-and-key-files-td47681.html#a47697)):

```sh
openssl crl2pkcs7 -nocrl -certfile "$CERTBUNDLE" | \
  openssl pkcs7 -print_certs -out ca-bundle.pem
openssl x509 -in "$CERTBUNDLE" -outform PEM -out cert.pem
```

The files `ca-bundle.pem` and `cert.pem` now have what you want.

### apachesolver

This is an example solver program for Apache web servers, written in
Bash. It supports solving the http-01 challenge with cost 1.

For http-01, a file is created in a directory, and Apache is expected
to be configured to publish this directory as
`http://$name/.well-known/acme-challenge`. An example configuration is

```apache
Alias /.well-known/acme-challenge/ /var/www/localhost/acme-challenge/
<Location "/.well-known/acme-challenge/">
  Options None
  Order allow,deny
  Allow from all
</Location>
```

This directory should normally be empty. It should be publicly
accessible, and directory listings are disabled by `Options None`
above.

You can change the paths using environment variables:

* `ACME_CHALLENGE_DIR` is where to store the http-01 files.

See the top of the script file for more information.

Commands
--------

### help

Show a short version of this documentation.

### newreg

Register a new account. `-dir` and `-key` are required. Outputs
registration URI. If a ToS has to be accepted, its URI is also
listed.

### reg

Show information about the account registration. `-dir`, `-reg` and
`-key` are required.

### updatereg

Update an account. `-dir`, `-reg` and `-key` are required. Can be used
to e.g.  accept the ToS.

### issuecert <csr-path> <solver-command>...

Issue a certificate for a given X.509 certificate signing request in
DER format. `-dir`, `-reg`, and `-key` are required. The certificate
is output on stdout on success. Use `-certformat=chain:pem` to output
the entire CA chain as a PEM file.

The solver command is executed with environment variables

* `ACME_MODE={cost, solve}`
  Indicating the mode of operation. See below.
* `ACME_ACCOUNT_JWK=<JWK>`
  Being the base64-encoded JSON web key for the current
  account. This is needed for the proofOfPossession-01 challenge.

In all modes, the solver receives CSV records on stdin, one record per
challenge. The final record is empty (an empty line). The first field
is the challenge type. Remaining fields depend on the type:

```
{dns-01, http-01}    <token> <key-authorization>
proofOfPossession-01 <base64-DER-cert>...
tls-alpn-01          <base64-validation-string>
```

All base64 data use the URL-safe character set in RFC 4648. All CSV
records use tab as the field separator and new-line as the record
separator.

Mode `cost` should compute a solving cost for all the challenges
combined. It writes the (64-bit float) cost to stdout if it can solve
all challenges, and nothing if it cannot solve them.

Mode `solve` should start solvers for all challenges. It must write
one response CSV-record per challenge, once the solver is able to
accept validation for that challenge. When stdin is closed, the
process must terminate and clean up after the solvers. Responses start
with the challenge type, and the formats are

```
{dns-01, http-01}    <key-authorization>
proofOfPossession-01 <compact-JWS-authorization>
tls-alpn-01
```

Returning non-zero exit status causes the command to fail.

### certs

List URIs of issued certificates. `-dir`, `-reg` and `-key` are
required. Use `-v` to also display some certificate details in human
readable form.

### certs <uri>...

Output certificates for the given URIs. `-dir`, `-reg` and `-key` are
required. Use `-certformat=chain:pem` to output the entire CA chain as
a PEM file.

### revokecert <uri>

Revoke the given certificate. `-dir`, `-reg` and `-key` are required.
