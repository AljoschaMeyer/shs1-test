# Testsuite for Secret-Handshake Version 1
The [shs](https://github.com/auditdrivencrypto/secret-handshake) protocol is a handshake protocol for deriving shared secrets. This repository provides a language-independent testsuite, both for the server and the client parts of shs.

## Usage
Run `npm install shs1-test` to get the `shs1testserver` and `shs1testclient` commands described below. Alternatively, you can directly execute `node test-server.js path_to_executable [seed]` or `node test-client.js path_to_executable [seed]` without having to install the module.

As an example of test executables, see [the test scrips of shs1-crypto-js](https://github.com/AljoschaMeyer/shs1-crypto-js).

### Testing the Server Role
Run `shs1testserver path_to_executable [seed]` to test the server side of the protocol. The `seed` argument is optional to make the test fully deterministic. The script will execute the file at `path_to_executable`, passing three arguments: a `network_identifier`, a `server_longterm_sk` and a `server_longterm_pk`, all encoded in hex. The executable must then perform the server role of the handshake via stdin and stdout, using the given arguments as intial parameters (server_ephemeral keys can be chosen freely).

The test script might either correctly perform the client side of a handshake, or it might misbehave.

If the server detects that the client is not well-behaved, it must immediately exit with a non-zero exit code, without writing any further data to stdout.

If a full handshake has been correctly performed up until receiving msg3, the server must then write the concatenation of msg4, and its `encryption_key`, `encryption_nonce`, `decryption_key` and `decryption_nonce` to stdout. It must then either terminate on its own or wait to terminate upon receiving a SIGTERM signal.

So overall:

- read 64 bytes msg1 from stdin
- write 64 bytes msg2 to stdout
- read 112 bytes msg3 from stdin
- write 80 + 32 + 24 +32 +24 = 192 bytes msg4 and outcome to stdout
- terminate (upon receiving SIGTERM)

All data written by the server to stderr is written to the stderr of the test script (useful for debugging).

### Testing the Client Role
Run `shs1testclient path_to_executable [seed]` to test the client side of the protocol. The `seed` argument is optional to make the test fully deterministic. The script will execute the file at `path_to_executable`, passing two arguments: a `network_identifier` and a `server_longterm_pk`, both encoded in hex. The executable must then initate and execute a handshake via stdin and stdout, using the given arguments as intial parameters (client and ephemeral keys can be chosen freely).

The test script might either correctly perform the server side of a handshake, or it might misbehave.

If the client detects that the server is not well-behaved, it must immediately exit with a non-zero exit code, without writing any further data to stdout.

If a full handshake has been correctly performed up until receiving msg4, the client must then write the concatenation of its `encryption_key`, `encryption_nonce`, `decryption_key` and `decryption_nonce` to stdout. It must then either terminate on its own or wait to terminate upon receiving a SIGTERM signal.

So overall:

- write 64 bytes msg1 to stdout stdin
- read 64 bytes msg2 from stdin
- write 112 bytes msg3 to stdout
- read 80 bytes msg4 from stdin
- write 32 + 24 + 32 + 24 = 112 bytes outcome to stdout
- terminate (upon receiving SIGTERM)

All data written by the client to stderr is written to the stderr of the test script (useful for debugging).
