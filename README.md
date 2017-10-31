# Testsuite for Secret-Handshake Version 1
The [shs](https://github.com/auditdrivencrypto/secret-handshake) protocol is a handshake protocol for deriving shared secrets. This repository provides a language-independent testsuite. To run the testsuite, run `node index.js path-to-server path-to-client`. The arguments are the paths to executables which are automatically run by the suite. They should behave as follows:

#### Server
The server executable must write a public key to stdout. It then waits for a client to initiate a handshake via stdin (using the previously written public key) and writes its responses to stdout (not newline-terminated, the testsuite knows how many bytes to read). If the client is not well-behaved, the server may not respond and must terminate with a non-zero exit code.  
If the client is well-behaved, the server must respond with the final message and then write to stdout in order: the encryption key, the encryption nonce, the decryption key and the decryption nonce. Then the server must exit with exit code 0.

#### Client
The client executable receives the app key as its first command-line argument, and a public key as its second command line argument. It must then initiate a handshake via stdout, and read responses from stdin. If the server is not well-behaved, the client may not respond and must terminate with a non-zero exit code.  
If the server is well-behaved, after sending its final message, the client must write to stdout in order: the encryption key, the encryption nonce, the decryption key and the decryption nonce. Then the client must exit with exit code 0.
