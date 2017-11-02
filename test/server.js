#!/usr/bin/env node
const {verifyMsg1, createMsg2, verifyMsg3, createMsg4, serverOutcome} = require('../crypto-server');

const network_identifier = Buffer.from(process.argv[2], 'hex');
const server_longterm_sk = Buffer.from(process.argv[3], 'hex');
const server_longterm_pk = Buffer.from(process.argv[4], 'hex');

const serverState = {
  server_longterm_sk,
  server_longterm_pk,
  server_ephemeral_sk: Buffer.from([176, 248, 210, 185, 226, 76, 162, 153, 239, 144, 57, 206, 218, 97, 2, 215, 155, 5, 223, 189, 22, 28, 137, 85, 228, 233, 93, 79, 217, 203, 63, 125]),
  server_ephemeral_pk: Buffer.from([166, 12, 63, 218, 235, 136, 61, 99, 232, 142, 165, 147, 88, 93, 79, 177, 23, 148, 129, 57, 179, 24, 192, 174, 90, 62, 40, 83, 51, 9, 97, 82]),
  network_identifier
};

// State machine, not the shs state
let state = 'initial';

process.stdin.on('readable', () => {
  switch (state) {
    case 'initial':
      {
        const msg1 = process.stdin.read();

        if (!verifyMsg1(serverState, msg1)) {
          process.exit(1);
        }

        process.stdout.write(createMsg2(serverState));
        state = 'wroteMsg2';
      }
      break;
    case 'wroteMsg2':
      {
        const msg3 = process.stdin.read();

        if (!verifyMsg3(serverState, msg3)) {
          process.exit(3);
        }

        const outcome = serverOutcome(serverState);
        process.stdout.write(Buffer.concat([
          createMsg4(serverState),
          outcome.encryption_key,
          outcome.encryption_nonce,
          outcome.decryption_key,
          outcome.decryption_nonce
        ]));
      }
      break;
    default:
  }
});
