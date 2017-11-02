#!/usr/bin/env node
const {createMsg1, verifyMsg2, createMsg3, verifyMsg4, clientOutcome} = require('../crypto-client');

const network_identifier = Buffer.from(process.argv[2], 'hex');
const server_longterm_pk = Buffer.from(process.argv[3], 'hex');

const clientState = {
  client_longterm_sk: Buffer.from([243, 168, 6, 50, 44, 78, 192, 183, 210, 241, 189, 36, 183, 154, 132, 119, 115, 84, 47, 151, 32, 32, 26, 237, 64, 180, 69, 20, 95, 133, 92, 176, 225, 162, 73, 136, 73, 119, 94, 84, 208, 102, 233, 120, 23, 46, 225, 245, 198, 79, 176, 0, 151, 208, 70, 146, 111, 23, 94, 101, 25, 192, 30, 35]),
  client_longterm_pk: Buffer.from([225, 162, 73, 136, 73, 119, 94, 84, 208, 102, 233, 120, 23, 46, 225, 245, 198, 79, 176, 0, 151, 208, 70, 146, 111, 23, 94, 101, 25, 192, 30, 35]),
  client_ephemeral_sk: Buffer.from([80, 169, 55, 157, 134, 142, 219, 152, 125, 240, 174, 209, 225, 109, 46, 188, 97, 224, 193, 187, 198, 58, 226, 193, 24, 235, 213, 214, 49, 55, 213, 104]),
  client_ephemeral_pk: Buffer.from([79, 79, 77, 238, 254, 215, 129, 197, 235, 41, 185, 208, 47, 32, 146, 37, 255, 237, 208, 215, 182, 92, 201, 106, 85, 86, 157, 41, 53, 165, 177, 32]),
  server_longterm_pk,
  network_identifier
};

process.stdout.write(createMsg1(clientState));

// State machine, not the shs state
let state = 'WroteMsg1';

process.stdin.on('readable', () => {
  switch (state) {
    case 'WroteMsg1':
      {
        const msg2 = process.stdin.read();

        if (!verifyMsg2(clientState, msg2)) {
          process.exit(2);
        }

        process.stdout.write(createMsg3(clientState));
        state = 'wroteMsg3';
      }
      break;
    case 'wroteMsg3':
      {
        const msg4 = process.stdin.read();

        if (!verifyMsg4(clientState, msg4)) {
          process.exit(4);
        }

        const outcome = clientOutcome(clientState);
        process.stdout.write(Buffer.concat([
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
