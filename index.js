#!/usr/bin/env node
const chalk = require('chalk');

const testServer = require('./test-server');
const testClient = require('./test-client');

const server = process.argv[2];
const client = process.argv[3];
const seed = process.argv[4];

let failures = 0;
let runs = 0;
const cb = didFail => {
  runs += 1;
  if (didFail) {
    failures += 1;
  }

  if (runs === 2) {
    if (failures > 0) {
      console.log(chalk.red('Did not pass the test suite.'));
      process.exit(1);
    } else {
      console.log(chalk.green('All tests passed.'));
      process.exit(0);
    }
  }
};

testServer(server, seed, cb);
testClient(client, seed, cb);
