#!/usr/bin/env node

import { main } from "../src/server.js";

main(process.argv.slice(2)).catch((error) => {
  const message = error && error.stack ? error.stack : String(error);
  console.error(message);
  process.exit(1);
});
