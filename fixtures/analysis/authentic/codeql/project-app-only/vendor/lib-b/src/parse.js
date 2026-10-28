// Minimal "vendored library" containing the vulnerable code (written for this repository's validation; MIT).
const cp = require("child_process");

function parse(input) {
  cp.exec("tool " + input);
}

module.exports = { parse };
