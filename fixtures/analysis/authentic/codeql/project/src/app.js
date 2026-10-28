// Minimal example application (written for this repository's validation; MIT).
const http = require("http");
const url = require("url");
const libB = require("../vendor/lib-b/src/parse.js");

http.createServer((req, res) => {
  const query = url.parse(req.url, true).query;
  libB.parse(query.cmd);
  res.end("ok");
}).listen(8080);
