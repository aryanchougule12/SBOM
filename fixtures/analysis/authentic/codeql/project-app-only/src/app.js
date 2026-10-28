// Variant: the vulnerable call is in the application itself, not in the vendored library.
const http = require("http");
const url = require("url");
const cp = require("child_process");

http.createServer((req, res) => {
  const query = url.parse(req.url, true).query;
  cp.exec("tool " + query.cmd);
  res.end("ok");
}).listen(8080);
