
var _ = require("lodash");

exports.writeResponse = function writeResponse(resp, response, status) {

    resp.json(JSON.stringify(response));
};

exports.writeError = function writeError(res, error, status) {
    // sw.setHeaders(res);
    res.send(status, JSON.stringify(_.omit(error, ["status"])));
};