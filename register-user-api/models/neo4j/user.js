// extracts just the data from the query results

const _ = require('lodash');

const User = module.exports = function (_node) {
    const username = _node.properties['username'];

    _.extend(this, {
        'id': _node.properties['id'],
        'username': username,
    });
};