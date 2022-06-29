// extracts just the data from the query results

const _ = require('lodash');

const User = module.exports = function (_node) {
    const email = _node.properties['email'];
    const name = _node.properties['name'];
    const age = _node.properties['age'];
    const phone = _node.properties['phone'];

    _.extend(this, {
        'id': _node.properties['id'],
        'email': email,
        'name': name,
        'age': age,
        'phone': phone
    });
};