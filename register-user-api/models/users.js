"use strict"

const uuid = require('uuid');
const randomstring = require("randomstring");
const _ = require('lodash');
const User = require('../models/neo4j/user');
const crypto = require('crypto');

const register = function (session, username, password) {
    return session.readTransaction(txc => txc.run('MATCH (user:User {username: $username}) RETURN user', { username: username }))
        .then(results => {
            if (!_.isEmpty(results.records)) {
                throw { message: 'usuário já existe', status: 400 }
            }
            else {
                return session.writeTransaction(txc => txc.run('CREATE (user:User {id: $id, username: $username, password: $password, api_key: $api_key}) RETURN user',
                    {
                        id: uuid.v4(),
                        username: username,
                        password: hashPassword(username, password),
                        api_key: randomstring.generate({
                            length: 20,
                            charset: 'hex'
                        })
                    }
                )).then(results => {
                    return new User(results.records[0].get('user'));
                }
                )
            }
        });
};

const me = function (session, apiKey) {
    return session.readTransaction(txc => txc.run('MATCH (user:User {api_key: $api_key}) RETURN user', { api_key: apiKey }))
        .then(results => {
            if (_.isEmpty(results.records)) {
                throw { message: 'invalid authorization key', status: 401 };
            }
            return new User(results.records[0].get('user'));
        });
};

const login = function (session, username, password) {
    return session.readTransaction(txc => txc.run('MATCH (user:User {username: $username}) RETURN user', { username: username }))
        .then(results => {
            if (_.isEmpty(results.records)) {
                return { username: 'usuário não existe', status: 400 }
            }
            else {
                const dbUser = _.get(results.records[0].get('user'), 'properties');
                if (dbUser.password != hashPassword(username, password)) {
                    return { password: 'senha inválida', status: 400 }
                } else
                    return { token: _.get(dbUser, 'api_key') };
            }
        }
        );
};

const update = function (session, apiKey, username, password) {
    return session.session.readTransaction(txc => txc.run('MATCH (user:User {api_key: $api_key}) RETURN user', { api_key: apiKey }))
        .then(results => {
            if (_.isEmpty(results.records)) {
                throw { message: 'invalid authorization key', status: 401 };
            }
            else {
                return session.writeTransaction(txc => txc.run('MATCH (user:User {api_key: $api_key}) SET user +={username: $username, password: $password} RETURN user',
                    {
                        username: username,
                        password: hashPassword(username, password),

                    }
                )).then(results => {
                    return new User(results.records[0].get('user'));
                }
                )
            }
        });
}

const deleteUser = function (session, apikey) {
    return session.readTransaction(txc => txc.run('MATCH (user:User {api_key: $api_key}) RETURN user', { api_key: apiKey }))
        .then(results => {
            if (_.isEmpty(results.records)) {
                throw { message: 'invalid authorization key', status: 401 };
            }
            else {
                return session.writeTransaction(txc => txc.run('MATCH (user: User {api_key: $api_key}) DETACH DELETE user',
                    { api_key: apiKey }
                )).then(results => {
                    return 'Usuário deletado com sucesso';
                })
            }
        });
}

function hashPassword(username, password) {
    const s = username + ':' + password;
    return crypto.createHash('sha256').update(s).digest('hex');
}

module.exports = {
    register: register,
    me: me,
    login: login,
    update: update,
    deleteUser: deleteUser
};