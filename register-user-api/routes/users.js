

const loginRequired = require('../middlewares/loginRequired')
const dbUtils = require('../neo4js/dbUtils.js')
const _ = require('lodash');
const uuid = require('uuid');
const randomstring = require("randomstring");
const User = require('../models/neo4j/user');
const crypto = require('crypto');

//register user  /register
exports.register = function (req, resp, next) {
    const name = _.get(req.body, 'name');
    const age = _.get(req.body, 'age');
    const email = _.get(req.body, 'email');
    const phone = _.get(req.body, 'phone');
    const password = _.get(req.body, 'password');

    if (!name) {
        resp.status(400);
        resp.json({ message: 'O nome é obrigatório.', status: 400 });
        next();
    }
    if (!age) {
        resp.status(400);
        resp.json({ message: 'A idade é obrigatório.', status: 400 });
        next();
    }
    if (!phone) {
        resp.status(400);
        resp.json({ message: 'O celular é obrigatório.', status: 400 });
        next();
    }
    if (!email) {
        resp.status(400);
        resp.json({ message: 'O email é obrigatório.', status: 400 });
        next();
    }
    if (!password) {
        resp.status(400);
        resp.json({ message: 'A senha é obrigatótia.', status: 400 });
        next();
    }

    dbUtils.getSession(req).readTransaction(txc => txc.run('MATCH (user:User {email: $email}) RETURN user', { email: email }))
        .then(results => {
            if (!_.isEmpty(results.records)) {
                resp.status(404);
                resp.json({ message: 'Usuário já cadastrado', status: 404 });
                next();
            }
            else {
                dbUtils.getSession(req).writeTransaction(txc => txc.run('CREATE (user:User {id: $id, name: $name, age: $age, phone: $phone, email: $email, password: $password, api_key: $api_key}) RETURN user',
                    {
                        id: uuid.v4(),
                        name: name,
                        age: age,
                        phone: phone,
                        email: email,
                        password: hashPassword(email, password),
                        api_key: randomstring.generate({
                            length: 20,
                            charset: 'hex'
                        })
                    }
                )).then(results => {
                    resp.status(201)
                    resp.json(User(results.records[0].get('user')));
                    next();
                }
                )
            }
        });

};

//login  /login
exports.login = function (req, resp, next) {
    const email = _.get(req.body, 'email');
    const password = _.get(req.body, 'password');

    if (!email) {
        resp.status(400);
        resp.json({ username: 'O email do usuário é obrigatório', status: 400 });
    }
    if (!password) {
        resp.status(400);
        resp.json({ password: 'A senha é obrigatória.', status: 400 });
    }


    dbUtils.getSession(req).readTransaction(txc => txc.run('MATCH (user:User {email: $email}) RETURN user', { email: email }))
        .then(results => {
            if (_.isEmpty(results.records)) {
                resp.status(404);
                resp.json({ message: 'usuário não existe', status: 404 });
                next();
            }
            else {
                const dbUser = _.get(results.records[0].get('user'), 'properties');
                if (dbUser.password != hashPassword(email, password)) {
                    resp.status(404);
                    resp.json({ message: 'senha inválida', status: 404 });
                    next();
                } else {
                    resp.status(200);
                    resp.json({ token: _.get(dbUser, 'api_key') });
                    next();
                }
            }
        }
        );
};

//get me  /users/me
exports.me = function (req, resp, next) {
    loginRequired(req, resp, () => {
        const authHeader = req.headers['authorization'];
        const match = authHeader.match(/^Token (\S+)/);

        if (!match || !match[1]) {
            resp.status(401);
            resp.json({ message: 'Não autorizado. Follow `Token <token>`', status: 401 });
            next();
        }

        const apiKey = match[1];

        dbUtils.getSession(req).readTransaction(txc => txc.run('MATCH (user:User {api_key: $api_key}) RETURN user', { api_key: apiKey }))
            .then(results => {
                const user = new User(results.records[0].get('user'));
                if (user) {
                    resp.status(200);
                    resp.json(user);
                    next();
                }
                else {
                    resp.status(401);
                    resp.json({ message: 'Token invállido', status: 401 });
                    next();
                }

            }).catch(next);
    })
};

//update /users/
exports.update = function (req, resp, next) {
    loginRequired(req, resp, () => {
        const authHeader = req.headers['authorization'];
        const match = authHeader.match(/^Token (\S+)/);
        if (!match || !match[1]) {
            resp.status(404);
            resp.json({ message: 'Formato de autenticação inválido. Follow `Token <token>`', status: 404 });
            next();
        }
        const name = _.get(req.body, 'name');
        const age = _.get(req.body, 'age');
        const email = _.get(req.body, 'email');
        const phone = _.get(req.body, 'phone');
        const password = _.get(req.body, 'password');
        const apiKey = match[1];

        dbUtils.getSession(req).readTransaction(txc => txc.run('MATCH (user:User {api_key: $api_key}) RETURN user', { api_key: apiKey }))
            .then(results => {
                if (_.isEmpty(results.records)) {
                    resp.status(401);
                    resp.json({ message: 'Token inválido', status: 401 });
                    next();
                }
                if (!name) {
                    resp.status(400);
                    resp.json({ message: 'O nome é obrigatório.', status: 400 });
                    next();
                }
                if (!age) {
                    resp.status(400);
                    resp.json({ message: 'A idade é obrigatório.', status: 400 });
                    next();
                }
                if (!phone) {
                    resp.status(400);
                    resp.json({ message: 'O celular é obrigatório.', status: 400 });
                    next();
                }
                if (!email) {
                    resp.status(400);
                    resp.json({ message: 'O email é obrigatório.', status: 400 });
                    next();
                }
                if (!password) {
                    resp.status(400);
                    resp.json({ message: 'A senha é obrigatótia.', status: 400 });
                    next();
                }
                dbUtils.getSession(req).writeTransaction(txc => txc.run('MATCH (user:User {api_key: $api_key}) SET user +={name: $name, age: $age, email: $email, phone: $phone, password: $password} RETURN user',
                    {
                        api_key: apiKey,
                        name: name,
                        age: age,
                        phone: phone,
                        email: email,
                        password: hashPassword(email, password),

                    }
                )).then(results => {
                    resp.status(200);
                    resp.json(new User(results.records[0].get('user')));
                    next();
                }
                )

            });
    })
}

//delete user  /users/
exports.deleteUser = function (req, resp, next) {
    loginRequired(req, resp, () => {
        const authHeader = req.headers['authorization'];
        const match = authHeader.match(/^Token (\S+)/);
        if (!match || !match[1]) {
            resp.status(401);
            resp.json({ message: 'Formato do token inválido. Follow `Token <token>`', status: 401 });
            next();
        }

        const apiKey = match[1];

        dbUtils.getSession(req).readTransaction(txc => txc.run('MATCH (user:User {api_key: $api_key}) RETURN user', { api_key: apiKey }))
            .then(results => {
                if (_.isEmpty(results.records)) {
                    resp.status(401);
                    resp.json({ message: 'invalid authorization key', status: 401 });
                    next();
                }
                else {
                    dbUtils.getSession(req).writeTransaction(txc => txc.run('MATCH (user: User {api_key: $api_key}) DETACH DELETE user',
                        { api_key: apiKey }
                    )).then(results => {
                        resp.status(200);
                        resp.json({ message: 'Usuário deletado com sucesso' });
                        next();
                    })
                }
            });

    })
}

function hashPassword(username, password) {
    const s = username + ':' + password;
    return crypto.createHash('sha256').update(s).digest('hex');
}