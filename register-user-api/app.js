require('dotenv').config();

const restify = require('restify');
const routes = require('./routes');
const nconf = require('./config');
const setAuthUser = require('./middlewares/setAuthUser');
const neo4jSessionCleanup = require('./middlewares/neo4jSessionCleanup');
const writeError = require("./helpers/response").writeError;

const corsMiddleware = require('restify-cors-middleware2')

const cors = corsMiddleware({
    preflightMaxAge: 5,
    origins: ['*'],
    allowHeaders: ['*'],
    exposeHeaders: ['*']
});

const server = restify.createServer();

server.pre(cors.preflight)
server.use(cors.actual)

server.use(restify.plugins.acceptParser(server.acceptable));
server.use(restify.plugins.queryParser());
server.use(restify.plugins.bodyParser());

server.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header('Access-Control-Allow-Credentials', true);
    res.header(
        "Access-Control-Allow-Methods",
        "GET,HEAD,OPTIONS,POST,PUT,DELETE"
    );
    res.header(
        "Access-Control-Allow-Headers",
        "Origin, X-Requested-With, Content-Type, Accept, Authorization"
    );
    return next();
});

server.use(setAuthUser);
server.use(neo4jSessionCleanup);

//routes
server.post('/register', routes.users.register);
server.post('/login', routes.users.login);
server.get('/users/me', routes.users.me);
server.put('/users/', routes.users.update);
server.del('/users/', routes.users.deleteUser);

server.use(function (err, req, res, next) {
    if (err && err.status) {
        writeError(res, err);
    } else next(err);
});

server.listen(nconf.get("PORT"), () => {

    console.log('%s listening at %s', server.name, server.url);

});
