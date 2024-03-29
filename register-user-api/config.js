'use strict';

require('dotenv').config();

var nconf = require('nconf');

nconf.env(['PORT', 'NODE_ENV'])
    .argv({
        'e': {
            alias: 'NODE_ENV',
            describe: 'Set production or development mode.',
            demand: false,
            default: 'development'
        },
        'p': {
            alias: 'PORT',
            describe: 'Port to run on.',
            demand: false,
            default: process.env.PORT
        },
        'n': {
            alias: "neo4j",
            describe: "Use local or remote neo4j instance",
            demand: false,
            default: "local"
        }
    })
    .defaults({
        'USERNAME': process.env.DATABASE_USER,
        'PASSWORD': process.env.DATABASE_PASSWORD,
        'neo4j': 'local',
        'neo4j-local': process.env.DATABASE_URL,
        'base_url': 'http://localhost:5000',
        'api_path': '/api/v0'
    });

module.exports = nconf;