const mongo = require('mongoose');

const token = new mongo.Schema({
    token: String,
    user: String,
    valid: Boolean,
    uuid: String,
    date: Date
});

module.exports = mongo.model('token', token);