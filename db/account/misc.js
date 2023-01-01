const mongo = require('mongoose');

const user = mongo.Schema({
    uuid: String,
    tos: Array,
    reserved: Array,
    blocked: Array,
    hashtags: Array
});

module.exports = mongo.model('misc', user);