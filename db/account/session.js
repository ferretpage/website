const mongo = require('mongoose');

const session = mongo.Schema({
  uuid: String,
  sessions: Array,
  keys: Array
});

module.exports = mongo.model('sessions', session);