const mongo = require('mongoose');

const ve = mongo.Schema({
  uuid: String,
  email: String,
  token: String,
  used: Boolean,
  valid: Boolean,
  date: String
});

module.exports = mongo.model('verify_email', ve);