const mongo = require('mongoose');

const notification = mongo.Schema({
  author: { type: mongo.Types.ObjectId, ref: 'user' },
  from: { type: mongo.Types.ObjectId, ref: 'user' },
  text: String,
  friendRequest: Boolean,
  hidden: Boolean,
  date: Date,
  uuid: String
});

module.exports = mongo.model('notification', notification);