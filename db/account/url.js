const mongo = require('mongoose');

const short_url = mongo.Schema({
  author: { type: mongo.Types.ObjectId, ref: 'user' },
  link: String,
  id: String,
  title: String,
  subtitle: String,
  thumbnail: String,
  thumbnail_pro_id: String,
  highlight: Boolean,
  limitClicks: Boolean,
  limitClick: String,
  clicks: Array,
  order: String,
  hidden: Boolean,
  blocked: Boolean,
  warn: Boolean,
  blocked_reason: String,
  date: Date,
  uuid: String
});

module.exports = mongo.model('short_url', short_url);