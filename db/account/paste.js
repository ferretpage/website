const mongo = require('mongoose');

const paste = new mongo.Schema({
    auth: Boolean,
    title: String,
    text: String,
    user: {
        type: mongo.Types.ObjectId,
        ref: 'user'
    },
    ID: String,
    date: Date,
    hidden: Boolean,
    blacklisted: Boolean,
    blacklisted_reason: String
});

module.exports = mongo.model('paste', paste);