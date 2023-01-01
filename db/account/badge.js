const mongo = require('mongoose');

const badge = new mongo.Schema({
    badge: String,
    text: String,
    info: String,
    textToFind: String,
    users: [
        {
            user: {
                type: mongo.Types.ObjectId,
                ref: 'user'
            },
            disabled: Boolean,
            date: Date
        }
    ],
    id: String,
    date: Date
});

module.exports = mongo.model('badge', badge);