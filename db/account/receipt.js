const mongo = require('mongoose');

const receipt = new mongo.Schema({
    user: { type: mongo.Types.ObjectId, ref: 'user' },
    gift_from: { type: mongo.Types.ObjectId, ref: 'user' },
    receipt: String,
    pro: Boolean,
    pro_plus: Boolean,
    subdomain: Boolean,
    customdomain: Boolean,
    badge: Boolean,
    credit: Boolean,
    gift: Boolean,
    admin_gift: Boolean,
    amount: String,
    valid_until: Date,
    valid: Boolean,
    uuid: String,
    date: Date
});

module.exports = mongo.model('receipt', receipt);