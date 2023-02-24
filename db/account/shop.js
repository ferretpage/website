const mongo = require('mongoose');

const shop = mongo.Schema({
    title: String,
    bio: String,
    amount: String,
    texture: String,
    id: String,
    purchases: [
        {
          user: {
            type: mongo.Types.ObjectId,
            ref: 'user'
          },
          uuid: String,
          date: Date
        }
    ],
    coupon: Array,
    hidden: Boolean,
    years: String,
    listingDate: Date,
    UpdateDate: Date,
    date: Date
});

module.exports = mongo.model('shop', shop);