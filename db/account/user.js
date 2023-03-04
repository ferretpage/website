const mongo = require('mongoose');

const user = mongo.Schema({
  email: String,
  name: String,
  displayName: String,
  uuid: String,
  signin_id: String,
  password: String,
  pfp: String,
  pfp_id: String,
  banner: String,
  banner_id: String,
  recEmail: String,
  session: String,
  apiKey: String,
  bio: String,
  google_backup: String,
  links: [
    {
      user: {
        type: mongo.Types.ObjectId,
        ref: 'user'
      },
      uuid: String,
      date: Date
    }
  ],
  socials: Object,
  connectedUser: [
    {
      user: {
        type: mongo.Types.ObjectId,
        ref: 'user'
      },
      uuid: String,
      date: Date
    }
  ],
  views: [
    {
      user: {
        type: mongo.Types.ObjectId,
        ref: 'user'
      },
      uuid: String,
      date: Date
    }
  ],
  linklimit: String,
  url: String,
  credit: String,
  location: String,
  theme: String,
  fonts: String,
  personal_border: String,
  nameHistory: Array,
  verified: Boolean,
  vrverified: Boolean,
  ogname: Boolean,
  blocked: Boolean,
  pro: Boolean,
  subdomain: Boolean,
  TFA: Boolean,
  pronouns: String,
  staff: Boolean,
  hidden: Boolean,
  whitelist: Boolean,
  memorialize: Boolean,
  showAvatarSquare: Boolean,
  showCreationDate: Boolean,
  reason: String,
  nameToFind: String,
  createdIP: String,
  createdAt: String,
  last_login: String
});

module.exports = mongo.model('user', user);