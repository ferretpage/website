const a = require('express').Router();
const fetch = require('node-fetch');
let moment = require('moment-timezone');
let fs = require('fs');
let path = require('path');
const { verify, randomUUID } = require('crypto');
const cryptojs = require('crypto-js');
const qrcode = require('qrcode');
const twemoji = require('twemoji');
let nD = new Date();

function encrypt(g, s = process.env.SALT) {
    return cryptojs.AES.encrypt(g, s).toString();
}

function decrypt(g, s = process.env.SALT) {
    return cryptojs.AES.decrypt(g, s).toString(cryptojs.enc.Utf8);
}

const user = require('../db/account/user');
const sessions = require('../db/account/session');
const badge = require('../db/account/badge');
const tokens = require('../db/account/tokens');
const short_url = require('../db/account/url');
const notification = require('../db/account/notification');
const paste = require('../db/account/paste');
const misc = require('../db/account/misc');
const avatarCache = require('./api/avatarCache');
const bannerCache = require('./api/bannerCache');
const faviconCache = require('./api/faviconCache');
const authCode = require('./api/authCode');
const Jimp = require('jimp');
const receipt = require('../db/account/receipt');
const shop = require('../db/account/shop');

async function removeTOKENS() {
    await tokens.deleteMany({  });
};

function domain(d) {
    let ret = false;
    if (d.includes('.had.contact') || d.includes('.ferret.page') || d.includes('.localhost')) ret = true;

    return ret;
};

function time_ago(time) {
    switch (typeof time) {
      case 'number':
        break;
      case 'string':
        time = +new Date(time);
        break;
      case 'object':
        if (time.constructor === Date) time = time.getTime();
        break;
      default:
        time = +new Date();
    }
    var time_formats = [
        [60, 'seconds', 1], // 60
        [120, '1 minute ago', '1 minute from now'], // 60*2
        [3600, 'minutes', 60], // 60*60, 60
        [7200, '1 hour ago', '1 hour from now'], // 60*60*2
        [86400, 'hours', 3600], // 60*60*24, 60*60
        [172800, 'Yesterday', 'Tomorrow'], // 60*60*24*2
        [604800, 'days', 86400], // 60*60*24*7, 60*60*24
        [1209600, 'Last week', 'Next week'], // 60*60*24*7*4*2
        [2419200, 'weeks', 604800], // 60*60*24*7*4, 60*60*24*7
        [4838400, 'Last month', 'Next month'], // 60*60*24*7*4*2
        [29030400, 'months', 2419200], // 60*60*24*7*4*12, 60*60*24*7*4
        [58060800, 'Last year', 'Next year'], // 60*60*24*7*4*12*2
        [2903040000, 'years', 29030400], // 60*60*24*7*4*12*100, 60*60*24*7*4*12
        [5806080000, 'Last century', 'Next century'], // 60*60*24*7*4*12*100*2
        [58060800000, 'centuries', 2903040000] // 60*60*24*7*4*12*100*20, 60*60*24*7*4*12*100
    ];
    var seconds = (+new Date() - time) / 1000,
        token = 'ago',
        list_choice = 1;
    if (seconds == 0) {
        return 'Just now'
    }
    if (seconds < 0) {
        seconds = Math.abs(seconds);
        token = 'from now';
        list_choice = 2;
    }
    var i = 0,
        format;
    while (format = time_formats[i++])
        if (seconds < format[0]) {
          if (typeof format[2] == 'string')
            return format[list_choice];
          else
            return Math.floor(seconds / format[2]) + ' ' + format[1] + ' ' + token;
        }
    return time;
};

removeTOKENS();

a.get('/', async function (req, res) {
    let { session, theme } = req.cookies;
    let acc = null;
    var aDay = 0;

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    if (domain(req.hostname)) {
        let host = req.hostname.split('.')[0];
        let links = null;

        let v = await user.findOne({ nameToFind: host.toUpperCase(), hidden: false }).lean();

        if (!v) return res.render('error', { errorMessage: `Could not find page.`, theme: theme, acc, domain: `${req.protocol}://${req.hostname}`, last_active: null });
        if (v.hidden || v.blocked || !v.subdomain) return res.render('error', { errorMessage: `Could not find page.`, theme: theme, acc, domain: `${req.protocol}://${req.hostname}`, last_active: null });
        let badges = await badge.findOne({ "users.user": v._id, "users.disabled": false }).populate([{ path:"users.user", select: {displayName: 1, name: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();

        v.apiKey = decrypt(v.apiKey);
        v.bio = decrypt(v.bio);
        v.url = decrypt(v.url);
        v.location = decrypt(v.location);
        v.fonts = decrypt(v.fonts);
        if (v.pro && v.theme == "dark") theme = "dark";

        if (badges) badges = { badge: badges.badge, text: badges.text, info: badges.info, url: `/api/badge/${v.uuid}` };
        if (acc && !acc.blocked) {
            await user.updateOne({ uuid: v.uuid }, { $push: { views: [{ user: acc._id, uuid: randomUUID(), date: Date.now() }] } });
        };
        if (!acc) {
            await user.updateOne({ uuid: v.uuid }, { $push: { views: [{ user: null, uuid: randomUUID(), date: Date.now() }] } });
        };

        if (!links) {
            links = await short_url.find({ author: v._id, blocked: false }).populate([{ path:"author.user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();

            if (links && links.length > 0) {
                links.forEach((elm) => { elm.link = decrypt(elm.link); elm.title = decrypt(elm.title); elm.subtitle = decrypt(elm.subtitle); elm.thumbnail = decrypt(elm.thumbnail) });
            }
        }

        return res.render('account/profile', { theme: theme, acc, view: v, badge: badges, links, domain: `${req.protocol}://${req.hostname}`, last_active: time_ago(new Date(v.last_login - aDay)) });
    };

    let shortURL = await short_url.find({ }, { uuid: 1 }).lean();
    let userss = await user.find({ }, { uuid: 1, credit: 1 }).lean();
    let credits = 0;
    if (!shortURL) shortURL = [];
    if (!userss) userss = [];
    if (acc) credits = parseInt(acc.credit);

    res.render('home/index', { theme, acc, domain: `${req.protocol}://${req.hostname}`, length: { urls: shortURL.length, users: userss.length, credits: credits.toLocaleString('en-US') } });
});

a.get('/register', async function (req, res) {
    let { session, theme } = req.cookies;
    let acc = null;

    if (domain(req.hostname)) return res.redirect('/');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };
    
    if (req.query.code) res.cookie('reserve_code', req.query.code.toUpperCase());

    res.render('auth/register', { theme, acc, domain: `${req.protocol}://${req.hostname}` });
});

a.get('/signin', async function (req, res) {
    let { session, theme } = req.cookies;
    let acc = null;

    if (domain(req.hostname)) return res.redirect('/');
    
    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    let code = randomUUID();
    authCode[code] = code;
    res.render('auth/signin', { theme, acc, code, domain: `${req.protocol}://${req.hostname}` });
});

a.get('/signout', async function (req, res) {
    let { session } = req.cookies;
    if (!session) return res.redirect('/');

    let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
    if (!auth) return res.redirect('/');
    if (auth) auth = JSON.parse(decrypt(auth.account));

    let s = await sessions.findOne({ uuid: auth.uuid }).lean();
    if (!s) return res.redirect('/');

    let token = randomUUID();

    await sessions.updateOne({ uuid: auth.uuid }, { $push: { sessions: [{ token, date: Date.now(), ip: encrypt(req.headers['x-forwarded-for']), logout: true }] } });
    await user.updateOne({ uuid: auth.uuid }, { $set: { session: token } });

    res.clearCookie('session');
    res.redirect('/');
});

a.get('/reset-password', async function (req, res) {
    let { session, theme } = req.cookies;
    let acc = null;

    if (domain(req.hostname)) return res.redirect('/');
    
    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    let co = null;
    if (req.query.code && authCode[req.query.code]) co = authCode[req.query.code];
    if (req.query.code && !authCode[req.query.code]) return res.redirect('/reset-password');

    let code = randomUUID();
    authCode[code] = code;
    res.render('auth/reset-password', { theme, acc, code, domain: `${req.protocol}://${req.hostname}`, co });
});

a.get('/tos', async function (req, res) {
    let { session, theme } = req.cookies;
    let acc = null;

    if (domain(req.hostname)) return res.redirect('/');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    let l = await misc.findOne({ uuid: "0f018e78-7bfe-4230-8578-1da721487fb2" }).lean();
    if (l && !l.tos[0]) l = null;
    if (l && l.tos[0]) l = l.tos[0];

    res.render('home/tos', { theme, acc, date: l, domain: `${req.protocol}://${req.hostname}` });
});

a.get('/dashboard', async function (req, res) {
    let { session, theme } = req.cookies;
    let acc = null;
    let links = null;
    let aDay = 0;
    let code = null;

    if (domain(req.hostname)) return res.redirect('/');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}&links=1`)).json();
        if (auth && auth.status == 403) return res.redirect('/');
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account)); links = decrypt(auth.links);
    };

    if (!acc) return res.redirect('/');
    if (acc.status == 403) return res.redirect('/');
    if (acc.blocked) return res.redirect('/help/suspended-accounts');

    if (links) links = JSON.parse(links);
    if (req.query.code) code = req.query.code.toUpperCase();
    let qrl = `${req.protocol}://${req.hostname}/${acc.name}`;
    if (acc.subdomain) qrl = `${req.protocol}://${acc.name.toLowerCase()}.${req.hostname}`;

    let bdF = [];
    let bdA;
    let bd = await badge.find({ "users.user": acc._id }).lean();
    let login = await user.findOne({ uuid: acc.uuid }, { last_login: 1, uuid: 1 }).lean();
    if (!login) login = null;
    login = time_ago(new Date(login.last_login - aDay));

    if (bd) {
        for (let i = 0; i < bd.length; i++) {
            bd[i].users.forEach(elm => {
                if (elm.user == acc._id) bdF.push({ elm, badge: bd[i].badge, text: bd[i].text, info: bd[i].info, id: bd[i].id });
                if (elm.user == acc._id && !elm.disabled) bdA = { elm, badge: bd[i].badge, text: bd[i].text, info: bd[i].info, id: bd[i].id };
            });
        };
    };

    qrcode.toDataURL(qrl, function (err, url) {
        let qr = null;
        if (url) qr = url;

        res.render('account/dashboard', { theme, acc, links, qr, code, domain: `${req.protocol}://${req.hostname}`, badge: bdF, activeBadge: bdA, last_active: login });
    });
});

a.get('/settings', async function (req, res) {
    let { session, theme } = req.cookies;
    let acc = null;

    if (domain(req.hostname)) return res.redirect('/');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 403) return res.redirect('/');
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    if (!acc) return res.redirect('/');
    if (acc.status == 403) return res.redirect('/');
    if (acc.blocked) return res.redirect('/help/suspended-accounts');

    res.render('account/settings', { theme, acc, domain: `${req.protocol}://${req.hostname}` });
});

a.get('/settings/switch_account', async function (req, res) {
    let { session, theme } = req.cookies;
    let acc = null;

    if (domain(req.hostname)) return res.redirect('/');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 403) return res.redirect('/');
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    if (!acc) return res.redirect('/');
    if (acc.status == 403) return res.redirect('/');
    if (!acc.pro) return res.redirect('/');
    if (acc.blocked) return res.redirect('/help/suspended-accounts');

    res.render('account/switch', { theme, acc, domain: `${req.protocol}://${req.hostname}` });
});

a.get('/analytics', async function (req, res) {
    let { session, theme } = req.cookies;
    let acc = null;

    if (domain(req.hostname)) return res.redirect('/');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}&views=1`)).json();
        if (auth && auth.status == 403) return res.redirect('/');
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    if (!acc) return res.redirect('/');
    if (acc.status == 403) return res.redirect('/');
    if (!acc.verified) return res.redirect('/dashboard');
    if (acc.blocked) return res.redirect('/help/suspended-accounts');

    res.render('account/analytics', { theme, acc, domain: `${req.protocol}://${req.hostname}` });
});

a.get('/my/shop', async function (req, res) {
    let { session, theme, verified_session } = req.cookies;
    let acc = null;

    if (domain(req.hostname)) return res.redirect('/');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}&views=1`)).json();
        if (auth && auth.status == 403) return res.redirect('/');
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    if (!acc) return res.redirect('/');
    if (acc.status == 403) return res.redirect('/');
    if (!acc.verified) return res.redirect('/dashboard');
    if (acc.blocked) return res.redirect('/help/suspended-accounts');

    let isAdmin = false;
    let shopListing = null;
    let u = await user.findOne({ session }, { views: 0, connectedUsers: 0 }).lean();
    let SL = await shop.find({  }).lean();
    if (u && !u.blocked && u.staff && verified_session && authCode[verified_session]) isAdmin = true;
    if (SL && SL.length > 0) {
        shopListing = [];
        SL.forEach(elm => {
            shopListing.push({ title: decrypt(elm.title), bio: decrypt(elm.bio), amount: elm.amount, texture: decrypt(elm.texture), id: elm.id, hidden: elm.hidden, listingDate: elm.listingDate, UpdateDate: elm.UpdateDate, date: elm.date })
        });
    };

    res.render('shop/shop', { theme, acc, domain: `${req.protocol}://${req.hostname}`, staff: isAdmin, shopListing, error: null });
});

a.get('/my/purchases', async function (req, res) {
    let { session, theme } = req.cookies;
    let { redeem } = req.query;
    let acc = null;

    if (domain(req.hostname)) return res.redirect('/');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}&views=1`)).json();
        if (auth && auth.status == 403) return res.redirect('/');
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    if (!acc) return res.redirect('/');
    if (acc.status == 403) return res.redirect('/');
    if (!acc.verified) return res.redirect('/dashboard');
    if (acc.blocked) return res.redirect('/help/suspended-accounts');

    let u = await user.findOne({ session }, { views: 0, connectedUsers: 0 }).lean();
    let rec = await receipt.find({ user: u._id }).populate([{ path:"gift_from", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }, { path:"user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();
    let gifts = await receipt.find({ gift_from: u._id }).populate([{ path:"gift_from", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }, { path:"user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();
    let p = null;
    let t = null;
    let redeem_code = null;

    if (rec && rec.length > 0) p = rec;
    if (gifts && gifts.length > 0) t = gifts;
    if (redeem) redeem_code = redeem;

    res.render('account/purchases', { theme, acc, domain: `${req.protocol}://${req.hostname}`, p, t, redeem_code });
});

a.get('/:uuid/purchases', async function (req, res) {
    let { session, theme, verified_session } = req.cookies;
    let acc = null;

    if (domain(req.hostname)) return res.redirect('/');
    if (!verified_session) return res.redirect('/admin/panel');
    if (verified_session && !authCode[verified_session]) return res.redirect('/admin/panel');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}&views=1`)).json();
        if (auth && auth.status == 403) return res.redirect('/');
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    if (!acc) return res.redirect('/');
    if (acc.status == 403) return res.redirect('/');
    if (acc && !acc.staff) return res.redirect('/');
    if (acc.blocked) return res.redirect('/help/suspended-accounts');

    let u = await user.findOne({ uuid: req.params.uuid }, { views: 0, connectedUsers: 0 }).lean();
    let rec = await receipt.find({ user: u._id }).populate([{ path:"gift_from", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }, { path:"user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();
    let gifts = await receipt.find({ gift_from: u._id }).populate([{ path:"gift_from", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }, { path:"user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();
    let p = null;
    let t = null;

    if (rec && rec.length > 0) p = rec;
    if (gifts && gifts.length > 0) t = gifts;

    res.render('admin/purchases', { theme, acc, domain: `${req.protocol}://${req.hostname}`, u, p, t });
});

a.get('/purchase/confirm/:id', async function (req, res) {
    let { session, theme } = req.cookies;
    let acc = null;

    if (domain(req.hostname)) return res.redirect('/');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}&views=1`)).json();
        if (auth && auth.status == 403) return res.redirect('/');
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    if (!acc) return res.redirect('/');
    if (acc.status == 403) return res.redirect('/');
    if (!acc.verified) return res.redirect('/dashboard');
    if (acc.blocked) return res.redirect('/help/suspended-accounts');

    let token = Math.random().toString(32).substring(5).toUpperCase();
    let isAdmin = false;
    let shopListing = null;
    let u = await user.findOne({ session }, { views: 0, connectedUsers: 0 }).lean();
    let SL = await shop.findOne({ id: req.params.id }).lean();
    if (u && !u.blocked && u.staff) isAdmin = true;
    let SL2 = await shop.find({  }).lean();
    shopListing = [];
    SL2.forEach(elm => {
        shopListing.push({ title: decrypt(elm.title), bio: decrypt(elm.bio), amount: elm.amount, texture: decrypt(elm.texture), id: elm.id, hidden: elm.hidden, listingDate: elm.listingDate, UpdateDate: elm.UpdateDate, date: elm.date })
    });

    if (!SL) return res.render('shop/shop', { theme, acc, domain: `${req.protocol}://${req.hostname}`, staff: isAdmin, shopListing, error: `Unable to locate Listing` });
    if (parseInt(u.credit) < parseInt(SL.amount)) return res.render('shop/shop', { theme, acc, domain: `${req.protocol}://${req.hostname}`, staff: isAdmin, shopListing, error: `Insufficient Funds` });

    let yr = new Date().setFullYear(new Date().getFullYear()+1);
    let uuidv4 = randomUUID();
    if (SL.years && !isNaN(SL.years) && SL.years > 0 && SL.years < 251) yr = new Date().setFullYear(new Date().getFullYear()+parseInt(SL.years));

    if (SL.id == 'e9caa03c8ebb43ad836f620293fa605b') {
        let hasPurchase = false;
        SL.purchases.forEach(elm => {
            if (elm.user.toString() == u._id.toString()) hasPurchase = true;
        });

        if (hasPurchase) return res.render('shop/shop', { theme, acc, domain: `${req.protocol}://${req.hostname}`, staff: isAdmin, shopListing, error: `You already have this product` });

        token = `${token}-redeem_paw`;

        await shop.updateOne({ id: req.params.id }, { $push: { purchases: [{ user: u._id, uuid: uuidv4, date: Date.now() }] } });
        await user.updateOne({ session }, { $set: { credit: parseInt(u.credit)-parseInt(SL.amount) } });
        await badge.updateOne({ badge: token.split('-')[1] }, { $push: { users: { user: u._id, disabled: true, date: Date.now() } } });
        new receipt({
            user: u._id,
            receipt: token,
            pro: false,
            pro_plus: false,
            subdomain: false,
            customdomain: false,
            badge: true,
            credit: false,
            gift: false,
            admin_gift: true,
            gift_from: null,
            amount: SL.amount,
            valid_until: yr,
            valid: true,
            uuid: uuidv4,
            date: Date.now()
        }).save();
    };

    if (SL.id == '36c440e1e88944128a209730ec8edb4f') {
        let hasPurchase = false;
        SL.purchases.forEach(elm => {
            if (elm.user.toString() == u._id.toString() && new Date(elm.date).valueOf()+3.154e+10 > Date.now()) hasPurchase = true;
        });

        if (hasPurchase) return res.render('shop/shop', { theme, acc, domain: `${req.protocol}://${req.hostname}`, staff: isAdmin, shopListing, error: `You already have this product` });

        await shop.updateOne({ id: req.params.id }, { $push: { purchases: [{ user: u._id, uuid: uuidv4, date: Date.now() }] } });
        await user.updateOne({ session }, { $set: { credit: parseInt(u.credit)-parseInt(SL.amount) } });
        new receipt({
            user: u._id,
            receipt: token,
            pro: true,
            pro_plus: false,
            subdomain: false,
            customdomain: false,
            badge: false,
            credit: false,
            gift: false,
            admin_gift: true,
            gift_from: null,
            amount: SL.amount,
            valid_until: yr,
            valid: true,
            uuid: uuidv4,
            date: Date.now()
        }).save();
    };

    if (SL.id == '13ef5d57303a46bb8ed5453baa0238a8') {
        let hasPurchase = false;
        SL.purchases.forEach(elm => {
            if (elm.user.toString() == u._id.toString() && new Date(elm.date).valueOf()+3.154e+10 > Date.now()) hasPurchase = true;
        });

        if (hasPurchase) return res.render('shop/shop', { theme, acc, domain: `${req.protocol}://${req.hostname}`, staff: isAdmin, shopListing, error: `You already have this product` });

        await shop.updateOne({ id: req.params.id }, { $push: { purchases: [{ user: u._id, uuid: uuidv4, date: Date.now() }] } });
        await user.updateOne({ session }, { $set: { credit: parseInt(u.credit)-parseInt(SL.amount) } });
        new receipt({
            user: u._id,
            receipt: token,
            pro: false,
            pro_plus: false,
            subdomain: true,
            customdomain: false,
            badge: false,
            credit: false,
            gift: false,
            admin_gift: true,
            gift_from: null,
            amount: SL.amount,
            valid_until: yr,
            valid: true,
            uuid: uuidv4,
            date: Date.now()
        }).save();
    };

    res.redirect('/my/purchases');
});

a.get('/admin/panel', async function (req, res) {
    let { session, theme, verified_session } = req.cookies;
    let acc = null;

    if (domain(req.hostname)) return res.redirect('/');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 403) return res.redirect('/');
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    if (!acc) return res.redirect('/');
    if (acc.status == 403) return res.redirect('/');
    if (acc.blocked) return res.redirect('/help/suspended-accounts');
    if (!acc.staff) return res.redirect('/');

    let u = await user.find({  }).lean();
    let users = [];
    let isVerified = false;

    if (verified_session && authCode[verified_session]) isVerified = true;

    u.forEach(elm => {
        elm.email = decrypt(elm.email);
        elm.bio = decrypt(elm.bio);
        elm.createdIP = decrypt(elm.createdIP);
        users.push(elm);
    });

    users.sort((a, b) => { return b.date - a.date });

    res.render('admin/panel', { theme, acc, users, domain: `${req.protocol}://${req.hostname}`, isVerified });
});

a.get('/help', async function (req, res) {
    let { session, theme } = req.cookies;
    let acc = null;

    if (domain(req.hostname)) return res.redirect('https://had.contact/help');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    let article = [];
    fs.readdirSync(path.join(__dirname, `../views/help`)).forEach(file => {
        article.push(file.split('.')[0]);
    });;

    res.render(`home/help`, { theme, acc, article, domain: `${req.protocol}://${req.hostname}` });
});

a.get('/help/:id', async function (req, res) {
    let { session, theme } = req.cookies;
    let acc = null;

    if (domain(req.hostname)) return res.redirect(`https://had.contact/help/${req.params.id.toLowerCase()}`);

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    if (!fs.existsSync(path.join(__dirname, `../views/help/${req.params.id.toLowerCase()}.ejs`))) return res.render('error', { errorMessage: `This article does not exist.`, theme: theme, acc, domain: `${req.protocol}://${req.hostname}` });
    res.render(`help/${req.params.id.toLowerCase()}`, { theme, acc, domain: `${req.protocol}://${req.hostname}` });
});

a.get('/l/:uuid', async function (req, res) {
    let s = await user.findOne({ session: req.cookies.session }).lean();
    let urls = await short_url.findOne({ id: req.params.uuid, blocked: false }).populate([{ path:"author", select: {displayName: 1, name: 1, pfp: 1, uuid: 1, hcverified: 1, hidden: 1} }]).lean();
    if (!urls) return res.redirect('/');
    
    let data = urls;
    let loggedin;
    if (s && !s.blocked) loggedin = s._id;

    if (data && data.author) {
        await short_url.updateOne({ id: req.params.uuid }, { $push: { clicks: [{ user: loggedin, ip: encrypt(req.headers['x-forwarded-for']), uuid: randomUUID(), date: Date.now() }] } });

        if (data.limitClicks && data.clicks.length+1 > data.limitClick) {
            return res.redirect(`/${data.author.name.toLowerCase()}`);
        };
    };

    if (urls.warn) return res.redirect(`/warning?id=${req.params.uuid}`);
    res.redirect(decrypt(data.link));
    // res.json({ OK: true, status: 200, return: decrypt(data.link), uuid: data.uuid });
});

a.get('/warning', async function (req, res) {
    let { session, theme } = req.cookies;
    let acc = null;

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    let urls = await short_url.findOne({ id: req.query.id, blocked: false }).populate([{ path:"author", select: {displayName: 1, name: 1, pfp: 1, uuid: 1, hcverified: 1, hidden: 1} }]).lean();
    if (!urls) return res.redirect('/');

    res.render('warning_link', { theme: theme, acc, url: `${req.protocol}://${req.hostname}/l/${urls.id}`, forward_url: decrypt(urls.link), domain: `${req.protocol}://${req.hostname}` });
});

a.get('/avatar/:uuid.:ext', async function (req, res) {
    if (avatarCache[req.params.uuid]) {
        let image = Buffer.from(avatarCache[req.params.uuid].split(',')[1], 'base64');
        if (req.params.ext && req.params.ext !== avatarCache[req.params.uuid].split('data:')[1].split(';')[0].split('/')[1]) return res.sendStatus(404)
        res.writeHead(200, {
            'Content-Type': avatarCache[req.params.uuid].split('data:')[1].split(';')[0],
            'Content-Length': image.length
        });
        return res.end(image);
    };
    let u = await user.findOne({ uuid: req.params.uuid }).lean();
    if (!u) return res.sendStatus(404);
    if (u && u.blocked) return res.sendStatus(404);

    let pfp = await (await fetch(u.pfp));
    let buffer = await pfp.arrayBuffer();

    data = "data:" + pfp.headers.get('content-type') + ";base64," + Buffer.from(buffer).toString('base64');
    avatarCache[req.params.uuid] = data;

    if (req.params.ext && req.params.ext !== pfp.headers.get('content-type').split('/')[1]) return res.sendStatus(404);

    res.writeHead(200, {
        'Content-Type': pfp.headers.get('content-type'),
        'Content-Length': pfp.headers.get('content-length')
    });
    res.end(Buffer.from(buffer, 'base64'));
});

a.get('/avatar/:uuid', async function (req, res) {
    if (avatarCache[req.params.uuid]) {
        let image = Buffer.from(avatarCache[req.params.uuid].split(',')[1], 'base64');
        res.writeHead(200, {
            'Content-Type': avatarCache[req.params.uuid].split('data:')[1].split(';')[0],
            'Content-Length': image.length
        });
        return res.end(image);
    };
    let u = await user.findOne({ uuid: req.params.uuid }).lean();
    if (!u) return res.sendStatus(404);
    if (u && u.blocked) return res.sendStatus(404);

    let pfp = await (await fetch(u.pfp));
    let buffer = await pfp.arrayBuffer();

    data = "data:" + pfp.headers.get('content-type') + ";base64," + Buffer.from(buffer).toString('base64');
    avatarCache[req.params.uuid] = data;

    res.writeHead(200, {
        'Content-Type': pfp.headers.get('content-type'),
        'Content-Length': pfp.headers.get('content-length')
    });
    res.end(Buffer.from(buffer, 'base64'));
});

a.get('/banner/:uuid.:ext', async function (req, res) {
    if (bannerCache[req.params.uuid]) {
        let image = Buffer.from(bannerCache[req.params.uuid].split(',')[1], 'base64');
        if (req.params.ext && req.params.ext !== bannerCache[req.params.uuid].split('data:')[1].split(';')[0].split('/')[1]) return res.sendStatus(404)
        res.writeHead(200, {
            'Content-Type': bannerCache[req.params.uuid].split('data:')[1].split(';')[0],
            'Content-Length': image.length
        });
        return res.end(image);
    };
    let u = await user.findOne({ uuid: req.params.uuid }).lean();
    if (!u) return res.sendStatus(404);
    if (u && u.blocked) return res.sendStatus(404);
    if (u.banner == "") return res.sendStatus(404);

    let banner = await (await fetch(u.banner));
    let buffer = await banner.arrayBuffer();

    data = "data:" + banner.headers.get('content-type') + ";base64," + Buffer.from(buffer).toString('base64');
    bannerCache[req.params.uuid] = data;

    if (req.params.ext && req.params.ext !== banner.headers.get('content-type').split('/')[1]) return res.sendStatus(404);

    res.writeHead(200, {
        'Content-Type': banner.headers.get('content-type'),
        'Content-Length': banner.headers.get('content-length')
    });
    res.end(Buffer.from(buffer, 'base64'));
});

a.get('/banner/:uuid', async function (req, res) {
    if (bannerCache[req.params.uuid]) {
        let image = Buffer.from(bannerCache[req.params.uuid].split(',')[1], 'base64');
        res.writeHead(200, {
            'Content-Type': bannerCache[req.params.uuid].split('data:')[1].split(';')[0],
            'Content-Length': image.length
        });
        return res.end(image);
    };
    let u = await user.findOne({ uuid: req.params.uuid }).lean();
    if (!u) return res.sendStatus(404);
    if (u && u.blocked) return res.sendStatus(404);
    if (u.banner == "") return res.sendStatus(404);

    let banner = await (await fetch(u.banner));
    let buffer = await banner.arrayBuffer();

    data = "data:" + banner.headers.get('content-type') + ";base64," + Buffer.from(buffer).toString('base64');
    bannerCache[req.params.uuid] = data;

    res.writeHead(200, {
        'Content-Type': banner.headers.get('content-type'),
        'Content-Length': banner.headers.get('content-length')
    });
    res.end(Buffer.from(buffer, 'base64'));
});

a.get('/favicon/:id.:ext', async function (req, res) {
    if (faviconCache[req.params.id]) {
        let image = Buffer.from(faviconCache[req.params.id].split(',')[1], 'base64');
        if (req.params.ext && req.params.ext !== faviconCache[req.params.id].split('data:')[1].split(';')[0].split('/')[1]) return res.sendStatus(404)
        res.writeHead(200, {
            'Content-Type': faviconCache[req.params.id].split('data:')[1].split(';')[0],
            'Content-Length': image.length
        });
        return res.end(image);
    };
    let u = await short_url.findOne({ id: req.params.id }).lean();
    if (!u) return res.sendStatus(404);
    if (u && u.blocked) return res.sendStatus(404);
    if (u.thumbnail == "") return res.sendStatus(404);

    let icon = await (await fetch(decrypt(u.thumbnail)));
    if (icon.status == 404) icon = await (await fetch('https://t1.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://had.contact&size=128'));
    let image;
    let buffer;
    if (!icon.headers.get('content-type').includes('gif')) {
        image = await Jimp.read(icon.url);
        image.resize(128, 128, Jimp.RESIZE_NEAREST_NEIGHBOR);
        buffer = await image.getBufferAsync(icon.headers.get('content-type'));
    };
    if (icon.headers.get('content-type').includes('gif')) {
        image = await (await fetch(icon.url));
        buffer = await image.arrayBuffer();
    };

    if (req.params.ext && req.params.ext !== icon.headers.get('content-type').split('/')[1]) return res.sendStatus(404)

    data = "data:" + icon.headers.get('content-type') + ";base64," + Buffer.from(buffer).toString('base64');
    faviconCache[req.params.id] = data;

    res.writeHead(200, {
        'Content-Type': icon.headers.get('content-type'),
        'Content-Length': icon.headers.get('content-length')
    });
    res.end(Buffer.from(buffer, 'base64'));
});

a.get('/favicon/:id', async function (req, res) {
    if (faviconCache[req.params.id]) {
        let image = Buffer.from(faviconCache[req.params.id].split(',')[1], 'base64');
        res.writeHead(200, {
            'Content-Type': faviconCache[req.params.id].split('data:')[1].split(';')[0],
            'Content-Length': image.length
        });
        return res.end(image);
    };
    let u = await short_url.findOne({ id: req.params.id }).lean();
    if (!u) return res.sendStatus(404);
    if (u && u.blocked) return res.sendStatus(404);
    if (u.thumbnail == "") return res.sendStatus(404);

    let icon = await (await fetch(decrypt(u.thumbnail)));
    if (icon.status == 404) icon = await (await fetch('https://t1.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://had.contact&size=128'));
    let image;
    let buffer;
    if (!icon.headers.get('content-type').includes('gif')) {
        image = await Jimp.read(icon.url);
        image.resize(128, 128, Jimp.RESIZE_NEAREST_NEIGHBOR);
        buffer = await image.getBufferAsync(icon.headers.get('content-type'));
    };
    if (icon.headers.get('content-type').includes('gif')) {
        image = await (await fetch(icon.url));
        buffer = await image.arrayBuffer();
    };

    data = "data:" + icon.headers.get('content-type') + ";base64," + Buffer.from(buffer).toString('base64');
    faviconCache[req.params.id] = data;

    res.writeHead(200, {
        'Content-Type': icon.headers.get('content-type'),
        'Content-Length': icon.headers.get('content-length')
    });
    if (icon.headers.get('content-type').includes('gif')) return res.end(Buffer.from(buffer, 'base64'));
    res.end(buffer, 'binary');
});

a.get('/shop/:id.:ext', async function (req, res) {
    if (faviconCache[req.params.id]) {
        let image = Buffer.from(faviconCache[req.params.id].split(',')[1], 'base64');
        if (req.params.ext && req.params.ext !== faviconCache[req.params.id].split('data:')[1].split(';')[0].split('/')[1]) return res.sendStatus(404);
        res.writeHead(200, {
            'Content-Type': faviconCache[req.params.id].split('data:')[1].split(';')[0],
            'Content-Length': image.length
        });
        return res.end(image);
    };
    let u = await shop.findOne({ id: req.params.id }).lean();
    if (!u) return res.sendStatus(404);
    if (u && u.blocked) return res.sendStatus(404);
    if (u.texture == "") return res.sendStatus(404);

    let icon = await (await fetch(decrypt(u.texture)));
    if (icon.status == 404) icon = await (await fetch('https://t1.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://had.contact&size=128'));
    let buffer = await icon.arrayBuffer();

    if (req.params.ext && req.params.ext !== icon.headers.get('content-type').split('/')[1]) return res.sendStatus(404);

    data = "data:" + icon.headers.get('content-type') + ";base64," + Buffer.from(buffer).toString('base64');
    faviconCache[req.params.id] = data;

    res.writeHead(200, {
        'Content-Type': icon.headers.get('content-type'),
        'Content-Length': icon.headers.get('content-length')
    });
    res.end(Buffer.from(buffer, 'base64'));
});

a.get('/shop/:id', async function (req, res) {
    if (faviconCache[req.params.id]) {
        let image = Buffer.from(faviconCache[req.params.id].split(',')[1], 'base64');
        res.writeHead(200, {
            'Content-Type': faviconCache[req.params.id].split('data:')[1].split(';')[0],
            'Content-Length': image.length
        });
        return res.end(image);
    };
    let u = await shop.findOne({ id: req.params.id }).lean();
    if (!u) return res.sendStatus(404);
    if (u && u.blocked) return res.sendStatus(404);
    if (u.texture == "") return res.sendStatus(404);

    let icon = await (await fetch(decrypt(u.texture)));
    if (icon.status == 404) icon = await (await fetch('https://t1.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://had.contact&size=128'));
    let buffer = await icon.arrayBuffer();

    data = "data:" + icon.headers.get('content-type') + ";base64," + Buffer.from(buffer).toString('base64');
    faviconCache[req.params.id] = data;

    res.writeHead(200, {
        'Content-Type': icon.headers.get('content-type'),
        'Content-Length': icon.headers.get('content-length')
    });
    res.end(Buffer.from(buffer, 'base64'));
});

a.get('/badge/:uid', async function (req, res) {
    badge.findOne({ "users.user": req.params.uid, "users.disabled": false }, async function (e, r) {
        if (!r) return res.sendStatus(404);
        let user = null;
        r.users.forEach(function (u) { if (u.uid == req.params.uid) user = u; });
        if (user && user.disabled) return res.sendStatus(404);
        let par = twemoji.convert.toCodePoint(r.badge);
        try {
            let data = path.join(__dirname + "../../public/i/emoji/" + par + ".svg");
            if (!fs.lstatSync(data).isFile()) {
                data = path.join(__dirname + "../../public/i/assets/" + par + ".gif");
            };
            res.sendFile(data);
        } catch (e) {
            if (e.code !== "ENOENT") console.log(e);
            if (e.code == "ENOENT" && e.syscall == "lstat") { data = path.join(__dirname + "../../public/i/assets/" + par + ".gif"); return res.sendFile(data); }
            res.sendStatus(500);
        };
    }).populate([{ path:"users.user", select: {displayName: 1, name: 1, pfp: 1, uuid: 1, hcverified: 1, hidden: 1} }]);
});

a.get('/:user', async function (req, res) {
    let { session } = req.cookies;
    let acc = null;
    let links = null;
    var aDay = 0;
    let theme = "";

    if (domain(req.hostname)) return res.redirect('/');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 403) return res.redirect('/');
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };
    if (acc && acc.blocked) return res.redirect('/help/suspended-accounts');
    let accID = null;
    let v = await user.findOne({ nameToFind: req.params.user.toUpperCase(), hidden: false }).lean();

    if (!v) return res.render('error', { errorMessage: `Could not find page.`, theme: theme, acc, domain: `${req.protocol}://${req.hostname}`, last_active: null });
    if (v.hidden || v.blocked) return res.render('error', { errorMessage: `Could not find page.`, theme: theme, acc, domain: `${req.protocol}://${req.hostname}`, last_active: null });
    let badges = await badge.findOne({ "users.user": v._id, "users.disabled": false }).populate([{ path:"users.user", select: {displayName: 1, name: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();

    v.apiKey = decrypt(v.apiKey);
    v.bio = decrypt(v.bio);
    v.url = decrypt(v.url);
    v.location = decrypt(v.location);
    v.fonts = decrypt(v.fonts);
    if (v.pro && v.theme == "dark") theme = "dark";
    if (acc && !acc.blocked) accID = acc._id;

    if (badges) badges = { badge: badges.badge, text: badges.text, info: badges.info, url: `/api/badge/${v.uuid}` };
    await user.updateOne({ uuid: v.uuid }, { $push: { views: [{ user: accID, uuid: randomUUID(), date: Date.now() }] } });

    if (!links) {
        links = await short_url.find({ author: v._id, blocked: false }).populate([{ path:"author.user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();

        if (links && links.length > 0) {
            links.forEach((elm) => { elm.link = decrypt(elm.link); elm.title = decrypt(elm.title); elm.subtitle = decrypt(elm.subtitle); elm.thumbnail = decrypt(elm.thumbnail) });
        }
    };

    res.render('account/profile', { theme: theme, acc, view: v, badge: badges, links, domain: `${req.protocol}://${req.hostname}`, last_active: time_ago(new Date(v.last_login - aDay)) });
});

a.get('/:uuid/edit', async function (req, res) {
    let { session, verified_session } = req.cookies;
    let acc = null;
    let links = null;
    var aDay = 0
    let theme = "";

    if (domain(req.hostname)) return res.redirect('/');

    if (!verified_session) return res.redirect('/admin/panel');
    if (verified_session && !authCode[verified_session]) return res.redirect('/admin/panel');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 403) return res.redirect('/');
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };
    if (acc && acc.blocked) return res.redirect('/help/suspended-accounts');
    if (!acc) return res.redirect('/');
    if (acc && !acc.staff) return res.redirect('/');
    let v = await user.findOne({ uuid: req.params.uuid }).populate([{ path:"connectedUser.user", select: {displayName: 1, name: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();

    if (!v) return res.render('error', { errorMessage: `Could not find page.`, theme: theme, acc, last_active: null });
    let badges = await badge.findOne({ "users.user": v._id, "users.disabled": false }).populate([{ path:"users.user", select: {displayName: 1, name: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();

    v.apiKey = decrypt(v.apiKey);
    v.bio = decrypt(v.bio);
    v.url = decrypt(v.url);
    v.location = decrypt(v.location);

    if (badges) badges = { badge: badges.badge, text: badges.text, info: badges.info, url: `/api/badge/${v.uuid}` };

    if (!links) {
        links = await short_url.find({ author: v._id, blocked: false }).populate([{ path:"author.user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();

        if (links && links.length > 0) {
            links.forEach((elm) => { elm.link = decrypt(elm.link); elm.title = decrypt(elm.title); elm.subtitle = decrypt(elm.subtitle); elm.thumbnail = decrypt(elm.thumbnail) });
        }
    }

    res.render('admin/edit', { theme: theme, acc, view: v, badge: badges, links, domain: `${req.protocol}://${req.hostname}`, last_active: time_ago(new Date(v.last_login - aDay)) });
});

module.exports = a;