const a = require('express').Router();
const fetch = require('node-fetch');
let moment = require('moment-timezone');
let fs = require('fs');
let path = require('path');
const { verify, randomUUID } = require('crypto');
const cryptojs = require('crypto-js');
const qrcode = require('qrcode');
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

async function removeTOKENS() {
    await tokens.deleteMany({  });
};

function domain(d) {
    let ret = false;
    if (d.includes('.had.contact') || d.includes('.ferret.page') || d.includes('.localhost')) ret = true;

    return ret;
};

removeTOKENS();

a.get('/', async function (req, res) {
    let { session, theme } = req.cookies;
    let acc = null;

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };

    if (domain(req.hostname)) {
        let host = req.hostname.split('.')[0];
        let links = null;

        let v = await user.findOne({ nameToFind: host.toUpperCase(), hidden: false }).lean();

        if (!v) return res.render('error', { errorMessage: `Could not find page.`, theme: theme, acc, domain: `${req.protocol}://${req.hostname}` });
        if (v.hidden || v.blocked || !v.subdomain) return res.render('error', { errorMessage: `Could not find page.`, theme: theme, acc, domain: `${req.protocol}://${req.hostname}` });
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

        return res.render('account/profile', { theme: theme, acc, view: v, badge: badges, links, domain: `${req.protocol}://${req.hostname}` });
    }

    res.render('home/index', { theme, acc, domain: `${req.protocol}://${req.hostname}` });
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

    await sessions.updateOne({ uuid: auth.uuid }, { $push: { sessions: [{ token, date: Date.now(), ip: req.headers['x-forwarded-for'], logout: true }] } });
    await user.updateOne({ uuid: auth.uuid }, { $set: { session: token } });

    res.clearCookie('session');
    res.redirect('/');
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

    qrcode.toDataURL(qrl, function (err, url) {
        let qr = null;
        if (url) qr = url;

        res.render('account/dashboard', { theme, acc, links, qr, code, domain: `${req.protocol}://${req.hostname}` });
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
    if (acc.blocked) return res.redirect('/help/suspended-accounts');

    res.render('account/analytics', { theme, acc, domain: `${req.protocol}://${req.hostname}` });
});

a.get('/my/purchases', async function (req, res) {
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
    if (acc.blocked) return res.redirect('/help/suspended-accounts');

    let u = await user.findOne({ session }, { views: 0, connectedUsers: 0 }).lean();
    let rec = await receipt.find({ user: u._id }).populate([{ path:"gift_from", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();
    let gifts = await receipt.find({ gift_from: u._id }).populate([{ path:"gift_from", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();
    let p = null;
    let t = null;

    if (rec && rec.length > 0) p = rec;
    if (gifts && gifts.length > 0) t = gifts;

    res.render('account/purchases', { theme, acc, domain: `${req.protocol}://${req.hostname}`, p, t });
});

a.get('/admin/panel', async function (req, res) {
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
    if (!acc.staff) return res.redirect('/');

    let u = await user.find({  }).lean();
    let users = [];

    u.forEach(elm => {
        elm.email = decrypt(elm.email);
        elm.bio = decrypt(elm.bio);
        elm.createdIP = decrypt(elm.createdIP);
        users.push(elm);
    });

    users.sort((a, b) => { return b.date - a.date });

    res.render('admin/panel', { theme, acc, users, domain: `${req.protocol}://${req.hostname}` });
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
    let image = await Jimp.read(icon.url);
    image.resize(128, 128, Jimp.RESIZE_NEAREST_NEIGHBOR);
    let buffer = await image.getBufferAsync(icon.headers.get('content-type'));

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
    let image = await Jimp.read(icon.url);
    image.resize(128, 128, Jimp.RESIZE_NEAREST_NEIGHBOR);
    let buffer = await image.getBufferAsync(icon.headers.get('content-type'));

    data = "data:" + icon.headers.get('content-type') + ";base64," + Buffer.from(buffer).toString('base64');
    faviconCache[req.params.id] = data;

    res.writeHead(200, {
        'Content-Type': icon.headers.get('content-type'),
        'Content-Length': icon.headers.get('content-length')
    });
    res.end(buffer, 'binary');
});

a.get('/:user', async function (req, res) {
    let { session } = req.cookies;
    let acc = null;
    let links = null;
    let theme = "";

    if (domain(req.hostname)) return res.redirect('/');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 403) return res.redirect('/');
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };
    if (acc && acc.blocked) return res.redirect('/help/suspended-accounts');
    let v = await user.findOne({ nameToFind: req.params.user.toUpperCase(), hidden: false }).lean();

    if (!v) return res.render('error', { errorMessage: `Could not find page.`, theme: theme, acc, domain: `${req.protocol}://${req.hostname}` });
    if (v.hidden || v.blocked) return res.render('error', { errorMessage: `Could not find page.`, theme: theme, acc, domain: `${req.protocol}://${req.hostname}` });
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

    res.render('account/profile', { theme: theme, acc, view: v, badge: badges, links, domain: `${req.protocol}://${req.hostname}` });
});

a.get('/:uuid/edit', async function (req, res) {
    let { session } = req.cookies;
    let acc = null;
    let links = null;
    let theme = "";

    if (domain(req.hostname)) return res.redirect('/');

    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 403) return res.redirect('/');
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };
    if (acc && acc.blocked) return res.redirect('/help/suspended-accounts');
    if (!acc) return res.redirect('/');
    if (acc && !acc.staff) return res.redirect('/');
    let v = await user.findOne({ uuid: req.params.uuid }).populate([{ path:"connectedUser.user", select: {displayName: 1, name: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();

    if (!v) return res.render('error', { errorMessage: `Could not find page.`, theme: theme, acc });
    let badges = await badge.findOne({ "users.user": v._id, "users.disabled": false }).populate([{ path:"users.user", select: {displayName: 1, name: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();

    v.apiKey = decrypt(v.apiKey);
    v.bio = decrypt(v.bio);
    v.url = decrypt(v.url);
    v.location = decrypt(v.location);

    if (badges) badges = { badge: badges.badge, text: badges.text, info: badges.info, url: `/api/badge/${v.uuid}` };
    if (acc && !acc.blocked) {
        await user.updateOne({ uuid: v.uuid }, { $push: { views: [{ user: acc._id, uuid: randomUUID(), date: Date.now() }] } });
    }

    if (!links) {
        links = await short_url.find({ author: v._id, blocked: false }).populate([{ path:"author.user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();

        if (links && links.length > 0) {
            links.forEach((elm) => { elm.link = decrypt(elm.link); elm.title = decrypt(elm.title); elm.subtitle = decrypt(elm.subtitle); elm.thumbnail = decrypt(elm.thumbnail) });
        }
    }

    res.render('admin/edit', { theme: theme, acc, view: v, badge: badges, links, domain: `${req.protocol}://${req.hostname}` });
});

module.exports = a;