const a = require('express').Router();
const { randomUUID, createHmac } = require('crypto');
const cryptojs = require('crypto-js');
const multer = require('multer');
const nodemailer = require('nodemailer');
const fetch = require('node-fetch');
const QRCode = require('qrcode');
const authenticator = require('authenticator');
const twemoji = require('twemoji');
const path = require('path');
const fs = require('fs');
const sharp = require('sharp');
const B2 = require('backblaze-b2');

const user = require('../../db/account/user');
const sessions = require('../../db/account/session');
const verify_email = require('../../db/account/verify_email');
const dbMisc = require('../../db/account/misc');
const badge = require('../../db/account/badge');
const tokens = require('../../db/account/tokens');
const misc = require('../../db/account/misc');
const short_url = require('../../db/account/url');
const notification = require('../../db/account/notification');
const paste = require('../../db/account/paste');
const avatarCache = require('../api/avatarCache');
const bannerCache = require('../api/bannerCache');
const faviconCache = require('../api/faviconCache');
const authCode = require('../api/authCode');
const receipt = require('../../db/account/receipt');

const b2 = new B2({
    applicationKeyId: process.env.C_API_KEYID,
    applicationKey: process.env.C_API_KEY,
    retry: {
        retries: 3
    }
});

async function GetBucket() {
    try {
        await b2.authorize(); // must authorize first (authorization lasts 24 hrs)
        let response = await b2.getBucket({ bucketName: 'ferrets' });
        // console.log(response.data);
    } catch (err) {
      console.log('Error getting bucket:', err);
    }
};

const Filter = function (req, file, cb) {
    // Accept images only
    if (!file.originalname.match(/\.(jpg|JPG|jpeg|JPEG|png|PNG|gif|GIF)$/)) {
        req.fileValidationError = 'Only image files are allowed!';
        return cb(new Error('Only image files are allowed!'), false);
    }
    cb(null, true);
};

const Filter2 = function (req, file, cb) {
    // Accept images only
    if (!file.originalname.match(/\.(jpg|JPG|jpeg|JPEG|png|PNG|gif|GIF|mp4|MP4)$/)) {
        req.fileValidationError = 'Only image files are allowed!';
        return cb(new Error('Only image files are allowed!'), false);
    }
    cb(null, true);
};

const upload = multer({ limits: { fileSize: 1920 * 1080 * 5 }, fileFilter: Filter });
const upload2 = multer({ limits: { fileSize: 1280 * 720 * 5 }, fileFilter: Filter });

function salt(g, s) {
    const hash = createHmac('sha256', s).update(g).digest('hex');

    return hash
};

function encrypt(g, s = process.env.SALT) {
    return cryptojs.AES.encrypt(g, s).toString();
}

function decrypt(g, s = process.env.SALT) {
    return cryptojs.AES.decrypt(g, s).toString(cryptojs.enc.Utf8);
}

async function auth(session, staff) {
    let a = await (await fetch(session)).json();
    let contine = true;
    let error = null;
    if (a.OK && a.account) a = JSON.parse(decrypt(a.account));
    if (a.status) a = null;
    
    if (!a) { error = `You must be logged in`; }
    if (a && !a.verified) { error = `Account is not verified`; }
    if (a && a.blocked) { error = `Account is either blocked or muted and cannot access this endpoint`; }

    if (a && !a.staff && staff) error = `This is a staff endpoint`;
    if (error) contine = false;

    return { OK: contine, error };
};
// console.log(twemoji.convert.toCodePoint(""));

a.get('/v1/auth', async function (req, res) {
    let { session } = req.cookies;
    if (!session) session = req.query.session;

    if (!session) return res.status(403).json({ OK: false, status: 403, error: `Invalid authentication` });
    let s = await user.findOne({ session }, { password: 0, createdIP: 0, last_login: 0, __v: 0, recEmail: 0 }).populate([{ path:"connectedUser.user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();

    if (!s) return res.status(403).json({ OK: false, status: 403, error: `Invalid authentication` });
    // if (s.blocked) return res.status(403).json({ OK: false, status: 403, error: `User is blocked` });

    let links = await short_url.find({ author: s._id, blocked: false }).populate([{ path:"author.user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();
    let rec = await receipt.find({ user: s._id, valid: true }).populate([{ path:"author.user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }, { path:"gift_from.user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, vrverified: 1, hidden: 1} }]).lean();

    s.apiKey = decrypt(s.apiKey);
    s.bio = decrypt(s.bio);
    s.url = decrypt(s.url);
    s.location = decrypt(s.location);
    s.fonts = decrypt(s.fonts);
    if (req.query.views && req.query.views !== '1') delete s.views;
    if (!req.query.views) delete s.views;

    if (!req.query.links) links = null;
    if (req.query.links && req.query.links !== '1') links = null;
    if (links && links.length < 1) links = null;
    if (links && links.length > 0) {
        links.forEach((elm) => { elm.link = decrypt(elm.link); elm.title = decrypt(elm.title); elm.subtitle = decrypt(elm.subtitle); elm.thumbnail = decrypt(elm.thumbnail) });

        links = JSON.stringify(links);
    };

    if (rec && rec.length > 0) {
        let finalRec = [];
        rec.forEach(async elm => {
            if (elm.credit && elm.valid) {
                await receipt.updateOne({ user: s._id, uuid: elm.uuid }, { $set: { valid: false } });
                await user.updateOne({ uuid: s.uuid }, { $set: { credit: elm.amount } });
            };
            if (new Date() > elm.valid_until && !elm.credit && !elm.badge) {
                await receipt.updateOne({ user: s._id, uuid: elm.uuid }, { $set: { valid: false } });
                if (elm.pro) { await user.updateOne({ uuid: s.uuid }, { $set: { pro: false, linklimit: "25", theme: "" } }) };
                if (elm.subdomain) { await user.updateOne({ uuid: s.uuid }, { $set: { subdomain: false } }) };
            };
            if (!s.pro || !s.subdomain) {
                if (new Date() < elm.valid_until) {
                    if (elm.pro) { await user.updateOne({ uuid: s.uuid }, { $set: { pro: true, linklimit: "50", theme: "dark" } }) };
                    if (elm.subdomain) { await user.updateOne({ uuid: s.uuid }, { $set: { subdomain: true } }) };
                };
            };
            finalRec.push({ receipt: elm.receipt, amount: elm.amount, valid_until: elm.valid_until });
        });
        s.receipts = finalRec;
    };

    let result = { OK: true, status: 200, account: encrypt(JSON.stringify(s)), links: encrypt(links) };
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(result, null, 2.5));
});

a.get('/v1/uuid', async function (req, res) {
    let { session } = req.cookies;
    let { name } = req.query;

    let acc = await user.findOne({ session }, { password: 0, createdIP: 0, __v: 0, _id: 0, recEmail: 0, google_backup: 0, TFA: 0, email: 0, connectedUser: 0, staff: 0, socials: 0, links: 0, verified: 0, vrverified: 0, ogname: 0, linklimit: 0, pfp: 0 }).lean();
    if (!acc) return res.status(403).json({ OK: false, status: 403, error: `Must be authenticated to view this endpoint` });

    if (!name) return res.status(403).json({ OK: false, status: 403, error: `Invalid username` });
    let s = await user.findOne({ nameToFind: name.toUpperCase() }, { password: 0, createdIP: 0, __v: 0, _id: 0, recEmail: 0, session: 0, apiKey: 0, google_backup: 0, TFA: 0, email: 0, connectedUser: 0, staff: 0, socials: 0, links: 0, verified: 0, vrverified: 0, ogname: 0, linklimit: 0, pfp: 0 }).lean();

    if (!s) return res.status(403).json({ OK: false, status: 403, error: `Invalid username` });

    let result = { OK: true, status: 200, name: s.name, uuid: s.uuid };
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(result, null, 2.5));
});

a.get('/v1/account', async function (req, res) {
    let { session } = req.cookies;
    let { name, uuid } = req.query;

    let acc = await user.findOne({ session }, { password: 0, createdIP: 0, __v: 0, _id: 0, recEmail: 0, google_backup: 0, TFA: 0, email: 0, connectedUser: 0, staff: 0, socials: 0, links: 0, verified: 0, vrverified: 0, ogname: 0, linklimit: 0, pfp: 0, views: 0 }).lean();
    if (!acc) return res.status(403).json({ OK: false, status: 403, error: `Must be authenticated to view this endpoint` });

    if (!name && !uuid) return res.status(403).json({ OK: false, status: 403, error: `Invalid username or UUID` });
    let s;
    if (name) s = await user.findOne({ nameToFind: name.toUpperCase() }, { password: 0, createdIP: 0, __v: 0, recEmail: 0, session: 0, apiKey: 0, google_backup: 0, TFA: 0, email: 0, nameHistory: 0, connectedUser: 0, staff: 0, socials: 0, links: 0, verified: 0, vrverified: 0, ogname: 0, linklimit: 0, pfp: 0, banner: 0, views: 0, blocked: 0, hidden: 0, signin_id: 0, pfp_id: 0, banner_id: 0, createdAt: 0, location: 0, url: 0, credit: 0 }).lean();
    if (uuid) s = await user.findOne({ uuid }, { password: 0, createdIP: 0, __v: 0, recEmail: 0, session: 0, apiKey: 0, google_backup: 0, TFA: 0, email: 0, nameHistory: 0, connectedUser: 0, staff: 0, socials: 0, links: 0, verified: 0, vrverified: 0, ogname: 0, linklimit: 0, pfp: 0, banner: 0, views: 0, blocked: 0, hidden: 0, signin_id: 0, pfp_id: 0, banner_id: 0, createdAt: 0, location: 0, url: 0, credit: 0 }).lean();

    if (!s) return res.status(403).json({ OK: false, status: 403, error: `Invalid username or UUID` });

    s.bio = decrypt(s.bio);
    s.fonts = decrypt(s.fonts);
    if (!s.reason) delete s.reason;

    s.inactive = false;
    if (Date.now() - 2.234e+10 > s.last_login) s.inactive = true;

    delete s.last_login;
    delete s.pro;
    delete s.subdomain;
    delete s._id;

    let result = { OK: true, status: 200, account: s };
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(result, null, 2.5));
});

a.get('/v1/pronouns', async function (req, res) {
    let { name } = req.query;

    if (!name) return res.status(403).json({ OK: false, status: 403, error: `Invalid username` });
    let s = await user.findOne({ nameToFind: name.toUpperCase() }, { password: 0, createdIP: 0, __v: 0, _id: 0, recEmail: 0, session: 0, apiKey: 0, google_backup: 0, TFA: 0, email: 0, connectedUser: 0, staff: 0, socials: 0, links: 0, verified: 0, vrverified: 0, ogname: 0, linklimit: 0, pfp: 0, banner: 0, views: 0 }).lean();

    if (!s) s = { pronouns: null };

    let result = { OK: true, status: 200, pronoun: s.pronouns };
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(result, null, 2.5));
});

a.get('/v1/personal_border', async function (req, res) {
    let { name } = req.query;

    if (!name) return res.status(403).json({ OK: false, status: 403, error: `Invalid username` });
    let s = await user.findOne({ nameToFind: name.toUpperCase() }, { password: 0, createdIP: 0, __v: 0, _id: 0, recEmail: 0, session: 0, apiKey: 0, google_backup: 0, TFA: 0, email: 0, connectedUser: 0, staff: 0, socials: 0, links: 0, verified: 0, vrverified: 0, ogname: 0, linklimit: 0, pfp: 0, banner: 0, views: 0 }).lean();

    if (!s) s = { personal_border: 'none' };

    let result = { OK: true, status: 200, border: s.personal_border };

    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(result, null, 2.5));
});

a.get('/v1/inactive/:name', async function (req, res) {
    let { name } = req.params;

    if (!name) return res.status(404).json({ OK: false, status: 404, error: `Invalid username` });
    let s = await user.findOne({ nameToFind: name.toUpperCase() }, { password: 0, createdIP: 0, __v: 0, _id: 0, recEmail: 0, session: 0, apiKey: 0, google_backup: 0, TFA: 0, email: 0, connectedUser: 0, staff: 0, socials: 0, links: 0, verified: 0, vrverified: 0, ogname: 0, linklimit: 0, pfp: 0, banner: 0, views: 0 }).lean();

    if (name.toLowerCase() == "help") {
        s = { inactive: true };
    
        let result = { OK: true, status: 200, inactive: s.inactive };
        res.setHeader('Content-Type', 'application/json');
        return res.send(JSON.stringify(result, null, 2.5));
    };
    if (!s) s = { inactive: false, last_login: Date.now() - 5000 };

    s.inactive = false;
    if (Date.now() - 2.234e+10 > s.last_login) s.inactive = true;

    let result = { OK: true, status: 200, inactive: s.inactive };
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(result, null, 2.5));
});

a.post('/v1/register', async function (req, res) {
    try {
        let { session } = req.cookies;
        let { email_VR, password_VR, confpassword_VR, TOS_VR, Username_VR } = req.body;
    
        if (session) return res.status(403).json({ OK: false, status: 403, error: `You are already logged in!` });
        if (!email_VR || !password_VR || !confpassword_VR) return res.status(403).json({ OK: false, status: 403, error: `Missing fields` });
        if (!TOS_VR) return res.status(403).json({ OK: false, status: 403, error: `Please confirm that you read our ToS before joining` });
        if (password_VR !== confpassword_VR) return res.status(403).json({ OK: false, status: 403, error: `Password must match.` });
    
        let char = /^[a-zA-Z0-9_]+$/;
        let EMAIL_ALREADY = false;
        session = randomUUID();
        let uuid = randomUUID();
        let api_key = randomUUID();
        let username = Username_VR;
        let u = await user.find({  }, { email: 1, signin_id: 1 }).lean();

        u = u.map((h) => { if (h.signin_id == cryptojs.MD5(email_VR.toLowerCase()).toString().slice(24)) return EMAIL_ALREADY = true; });
        if (u && EMAIL_ALREADY) return res.status(403).json({ OK: false, status: 403, error: `E-Mail already used before` });

        if (username.length < 2) return res.status(400).json({ OK: false, status: 400, error: `Username must be greater than 2 characters` });
        if (username.length > 15) return res.status(400).json({ OK: false, status: 400, error: `Username must be less than 16 characters` });

        if (!char.test(username)) return res.status(403).json({ OK: false, status: 403, error: `Invalid regex form` });
    
        let confT = Math.random().toString(32).substring(4).toUpperCase();
        let filter = await dbMisc.findOne({ uuid: "a09ddcc5-0e36-4dc2-bb36-dc59959c114f" }, { reserved: 1, blocked: 1, _id: 0 }).lean();
        
        let reserved = false;
        let blockedU = false;
        filter.reserved.forEach(elm => {
            if (Username_VR.toLowerCase() == elm.name.toLowerCase()) reserved = true;
        });
        filter.blocked.forEach(elm => {
            if (Username_VR.toLowerCase() == elm.toLowerCase()) blockedU = true;
        });
    
        if (reserved) return res.status(403).json({ OK: false, status: 403, error: `Username is reserved. Contact support to continue` });
        if (blockedU) return res.status(403).json({ OK: false, status: 403, error: `Username is blocked` });
        let checkname = await user.findOne({ nameToFind: Username_VR.toUpperCase(), hidden: false }, { uuid: 1 }).lean();
        if (checkname) return res.status(403).json({ OK: false, status: 403, error: `Username is already taken` });
    
        await new user({
            email: encrypt(email_VR.toLowerCase()),
            name: encodeURIComponent(username),
            displayName: username,
            uuid,
            signin_id: cryptojs.MD5(email_VR.toLowerCase()).toString().slice(24),
            password: encrypt(password_VR),
            pfp: "https://f004.backblazeb2.com/file/ferrets/user_avatar/default_avatar.png",
            pfp_id: "4_zd5afb20446dd61128b590419_f1192ca08e2cc1c4e_d20221230_m043305_c004_v0402014_t0006_u01672374785939",
            banner: "",
            banner_id: "",
            recEmail: "",
            session,
            apiKey: encrypt(api_key),
            credit: "0.00",
            bio: "",
            url: "",
            location: "",
            reason: "",
            personal_border: "none",
            fonts: encrypt(""),
            linklimit: "25",
            links: [],
            socials: { "discord": "" },
            nameHistory: [{ username: encodeURIComponent(username), date: Date.now(), uuid: randomUUID() }],
            views: [],
            verified: false,
            vrverified: false,
            ogname: false,
            pro: false,
            subdomain: false,
            blocked: false,
            pronouns: null,
            staff: false,
            hidden: false,
            nameToFind: username.toUpperCase(),
            createdIP: encrypt(req.headers['x-forwarded-for']),
            createdAt: Date.now(),
            last_login: Date.now(),
        }).save();
        await new sessions({
            uuid,
            sessions: [{ token: session, date: Date.now(), ip: encrypt(req.headers['x-forwarded-for']) }],
            keys: [{ key: api_key, date: Date.now(), ip: encrypt(req.headers['x-forwarded-for']) }]
        }).save();
        await new verify_email({
            uuid,
            email: encrypt(email_VR.toLowerCase()),
            token: confT,
            used: false,
            valid: true,
            date: Date.now()
        }).save();
    
        let transporter = nodemailer.createTransport({
            host: "webserver4.pebblehost.com",
            port: 465,
            secure: true,
            auth: {
                user: "no-reply@ferret.page",
                pass: `${process.env.PASSWORD}`,
            },
        });
    
        let msg = {
            from: '"no-reply@ferret.page" <no-reply@ferret.page>',
            to: `${email_VR.toLowerCase()}`,
            subject: "Verify User Account",
            html: `<html><h4>Welcome to Ferret!</h4></br><h3>Here is your verification code: <a href="http://${req.hostname}/dashboard?code=${confT}" target="_blank">${confT}</a></h3><br><br><p>If you did not request to verify this account please click this (Also note that this will remove the account from our website!): <br><a href="http://${req.hostname}/api/verify/no/${uuid}?code=${confT}" target="_blank">http://${req.hostname}/api/verify/no/${uuid}?code=${confT}</a></p></html>`, // html body
        };
    
        const info = await transporter.sendMail(msg);
        res.cookie('session', session);
        res.json({ OK: true, status: 200 });
    } catch (e) {
        console.log(e);
        if (e.code == 'EENVELOPE') e = "Could not send verification code to email. (Please contact support)"
        res.status(403).json({ OK: false, status: 403, error: e });
    };
});

a.post('/v1/signin', async function (req, res) {
    let { session } = req.cookies;
    let { email_VR, password_VR, TFA_VR, expire_VR, code_VR } = req.body;

    if (!email_VR || !password_VR) return res.status(403).json({ OK: false, status: 403, error: `Missing fields` });
    if (!code_VR) return res.status(403).json({ OK: false, status: 403, error: `Invalid authentication code` });
    if (code_VR !== authCode[code_VR]) return res.status(403).json({ OK: false, status: 403, error: `Invalid authentication code` });

    let uC = await user.find({  }, { email: 1, password: 1, uuid: 1, TFA: 1, google_backup: 1, blocked: 1, flag: 1, name: 1, memorialize: 1, signin_id: 1 }).lean();
    let u = null;
    // u = u.map((h) => { if (decrypt(h.email) == email_VR.toLowerCase()) { return h }; });
    uC.forEach(elm => {
        if (elm && decrypt(elm.email) == email_VR.toLowerCase() && elm.signin_id == cryptojs.MD5(decrypt(elm.email)).toString().slice(24)) u = elm;
    });
    if (!u) return res.status(403).json({ OK: false, status: 403, error: `Account does not exist with that E-Mail` });
    if (password_VR !== decrypt(u.password)) return res.status(403).json({ OK: false, status: 403, error: `Incorrect Password` });
    if (u.blocked) return res.status(403).json({ OK: false, status: 403, error: `@${u.name} is currently blocked from signing in` });
    if (u.memorialize) return res.status(403).json({ OK: false, status: 403, error: `@${u.name} is currently blocked from signing in` });
    if (!TFA_VR && u.TFA) return res.status(403).json({ OK: false, status: 403, error: `Incorrect 2FA Code` });
    if (u.TFA) {
        let verify = authenticator.verifyToken(decrypt(u.google_backup), TFA_VR);
        if (!verify) return res.status(403).json({ OK: false, status: 403, error: `Incorrect 2FA Code` });
    };

    session = randomUUID();

    await sessions.updateOne({ uuid: u.uuid }, { $push: { sessions: [{ token: session, date: Date.now(), ip: encrypt(req.headers['x-forwarded-for']) }] } });
    await user.updateOne({ uuid: u.uuid }, { $set: { session, last_login: Date.now() } });

    if (expire_VR) {
        res.cookie('session', session, { maxAge: 2.592e+8 });
        res.json({ OK: true, status: 200 });
        return
    };
    res.cookie('session', session, { maxAge: 2.678e+9 });
    delete authCode[code_VR];
    res.json({ OK: true, status: 200 });
});

a.post('/v1/verify/:uid', async function (req, res) {
    let { session } = req.cookies;
    let { verifcode } = req.body;
    if (!verifcode && !req.query.resend) return res.status(403).json({ OK: false, error: `Enter code to continue` });

    try {
        let u = await user.findOne({ session }).lean();
        let c = null
        if (verifcode) c = verifcode.toUpperCase();
        if (u.verified) return res.status(403).json({ OK: false, error: `Account is already verified` });
        let token = Math.random().toString(32).substring(8);
        if (req.query.resend && req.query.resend == "true") {
            let confT = Math.random().toString(32).substring(4).toUpperCase();
            await new verify_email({
                uuid: u.uuid,
                email: encrypt(u.email),
                token: confT,
                used: false,
                valid: true,
                date: Date.now()
            }).save();
        
            let transporter = nodemailer.createTransport({
                host: "webserver4.pebblehost.com",
                port: 465,
                secure: true,
                auth: {
                    user: "no-reply@ferret.page",
                    pass: `${process.env.PASSWORD}`,
                },
            });
        
            let msg = {
                from: '"no-reply@ferret.page" <no-reply@ferret.page>',
                to: `${decrypt(u.email).toLowerCase()}`,
                subject: "Verify User Account",
                html: `<html><h4>Here's your new code!</h4></br><h3>Here is your verification code: <a href="http://${req.hostname}/dashboard?code=${confT}" target="_blank">${confT}</a></h3><br><br><p>If you did not request to verify this account please click this (Also note that this will remove the account from our website!): <br><a href="http://${req.hostname}/api/verify/no/${u.uuid}?code=${confT}" target="_blank">http://${req.hostname}/api/verify/no/${u.uuid}?code=${confT}</a></p></html>`, // html body
            };
            await verify_email.deleteOne({ uuid: u.uuid, used: false });
            const info = await transporter.sendMail(msg);
            return res.status(404).json({ error: `Code Expired` });
        };
        let vv = await verify_email.findOne({ uuid: u.uuid, token: c, used: false }).lean();
        if (!vv) return res.status(403).json({ OK: false, error: `Invalid code` });
        if (vv.token.toUpperCase() !== c) return res.status(403).json({ OK: false, error: `Invalid code` });
        let nDate = Date.now();
        if (Date.now() > parseInt(vv.date)+1.728e+8) {
            let confT = Math.random().toString(32).substring(4).toUpperCase();
            await new verify_email({
                uuid: vv.uuid,
                email: vv.email,
                token: confT,
                used: false,
                valid: true,
                date: Date.now()
            }).save();
        
            let transporter = nodemailer.createTransport({
                host: "webserver4.pebblehost.com",
                port: 465,
                secure: true,
                auth: {
                    user: "no-reply@ferret.page",
                    pass: `${process.env.PASSWORD}`,
                },
            });
        
            let msg = {
                from: '"no-reply@ferret.page" <no-reply@ferret.page>',
                to: `${vv.email.toLowerCase()}`,
                subject: "Verify User Account",
                html: `<html><h4>Here's your new code!</h4></br><h3>Here is your verification code: <a href="http://${req.hostname}/dashboard?code=${confT}" target="_blank">${confT}</a></h3><br><br><p>If you did not request to verify this account please click this (Also note that this will remove the account from our website!): <br><a href="http://${req.hostname}/api/verify/no/${vv.uuid}?code=${confT}" target="_blank">http://${req.hostname}/api/verify/no/${vv.uuid}?code=${confT}</a></p></html>`, // html body
            };
            await verify_email.deleteOne({ uuid: u.uuid, token: c, used: false });
            const info = await transporter.sendMail(msg);
            res.status(404).json({ error: `Resent code` });
            return
        };
        await verify_email.updateOne({ uuid: u.uuid, used: false }, { $set: { used: true } });
        await user.updateOne({ session }, { $set: { verified: true } });

        if (!req.query.json) return res.redirect('/dashboard');
        res.json({ OK: true, status: 200, text: "Verified user" });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: e });
    };
});

a.get('/verify/no/:uid', async function (req, res) {
    let verifcode = req.query.code;

    if (!verifcode) return res.sendStatus(404);
    let c = verifcode.toUpperCase();
    user.findOne({ uuid: req.params.uid }, async function (e, r) {
        if (!r) return res.sendStatus(403);
        if (req.params.uid == r.uuid) {
            verify_email.findOne({ uuid: r.uuid, used: false }, async function (err, re) {
                if (!re) return res.status(404).json({ error: `Could not find code` });
                if (re.token == c) {
                    await verify_email.findOneAndRemove({ uuid: r.uuid });
                    await sessions.findOneAndRemove({ uuid: r.uuid });
                    await user.findOneAndRemove({ uuid: r.uuid });
                    res.clearCookie('session');
                    res.redirect('/');
                } else {
                    res.status(404).json({ error: `Invalid code` });
                };
            });
        } else {
            res.sendStatus(404);
        }
    });
});

a.post('/v1/reset-password', async function (req, res) {
    let { session } = req.cookies;
    let { email_VR, TFA_VR, code_VR } = req.body;

    if (!email_VR) return res.status(403).json({ OK: false, status: 403, error: `Missing fields` });
    if (!code_VR) return res.status(403).json({ OK: false, status: 403, error: `Invalid authentication code` });
    if (code_VR !== authCode[code_VR]) return res.status(403).json({ OK: false, status: 403, error: `Invalid authentication code` });

    let uC = await user.find({  }, { email: 1, password: 1, uuid: 1, TFA: 1, google_backup: 1, blocked: 1, flag: 1, name: 1, displayName: 1, memorialize: 1, signin_id: 1 }).lean();
    let u = null;
    uC.forEach(elm => {
        if (elm && decrypt(elm.email) == email_VR.toLowerCase() && elm.signin_id == cryptojs.MD5(decrypt(elm.email)).toString().slice(24)) u = elm;
    });
    if (!u) return res.status(403).json({ OK: false, status: 403, error: `Account does not exist with that E-Mail` });
    if (u.blocked) return res.status(403).json({ OK: false, status: 403, error: `@${u.name} is currently blocked` });
    if (u.TFA && !TFA_VR || !authenticator.verifyToken(decrypt(u.google_backup), TFA_VR)) return res.status(403).json({ OK: false, status: 403, error: `Invalid 2FA Code` });

    try {
        let confT = randomUUID();
        authCode[confT] = { code: confT, uuid: u.uuid };
        let transporter = nodemailer.createTransport({
            host: "webserver4.pebblehost.com",
            port: 465,
            secure: true,
            auth: {
                user: "no-reply@ferret.page",
                pass: `${process.env.PASSWORD}`,
            },
        });
    
        let msg = {
            from: '"no-reply@ferret.page" <no-reply@ferret.page>',
            to: `${decrypt(u.email).toLowerCase()}`,
            subject: "Reset Account Password",
            html: `<html><h4>Hello ${u.displayName} (@${u.name})!</h4></br><h3>You can reset your password by clicking <a href="http://${req.hostname}/reset-password?code=${confT}" target="_blank">here</a></h3><br><br><p>If the link does not work then you may need to request a new one.</p></html>`, // html body
        };

        delete authCode[code_VR];
        const info = await transporter.sendMail(msg);
        res.json({ OK: true, status: 200, text: 'Started account recovery' });
    } catch (e) {
        return res.status(500).json({ OK: false, status: 500, error: `An error has happened` });
    };
});

a.post('/v1/reset-password/conf', async function (req, res) {
    let { session } = req.cookies;
    let { password_VR, conf_pass_VR, code_VR, AuthCode_VR } = req.body;

    if (!password_VR || !conf_pass_VR) return res.status(403).json({ OK: false, status: 403, error: `Missing Fields` });
    if (!code_VR || !AuthCode_VR) return res.status(403).json({ OK: false, status: 403, error: `Invalid authentication code` });
    if (code_VR !== authCode[code_VR]) return res.status(403).json({ OK: false, status: 403, error: `Invalid authentication code` });
    if (AuthCode_VR !== authCode[AuthCode_VR].code) return res.status(403).json({ OK: false, status: 403, error: `Invalid Reset Token` });

    if (password_VR !== conf_pass_VR) return res.status(403).json({ OK: false, status: 403, error: `Passwords must match` });
    if (password_VR.length < 6) return res.status(403).json({ OK: false, status: 403, error: `Password must be longer than 6` });
    if (password_VR.length > 128) return res.status(403).json({ OK: false, status: 403, error: `Password must be shorter than 128` });

    let u = await user.findOne({ uuid: authCode[AuthCode_VR].uuid }, { email: 1, password: 1, uuid: 1, TFA: 1, google_backup: 1, blocked: 1, flag: 1, name: 1, displayName: 1, memorialize: 1, signin_id: 1, _id: 1 }).lean();
    if (!u) return res.status(404).json({ OK: false, status: 404, error: `Invalid UUID` });
    if (u.blocked) return res.status(403).json({ OK: false, status: 403, error: `This user is blocked` });
    if (password_VR == decrypt(u.password)) return res.status(403).json({ OK: false, status: 403, error: `Please use a different password` });

    try {
        let transporter = nodemailer.createTransport({
            host: "webserver4.pebblehost.com",
            port: 465,
            secure: true,
            auth: {
                user: "no-reply@ferret.page",
                pass: `${process.env.PASSWORD}`,
            },
        });
    
        let msg = {
            from: '"no-reply@ferret.page" <no-reply@ferret.page>',
            to: `${decrypt(u.email).toLowerCase()}`,
            subject: "Account Password Changed",
            html: `<html><h4>Hello ${u.displayName} (@${u.name})!</h4></br><h3>Your account password has been successfully changed.</h3><br><br><p>If you did not do this change then please contact our support team: support@ferret.page</p></html>`, // html body
        };

        await user.updateOne({ uuid: u.uuid }, { $set: { password: encrypt(password_VR) } });
        await new notification({
            author: u._id,
            from: u._id,
            text: `Your password has been changed`,
            friendRequest: false,
            hidden: false,
            date: Date.now(),
            uuid: randomUUID()
        }).save();

        delete authCode[code_VR];
        delete authCode[AuthCode_VR];
        const info = await transporter.sendMail(msg);
        res.json({ OK: true, status: 200, text: 'Updated user password' });
    } catch (e) {
        return res.status(500).json({ OK: false, status: 500, error: `An error has happened` });
    };
});

a.post('/v1/account/edit', async function (req, res) {
    let { session } = req.cookies;
    let { display_vr, name_vr, bio_vr, location_vr, pronouns_vr, darktheme_vr, border_vr } = req.body;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    if (!name_vr) return res.status(403).json({ OK: false, status: 403, error: `You must have a username` });

    let acc = await user.findOne({ session }).lean();
    let char = /^[a-zA-Z0-9_]+$/;
    let darktheme = "";

    if (!display_vr) {
        await user.updateOne({ session }, { $set: { displayName: acc.name } });
        res.json({ OK: true, status: 200, status: "Set display name to: None" });
        return
    };

    if (display_vr) {
        if (display_vr.length > 28) return res.status(403).json({ OK: false, status: 403, error: `Invalid length: ${display_vr.length}/28` });
        // if (!char.test(display_vr)) return res.status(403).json({ OK: false, status: 403, error: `Invalid Display Name` });
        if (acc.ogname) {
            if (!display_vr.includes(' ') && display_vr.toUpperCase() !== acc.nameToFind) return res.status(403).json({ OK: false, status: 403, error: `Display name must include username` });

            let splitName = display_vr.split(' ');
            let isname = false;
            splitName.forEach(elm => {
                if (elm.toUpperCase() == acc.nameToFind) isname = true;
            });

            if (!isname) return res.status(403).json({ OK: false, status: 403, error: `Display name must include username` });
        }

        await user.updateOne({ session }, { $set: { displayName: display_vr } });
    };

    if (name_vr && acc.nameToFind !== name_vr.toUpperCase()) {
        name_vr = encodeURIComponent(name_vr);

        if (!char.test(name_vr)) return res.status(403).json({ OK: false, status: 403, error: `Invalid regex form` });

        if (name_vr.length < 2) return res.status(400).json({ OK: false, status: 400, error: `Username must be greater than 2 characters` });
        if (name_vr.length > 15) return res.status(400).json({ OK: false, status: 400, error: `Username must be less than 16 characters` });

        let filter = await dbMisc.findOne({ uuid: "a09ddcc5-0e36-4dc2-bb36-dc59959c114f" }, { reserved: 1, blocked: 1, _id: 0 }).lean();
        
        let reserved = false;
        let blockedU = false;
        filter.reserved.forEach(elm => {
            if (name_vr.toLowerCase() == elm.name.toLowerCase()) reserved = true;
        });
        filter.blocked.forEach(elm => {
            if (name_vr.toLowerCase() == elm.toLowerCase()) blockedU = true;
        });

        if (reserved) return res.status(403).json({ OK: false, status: 403, error: `Username is reserved. Contact support to continue` });
        if (blockedU) return res.status(403).json({ OK: false, status: 403, error: `Username is blocked` });
        let checkname = await user.findOne({ nameToFind: name_vr.toUpperCase(), hidden: false }, { uuid: 1 }).lean();
        if (checkname) return res.status(403).json({ OK: false, status: 403, error: `Username is already taken` });

        if (acc.nameHistory.length > 0 && parseInt(acc.nameHistory[acc.nameHistory.length - 1].date)+8.64e+7 > Date.now()) return res.status(403).json({ OK: false, status: 403, error: `You can only change your username once every 24 hours` });
        await user.updateOne({ session }, { $set: { name: name_vr, nameToFind: name_vr.toUpperCase() } });
        await user.updateOne({ session }, { $push: { nameHistory: [{ name: name_vr, date: Date.now(), hidden: false, uuid: randomUUID() }] } });
    };

    if (bio_vr && bio_vr.length > 95) return res.status(400).json({ OK: false, status: 400, error: `Bio must be less than 96 characters` });
    if (location_vr.length > 57) return res.status(400).json({ OK: false, status: 400, error: `Location must be less than 58 characters` });

    let pronoun = { hh: "he/him", hi: "he/it", hs: "he/she", ht: "he/they", ih: "it/him", ii: "it/its", is: "it/she", it: "it/they", shh: "she/he", sh: "she/her", si: "she/it", st: "she/they", th: "they/he", ti: "they/it", ts: "they/she", tt: "they/them", any: "Any pronouns", other: "Other pronouns", ask: "Please ask", avoid: "Avoid pronouns" };
    if (!pronouns_vr) pronoun = null;
    if (pronouns_vr == "Unspecified...") pronoun = null;
    if (pronouns_vr && pronoun && !pronoun[pronouns_vr.toLowerCase()]) pronoun = null;
    if (pronouns_vr && pronoun && pronoun[pronouns_vr.toLowerCase()]) pronoun = pronoun[pronouns_vr.toLowerCase()];

    let pBorder = 'none';
    let crossBorder = { "lesbian": "lesbian", "gay": "gay", "bisexual": "bisexual", "trans": "trans", "queer": "queer", "intersex": "intersex", "asexual": "asexual", "agender": "agender", "aroace": "aroace", "aromantic": "aromantic", "nonbinary": "nonbinary", "polyamorous": "polyamorous", "poly": "poly", "gaymale": "gaymale", "gayfemale": "gayfemale", "genderqueer": "genderqueer", "omni": "omni", "ally": "ally" };
    if (border_vr && crossBorder[border_vr.toLowerCase()]) {
        pBorder = border_vr.toLowerCase();
    };

    if (location_vr.length < 1) {
        location_vr = "";
    }
    if (acc.pro && darktheme_vr == "on") darktheme = "dark";
    await user.updateOne({ session }, { $set: { location: encrypt(location_vr), bio: encrypt(bio_vr), pronouns: pronoun, theme: darktheme, personal_border: pBorder } });

    res.json({ OK: true, status: 200, status: `Updated profile` });
});

a.post('/v1/account/edit/font', async function (req, res) {
    let { session } = req.cookies;
    let { fonts_vr } = req.body;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    if (!fonts_vr) return res.status(403).json({ OK: false, status: 403, error: `You must have a font selected` });

    let font = {"none": "", "Caveat": "Caveat", "Kanit": "Kanit", "Oswald": "Oswald", "Poppins": "Poppins", "SourceCodePro": "Source Code Pro", "Aldrich": "Aldrich"};
    font = font[fonts_vr];

    if (!font && fonts_vr !== 'none') return res.status(403).json({ OK: false, status: 403, error: `Invalid Font` });

    await user.updateOne({ session }, { $set: { fonts: encrypt(font) } });
    res.json({ OK: true, status: 200, status: `Updated profile font`, updated_to: font });
});

a.post('/v1/account/edit_socials', async function (req, res) {
    let { session } = req.cookies;
    let { SDC, discord_vr } = req.body;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    let acc = await user.findOne({ session }).lean();

    if (SDC) {
        if (discord_vr && discord_vr.length < 5) return res.status(403).json({ OK: false, status: 403, error: "Length must be longer than 4" });
        if (discord_vr && !discord_vr.includes('#')) return res.status(403).json({ OK: false, status: 403, error: "You must include a valid tag" });
        if (discord_vr && discord_vr.includes('#') && discord_vr.split('#')[1].length > 4) return res.status(403).json({ OK: false, status: 403, error: "You must include a valid tag" });
        if (!discord_vr) { await user.updateOne({ session }, { $set: { "socials.discord": "" } }); };

        await user.updateOne({ session }, { $set: { "socials.discord": discord_vr } });
    };

    res.json({ OK: true, status: 200, status: `Updated socials` });
});

a.post('/v1/account/edit/avatar', async function (req, res) {
    let { session } = req.cookies;

    try {
        if (!session) return res.status(403).json({ OK: false, error: `Invalid session` });
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });
        var up = upload.single('pfp');

        let u = await user.findOne({ session }).lean();
        await GetBucket();

        up(req, res, async function (e) {
            if (e) console.log(e);
            if (e) return res.status(500).json({ OK: false, error: `${e}` });
            if (!e) {
                let file = null;
                let fileExtension = null;
                let upl = null;
                let authT = null;
                if (req.file) file = req.file;
                if (req.file) fileExtension = req.file.originalname.match(/\.(jpg|JPG|jpeg|JPEG|png|PNG|gif|GIF)$/);
                if (fileExtension) fileExtension = fileExtension[0];

                if (!file) {
                    let current = u.pfp;

                    if (current !== "https://f004.backblazeb2.com/file/ferrets/user_avatar/default_avatar.png") {
                        b2.getFileInfo({
                            fileId: u.pfp_id
                        }).then(async tt => {
                            let data = tt.data;

                            b2.deleteFileVersion({
                                fileId: data.fileId,
                                fileName: data.fileName
                            });
                            await user.updateOne({ session }, { $set: { pfp: `https://f004.backblazeb2.com/file/ferrets/user_avatar/default_avatar.png`, pfp_id: "4_zd5afb20446dd61128b590419_f106e64e803b29f2b_d20221230_m174015_c004_v0402001_t0028_u01672422015619" } });
                            delete avatarCache[u.uuid];
                        });
                    };
                    return res.json({ OK: true, status: 200, text: `Updated avatar` });
                }

                if (file && file.mimetype !== "image/gif") {
                    await sharp(file.buffer).resize({ width: 256, height: 256 }).toBuffer().then(data => {
                        if (data) file.buffer = data; file.size = data.length;
                    });
                };

                if (u.pfp !== "https://f004.backblazeb2.com/file/ferrets/user_avatar/default_avatar.png") {
                    b2.getFileInfo({
                        fileId: u.pfp_id
                    }).then(async tt => {
                        let data = tt.data
                        b2.deleteFileVersion({
                            fileId: data.fileId,
                            fileName: data.fileName
                        });
                    });
                };

                b2.getUploadUrl({
                    bucketId: 'd5afb20446dd61128b590419'
                }).then(tt => {
                    upl = tt.data.uploadUrl; 
                    authT = tt.data.authorizationToken;

                    b2.uploadFile({
                        uploadUrl: upl,
                        uploadAuthToken: authT,
                        fileName: randomUUID(),
                        contentLength: file.size,
                        mime: file.mimetype,
                        data: file.buffer,
                        hash: '',
                        onUploadProgress: (event) => {}
                    }).then(async fin => { await user.updateOne({ session }, { $set: { pfp: `https://f004.backblazeb2.com/file/ferrets/${fin.data.fileName}`, pfp_id: fin.data.fileId } }); delete avatarCache[u.uuid]; });
                });
                res.json({ OK: true, status: 200, text: `Updated avatar` });
            };
        });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: e });
    };
});

a.post('/v1/account/edit/banner', async function (req, res) {
    let { session } = req.cookies;

    try {
        if (!session) return res.status(403).json({ OK: false, error: `Invalid session` });
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });
        var up = upload.single('banner');

        let u = await user.findOne({ session }).lean();

        up(req, res, async function (e) {
            if (e) console.log(e);
            if (e) return res.status(500).json({ OK: false, error: `${e}` });
            if (!e) {
                let file = null;
                let fileExtension = null;
                let upl = null;
                let authT = null;
                if (req.file) file = req.file;
                if (req.file) fileExtension = req.file.originalname.match(/\.(jpg|JPG|jpeg|JPEG|png|PNG|gif|GIF)$/);
                if (fileExtension) fileExtension = fileExtension[0];

                if (!file) {
                    let current = u.banner;

                    if (current !== "") {
                        b2.getFileInfo({
                            fileId: u.banner_id
                        }).then(async tt => {
                            let data = tt.data;

                            b2.deleteFileVersion({
                                fileId: data.fileId,
                                fileName: data.fileName
                            });
                        });
                    };
                    delete bannerCache[u.uuid];
                    await user.updateOne({ session }, { $set: { banner: "", banner_id: "" } });
                    return res.json({ OK: true, status: 200, text: `Updated banner` });
                }

                if (file && file.mimetype !== "image/gif") {
                    await sharp(file.buffer).resize({ width: 350, height: 150 }).toBuffer().then(data => {
                        if (data) file.buffer = data; file.size = data.length;
                    });
                };

                if (u.banner !== "") {
                    b2.getFileInfo({
                        fileId: u.banner_id
                    }).then(async tt => {
                        let data = tt.data
                        b2.deleteFileVersion({
                            fileId: data.fileId,
                            fileName: data.fileName
                        });
                    });
                };

                b2.getUploadUrl({
                    bucketId: 'd5afb20446dd61128b590419'
                }).then(tt => {
                    upl = tt.data.uploadUrl; 
                    authT = tt.data.authorizationToken;

                    b2.uploadFile({
                        uploadUrl: upl,
                        uploadAuthToken: authT,
                        fileName: randomUUID(),
                        contentLength: file.size,
                        mime: file.mimetype,
                        data: file.buffer,
                        hash: '',
                        onUploadProgress: (event) => {}
                    }).then(async fin => { await user.updateOne({ session }, { $set: { banner: `https://f004.backblazeb2.com/file/ferrets/${fin.data.fileName}`, banner_id: fin.data.fileId } }) });
                });

                delete bannerCache[u.uuid];
                res.json({ OK: true, status: 200, text: `Updated banner` });
            };
        });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: e });
    };
});

a.post('/v1/create_url', async function (req, res) {
    let { session } = req.cookies;
    let { url_vr, title_vr, subtitle_vr, highlight_vr, limit_vr, llC } = req.body;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    let regex = /(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})/
    let url = regex.test(url_vr);
    
    if (!url) return res.status(403).json({ OK: false, status: 403, error: `Invalid URL` });
    if (!title_vr) title_vr = url_vr.split('/')[2];
    let u = await user.findOne({ session }).lean();
    let token = Math.random().toString(32).substring(8);
    let highlight = false;
    let isLimit = false;
    let BL = false;
    let WA = false;
    let isLimitNum = undefined;
    let thumb = `https://t1.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=${url_vr}&size=128`;

    let checkurl = await short_url.find({ author: u._id, blocked: false }).lean();
    let mis = await misc.findOne({ uuid: "f23b87dc-7c61-4a9e-8f7d-998b649f3614" }, { links: 1, uuid: 1 }).lean();
    if (checkurl && checkurl.length > 0) {
        if (checkurl.length > parseInt(u.linklimit)) return res.status(403).json({ OK: false, status: 403, error: `Upgrade plan to add more links` });
    };

    if (mis) {
        mis.links.forEach(elm => {
            if (url_vr.includes(elm.url) && elm.blocked) BL = true;
            if (url_vr.includes(elm.url) && elm.warn && !elm.blocked) WA = true;
        });
        if (BL) return res.status(403).json({ OK: false, status: 403, error: `This URL is blocked, please try a different one.` });
    };

    if (req.body.ico) req.file = req.body.ico;
    if (u.pro && highlight_vr && highlight_vr == "on") highlight = true;
    if (u.pro && limit_vr && llC == "on") isLimit = true;
    if (url_vr.includes('ferret.page')) thumb = "https://ferret.page/public/default.png";
    if (url_vr.includes('twitter.com')) thumb = "https://ferret.page/public/i/assets/twitter_normal.png";

    if (isLimit && !isNaN(limit_vr)) {
        limit_vr = parseInt(limit_vr);
        if (limit_vr > 2500) return res.status(403).json({ OK: false, status: 403, error: `Upgrade plan to increase the click limit: ${limit_vr}/2500` });
        if (limit_vr < 1) return res.status(403).json({ OK: false, status: 403, error: `Click limit must be greater than 1: ${limit_vr}/2500` });
        isLimitNum = limit_vr;
    };

    await new short_url({
        author: u._id,
        link: encrypt(url_vr),
        id: token,
        title: encrypt(title_vr),
        subtitle: encrypt(subtitle_vr),
        thumbnail: encrypt(thumb),
        thumbnail_pro_id: "",
        order: "99",
        limitClick: isLimitNum,
        clicks: [],
        highlight,
        hidden: false,
        blocked: false,
        warn: WA,
        limitClicks: isLimit,
        blocked_reason: "",
        date: Date.now(),
        uuid: randomUUID()
    }).save();

    res.json({ OK: true, status: 200, status: `Created link` });
});

a.get('/v1/remove_url/:uuid', async function (req, res) {
    let { session } = req.cookies;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });
    
    let u = await user.findOne({ session }).lean();
    let urls = await short_url.findOne({ author: u._id, uuid: req.params.uuid }).populate([{ path:"author", select: {displayName: 1, name: 1, pfp: 1, uuid: 1, hcverified: 1, hidden: 1} }]).lean();
    if (!urls) return res.status(404).json({ OK: false, status: 404, error: `Could not find URL` });

    if (urls.thumbnail_pro_id !== "") {
        b2.getFileInfo({
            fileId: urls.thumbnail_pro_id
        }).then(async tt => {
            let data = tt.data
            b2.deleteFileVersion({
                fileId: data.fileId,
                fileName: data.fileName
            });
        });
    };

    delete faviconCache[urls.id];
    await short_url.deleteOne({ uuid: urls.uuid });
    res.json({ OK: true, status: 200, status: `Removed link` });
});

a.post('/v1/edit_url/:uuid', async function (req, res) {
    let { session } = req.cookies;
    let { title_vr, subtitle_vr, order_vr, url_vr, highlight_vr, limit_vr, llC } = req.body;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });
    
    let u = await user.findOne({ session }).lean();
    let urls = await short_url.findOne({ author: u._id, uuid: req.params.uuid }).populate([{ path:"author", select: {displayName: 1, name: 1, pfp: 1, uuid: 1, hcverified: 1, hidden: 1} }]).lean();
    if (!urls) return res.status(404).json({ OK: false, status: 404, error: `Could not find URL` });

    let title = title_vr;
    let stitle = subtitle_vr;
    let highlight = false
    let isLimit = urls.limitClicks;
    let isLimitNum = parseInt(urls.limitClick);
    let thumb = `https://t1.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=${url_vr}&size=128`;
    if (decrypt(urls.thumbnail).includes('backblazeb2.com')) thumb = decrypt(urls.thumbnail);

    if (!title) title = decrypt(urls.title);
    if (!url_vr) url_vr = decrypt(urls.link);

    let regex = /(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})/
    let url = regex.test(url_vr);
    let limitClicks = true;
    if (!llC) limitClicks = false;
    if (!url) return res.status(403).json({ OK: false, status: 403, error: `Invalid URL` });

    if (u.pro && highlight_vr && highlight_vr == "on") highlight = true;
    if (u.pro && limitClicks) {
        if (!isNaN(limit_vr)) {
            limit_vr = parseInt(limit_vr);
            if (limit_vr > 2500) return res.status(403).json({ OK: false, status: 403, error: `Upgrade plan to increase the click limit: ${limit_vr}/2500` });
            if (limit_vr < 1) return res.status(403).json({ OK: false, status: 403, error: `Click limit must be greater than 1: ${limit_vr}/2500` });
            isLimitNum = limit_vr;
        };
    };
    if (url_vr.includes('ferret.page')) thumb = "https://ferret.page/public/default.png";
    if (url_vr.includes('twitter.com')) thumb = "https://ferret.page/public/i/assets/twitter_normal.png";

    delete faviconCache[urls.id];
    await short_url.updateOne({ uuid: urls.uuid, blocked: false }, { $set: { title: encrypt(title), subtitle: encrypt(stitle), thumbnail: encrypt(thumb), order: parseInt(order_vr), link: encrypt(url_vr), highlight, limitClick: isLimitNum, limitClicks } });
    res.json({ OK: true, status: 200, text: `Updated link` });
});

a.post('/v1/edit_url/:uuid/icon', async function (req, res) {
    let { session } = req.cookies;

    try {
        if (!session) return res.status(403).json({ OK: false, error: `Invalid session` });
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });
        var up = upload.single('favicon');

        let u = await user.findOne({ session }).lean();
        if (!u) return res.status(403).json({ OK: false, status: 403, error: `Must be authenticated to view this endpoint` });
        if (u.blocked) return res.status(403).json({ OK: false, status: 403, error: `User is blocked` });
        if (!u.pro) return res.status(403).json({ OK: false, status: 403, error: `User must be on an upgraded plan to view this endpoint` });
        let urls = await short_url.findOne({ author: u._id, uuid: req.params.uuid }).populate([{ path:"author", select: {displayName: 1, name: 1, pfp: 1, uuid: 1, hcverified: 1, hidden: 1} }]).lean();
        if (!urls) return res.status(404).json({ OK: false, status: 404, error: `Could not find URL` });

        up(req, res, async function (e) {
            if (e) console.log(e);
            if (e) return res.status(500).json({ OK: false, error: `${e}` });
            if (!e) {
                let file = null;
                let fileExtension = null;
                let upl = null;
                let authT = null;
                if (req.file) file = req.file;
                if (req.file) fileExtension = req.file.originalname.match(/\.(jpg|JPG|jpeg|JPEG|png|PNG|gif|GIF)$/);
                if (fileExtension) fileExtension = fileExtension[0];

                if (!file) {
                    urls.link = decrypt(urls.link);
                    urls.thumbnail = decrypt(urls.thumbnail);
                    let current = urls.thumbnail;
                    let thumb = `https://t1.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=${urls.link}&size=128`;
                    if (urls.link.includes('ferret.page')) thumb = "https://ferret.page/public/default.png";
                    if (urls.link.includes('twitter.com')) thumb = "https://ferret.page/public/i/assets/twitter_normal.png";

                    if (current.includes('backblaze') && urls.thumbnail_pro_id !== "") {
                        b2.getFileInfo({
                            fileId: urls.thumbnail_pro_id
                        }).then(async tt => {
                            let data = tt.data;

                            b2.deleteFileVersion({
                                fileId: data.fileId,
                                fileName: data.fileName
                            });
                        });
                    };
                    delete faviconCache[urls.id];
                    await short_url.updateOne({ uuid: urls.uuid }, { $set: { thumbnail: encrypt(thumb), thumbnail_pro_id: "" } });
                    return res.json({ OK: true, status: 200, text: `Updated icon` });
                }

                if (file && file.mimetype !== "image/gif") {
                    await sharp(file.buffer).resize({ width: 128, height: 128 }).toBuffer().then(data => {
                        if (data) file.buffer = data; file.size = data.length;
                    });
                };

                if (urls.thumbnail_pro_id !== "") {
                    b2.getFileInfo({
                        fileId: urls.thumbnail_pro_id
                    }).then(async tt => {
                        let data = tt.data
                        b2.deleteFileVersion({
                            fileId: data.fileId,
                            fileName: data.fileName
                        });
                    });
                };

                b2.getUploadUrl({
                    bucketId: 'd5afb20446dd61128b590419'
                }).then(tt => {
                    upl = tt.data.uploadUrl; 
                    authT = tt.data.authorizationToken;

                    b2.uploadFile({
                        uploadUrl: upl,
                        uploadAuthToken: authT,
                        fileName: randomUUID(),
                        contentLength: file.size,
                        mime: file.mimetype,
                        data: file.buffer,
                        hash: '',
                        onUploadProgress: (event) => {}
                    }).then(async fin => { await short_url.updateOne({ uuid: urls.uuid }, { $set: { thumbnail: encrypt(`https://f004.backblazeb2.com/file/ferrets/${fin.data.fileName}`), thumbnail_pro_id: fin.data.fileId } }); delete faviconCache[urls.id]; });
                });

                delete faviconCache[urls.id];
                res.json({ OK: true, status: 200, text: `Updated icon` });
            };
        });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: e });
    };
});

a.post('/v1/account/settings/email', async function (req, res) {
    let { session } = req.cookies;
    let { currentEmail_vr, newEmail_vr } = req.body;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    let u = await user.findOne({ session }).lean();
    let chcE = await user.find({  }, { name: 1, uuid: 1, email: 1, signin_id: 1 }).lean();
    chcE = chcE.map((h) => { if (decrypt(h.email) == newEmail_vr.toLowerCase() && h.signin_id == cryptojs.MD5(newEmail_vr.toLowerCase()).toString().slice(24)) return h })[0];
    if (decrypt(u.email) !== currentEmail_vr.toLowerCase()) return res.status(400).json({ OK: false, status: 400, error: `Please enter your current email address` });
    if (decrypt(u.email) == newEmail_vr.toLowerCase()) return res.status(403).json({ OK: false, status: 403, error: `You can not change your email to the same email address!` });
    if (decrypt(u.email).includes('@ferret.page')) return res.status(403).json({ OK: false, status: 403, error: `You can not change the email to a staff account.` });
    if (chcE) return res.status(403).json({ OK: false, status: 403, error: `E-Mail is already taken` });

    let confT = Math.random().toString(32).substring(4).toUpperCase();
    await new verify_email({
        uuid: u.uuid,
        email: encrypt(newEmail_vr.toLowerCase()),
        token: confT,
        used: false,
        valid: true,
        date: Date.now()
    }).save();

    let transporter = nodemailer.createTransport({
        host: "webserver4.pebblehost.com",
        port: 465,
        secure: true,
        auth: {
            user: "no-reply@ferret.page",
            pass: `${process.env.PASSWORD}`,
        },
    });

    let msg = {
        from: '"no-reply@ferret.page" <no-reply@ferret.page>',
        to: `${newEmail_vr.toLowerCase()}`,
        subject: "Verify new E-Mail Address",
        html: `<html><h4>Hello ${u.name}!</h4></br><h3>Here is your verification code: ${confT}</h3><br></html>`, // html body
    };
    let msg2 = {
        from: '"no-reply@ferret.page" <no-reply@ferret.page>',
        to: `${currentEmail_vr.toLowerCase()}`,
        subject: "User E-Mail address changed",
        html: `<html><h4>Hello ${u.name}!</h4></br><h3>It seems like your email address was changed to a different one. If you did not do this then please contact support: (${randomUUID()})</h3><br></html>`, // html body
    };

    await user.updateOne({ session }, { $set: { email: encrypt(newEmail_vr.toLowerCase()), verified: false, signin_id: cryptojs.MD5(newEmail_vr.toLowerCase()).toString().slice(24) } });

    await new notification({
        author: u._id,
        from: u._id,
        text: `Your E-Mail address has been changed`,
        friendRequest: false,
        hidden: false,
        date: Date.now(),
        uuid: randomUUID()
    }).save();

    res.json({ OK: true, status: 200, text: `Set email to: '${encrypt(newEmail_vr.toLowerCase())}'` });
    const info = await transporter.sendMail(msg);
    const info2 = await transporter.sendMail(msg2);
});

a.post('/v1/account/settings/password', async function (req, res) {
    let { session } = req.cookies;
    let { currentPass_vr, newPass_vr } = req.body;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    let u = await user.findOne({ session }).lean();
    if (decrypt(u.password) !== currentPass_vr) return res.status(400).json({ OK: false, status: 400, error: `Please enter your current password` });
    if (decrypt(u.password) == newPass_vr) return res.status(403).json({ OK: false, status: 403, error: `You can not change your password to the same password!` });

    await user.updateOne({ session }, { $set: { password: encrypt(newPass_vr) } });

    await new notification({
        author: u._id,
        from: u._id,
        text: `Your password has been changed`,
        friendRequest: false,
        hidden: false,
        date: Date.now(),
        uuid: randomUUID()
    }).save();

    res.json({ OK: true, status: 200, text: `Set password to: '${encrypt(newPass_vr)}'` });
});

a.post('/v1/account/settings/delete_account', async function (req, res) {
    let { session } = req.cookies;
    let { delete_hc, TFA_hc } = req.body;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    if (!delete_hc || delete_hc !== "on") return res.status(403).json({ OK: false, status: 403, error: `Please confirm account deletion` });
    
    let u = await user.findOne({ session }).lean();
    if (!u) return res.status(404).json({ OK: false, status: 404, error: `Account not found` });
    if (u.TFA && !TFA_hc) return res.status(404).json({ OK: false, status: 404, error: `Account has 2FA enabled` });
    if (u.TFA) {
        let verify = authenticator.verifyToken(decrypt(u.google_backup), `${TFA_hc}`);
        if (!verify) return res.status(403).json({ OK: false, error: `Invalid Code` });
    };
    let confT = Math.random().toString(32).substring(4).toUpperCase();
    await new tokens({
        token: confT,
        user: u.uuid,
        valid: true,
        uuid: randomUUID(),
        date: Date.now()
    }).save();
    u.email = decrypt(u.email);

    let transporter = nodemailer.createTransport({
        host: "webserver4.pebblehost.com",
        port: 465,
        secure: true,
        auth: {
            user: "no-reply@ferret.page",
            pass: `${process.env.PASSWORD}`,
        },
    });

    let msg = {
        from: '"no-reply@ferret.page" <no-reply@ferret.page>',
        to: `${u.email}`,
        subject: "Verify Account Deletion",
        html: `<html><h4>Hello @${u.name}!</h4></br><h3>Here is your deletion code: <a href="${req.protocol}://${req.hostname}/api/v1/account/settings/delete_account?code=${confT}" target="_blank">${confT}</a></h3><br><br><p>If you did not request to delete this account please ignore this<br></p></html>`, // html body
    };

    const info = await transporter.sendMail(msg);
    res.json({ OK: true, status: 200, text: `User has started account deletion request` });
});

a.get('/v1/account/settings/delete_account', async function (req, res) {
    let { session } = req.cookies;
    let { code } = req.query;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    if (!code) return res.status(403).json({ OK: false, status: 403, error: `This endpoint required a code` });
    
    let u = await user.findOne({ session }).lean();
    if (!u) return res.status(404).json({ OK: false, status: 404, error: `Account not found` });

    let t = await tokens.findOne({ user: u.uuid, token: code, valid: true }).lean();
    if (!t) return res.status(404).json({ OK: false, status: 404, error: `Code not found` });

    await notification.deleteMany({ author: u._id });
    await sessions.deleteOne({ uuid: u.uuid });

    await user.updateOne({ session }, { $set: { email: encrypt(randomUUID()), password: encrypt(randomUUID()), apiKey: encrypt(randomUUID()), session: encrypt(randomUUID()), blocked: true, hidden: true } });
    
    res.clearCookie('session');
    res.json({ OK: true, status: 200, text: `User has been deleted` });
});

a.post('/v1/account/settings/add_account', async function (req, res) {
    let { session } = req.cookies;
    let { email_HC, password_HC, TFA_HC } = req.body;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    let u = await user.findOne({ session }).populate([{ path:"connectedUser.user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, hcverified: 1, hidden: 1, flag: 1} }]).lean();
    if (!u) return res.status(403).json({ OK: false, status: 403, error: `Invalid Authentication` });
    if (!u.pro) return res.status(403).json({ OK: false, status: 403, error: `Must be a Upgraded account to access this endpoint` });

    let con = false;
    let chck = await user.find({  }).populate([{ path:"connectedUser.user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, hcverified: 1, hidden: 1, flag: 1} }]).lean();
    chck.forEach(elm => {
        if (elm && decrypt(elm.email) == email_HC.toLowerCase()) chck = elm;
    });
    if (chck && chck[0]) return res.status(403).json({ OK: false, status: 403, error: `Account does not exist with that E-Mail` });
    if (password_HC !== decrypt(chck.password)) return res.status(403).json({ OK: false, status: 403, error: `Incorrect Password` });
    if (!TFA_HC && chck.TFA) return res.status(403).json({ OK: false, status: 403, error: `Incorrect 2FA Code` });
    if (chck.TFA) {
        let verify = authenticator.verifyToken(decrypt(chck.google_backup), TFA_HC);
        if (!verify) return res.status(403).json({ OK: false, status: 403, error: `Incorrect 2FA Code` });
    };
    if (decrypt(u.email) == decrypt(chck.email)) return res.status(403).json({ OK: false, status: 403, error: `You can not connect your account to the same account` });

    if (chck.connectedUser && chck.connectedUser.length > 0) {
        chck.connectedUser.forEach(elm => {
            if (u.uuid == elm.user.uuid) con = true
        });
        if (con) return res.status(403).json({ OK: false, status: 403, error: `User is already connected to this account` });
    };

    await user.updateOne({ uuid: chck.uuid }, { $push: { connectedUser: [{ user: u._id, uuid: randomUUID(), date: Date.now() }] } });
    await user.updateOne({ uuid: chck.uuid }, { $set: { pro: true, linklimit: "50" } });
    await user.updateOne({ session }, { $push: { connectedUser: [{ user: chck._id, uuid: randomUUID(), date: Date.now() }] } });

    res.json({ OK: true, status: 200, text: `Connected User` });
});

a.get('/v1/account/settings/switch_account', async function (req, res) {
    let { session } = req.cookies;
    if (!req.query.uuid) return res.status(403).json({ OK: false, status: 403, error: `Please specify uuid` });
    if (req.query.uuid == "") return res.status(403).json({ OK: false, status: 403, error: `Please specify uuid` });

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    let u = await user.findOne({ session }).populate([{ path:"connectedUser.user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, session: 1, hcverified: 1, hidden: 1, flag: 1} }]).lean();
    if (!u) return res.status(403).json({ OK: false, status: 403, error: `Invalid Authentication` });
    if (!u.pro) return res.status(403).json({ OK: false, status: 403, error: `Must be a Upgraded account to access this endpoint` });
    if (u.connectedUser.length < 1) return res.status(403).json({ OK: false, status: 403, error: `This user does not have any connected users` });

    let con = null;
    u.connectedUser.forEach(elm => {
        if (elm.user.uuid == req.query.uuid) con = elm;
    });

    if (!con) return res.status(403).json({ OK: false, status: 403, error: `Invalid UUID` });
    if (con.TFA) return res.status(403).json({ OK: false, status: 403, error: `User has 2FA enabled` });

    let Nsession = randomUUID();
    let token = randomUUID();

    await sessions.updateOne({ uuid: u.uuid }, { $push: { sessions: [{ token, date: Date.now(), ip: encrypt(req.headers['x-forwarded-for']), logout: true }] } });
    await user.updateOne({ uuid: u.uuid }, { $set: { session: token } });

    await sessions.updateOne({ uuid: con.user.uuid }, { $push: { sessions: [{ token: Nsession, date: Date.now(), ip: encrypt(req.headers['x-forwarded-for']) }] } });
    await user.updateOne({ uuid: con.user.uuid }, { $set: { session: Nsession, last_login: Date.now() } });

    res.cookie('session', Nsession);
    if (req.query.auto && req.query.auto == "true") return res.redirect(`/settings/switch_account`);
    res.json({ OK: true, status: 200, text: `Switched User` });
});

a.get('/v1/account/settings/remove_account', async function (req, res) {
    let { session } = req.cookies;
    if (!req.query.uuid) return res.status(403).json({ OK: false, status: 403, error: `Please specify uuid` });
    if (req.query.uuid == "") return res.status(403).json({ OK: false, status: 403, error: `Please specify uuid` });

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    let u = await user.findOne({ session }).populate([{ path:"connectedUser.user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, session: 1, hcverified: 1, hidden: 1, flag: 1} }]).lean();
    if (!u) return res.status(403).json({ OK: false, status: 403, error: `Invalid Authentication` });
    if (!u.pro) return res.status(403).json({ OK: false, status: 403, error: `Must be a Upgraded account to access this endpoint` });
    if (u.connectedUser.length < 1) return res.status(403).json({ OK: false, status: 403, error: `This user does not have any connected users` });

    let con = null;
    u.connectedUser.forEach(elm => {
        if (elm.user.uuid == req.query.uuid) con = elm;
    });

    if (!con) return res.status(403).json({ OK: false, status: 403, error: `Invalid UUID` });
    if (con.TFA) return res.status(403).json({ OK: false, status: 403, error: `User has 2FA enabled` });

    await user.updateOne({ uuid: u.uuid }, { $pull: { connectedUser: { user: con.user._id } } });
    await user.updateOne({ uuid: con.user.uuid }, { $pull: { connectedUser: { user: u._id } } });

    if (req.query.auto && req.query.auto == "true") return res.redirect(`/settings/switch_account`);
    res.json({ OK: true, status: 200, text: `Removed User` });
});

a.post('/v1/account/purchases/gift/:id', async function (req, res) {
    let { session } = req.cookies;
    let { name_vr } = req.body;

    if (!name_vr) return res.status(404).json({ OK: false, status: 404, error: `Please specify a user` });

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    let u = await user.findOne({ session }).populate([{ path:"connectedUser.user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, hcverified: 1, hidden: 1, flag: 1} }]).lean();
    if (!u) return res.status(403).json({ OK: false, status: 403, error: `Invalid Authentication` });

    let rec = await receipt.findOne({ gift_from: u._id, receipt: req.params.id.toUpperCase(), user: null }).lean();
    if (!rec) return res.status(403).json({ OK: false, status: 403, error: `Invalid Gift` });

    let sendto = await user.findOne({ nameToFind: name_vr.toUpperCase() }, { _id: 1, uuid: 1, name: 1, displayName: 1, pfp: 1, blocked: 1, hidden: 1, pro: 1, subdomain: 1 }).lean();
    if (!sendto) return res.status(404).json({ OK: false, status: 404, error: `Could not find user: ${name_vr}` });
    if (sendto.blocked) return res.status(403).json({ OK: false, status: 403, error: `Could not find user: ${name_vr}` });
    if (sendto.pro && rec.pro) return res.status(403).json({ OK: false, status: 403, error: `${sendto.displayName} already has this plan enabled` });
    if (sendto.subdomain && rec.subdomain) return res.status(403).json({ OK: false, status: 403, error: `${sendto.displayName} already has this plan enabled` });

    await receipt.updateOne({ uuid: rec.uuid }, { $set: { user: sendto._id } });

    res.json({ OK: true, status: 200, text: `Sent gift to: ${sendto.displayName} (@${sendto.name})` });
});

a.get('/v1/redeem', async function (req, res) {
    let { session } = req.cookies;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    let u = await user.findOne({ session }).populate([{ path:"connectedUser.user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, hcverified: 1, hidden: 1, flag: 1} }]).lean();
    if (!u) return res.status(403).json({ OK: false, status: 403, error: `Invalid Authentication` });

    res.json({ OK: false, status: 404, error: `Please specify a gift code` });
});

a.get('/v1/redeem/:id', async function (req, res) {
    let { session } = req.cookies;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    let u = await user.findOne({ session }).populate([{ path:"connectedUser.user", select: {displayName: 1, name: 1, email: 1, pfp: 1, uuid: 1, hcverified: 1, hidden: 1, flag: 1} }]).lean();
    if (!u) return res.status(403).json({ OK: false, status: 403, error: `Invalid Authentication` });

    let rec = await receipt.findOne({ uuid: req.params.id, user: null, valid: true }).lean();
    if (!rec) return res.status(403).json({ OK: false, status: 403, error: `Invalid Gift Code` });

    let sendto = await user.findOne({ uuid: u.uuid }, { _id: 1, uuid: 1, name: 1, displayName: 1, pfp: 1, blocked: 1, hidden: 1, pro: 1, subdomain: 1 }).lean();
    if (!sendto) return res.status(404).json({ OK: false, status: 404, error: `Could not find user: ${u.name}` });
    if (sendto.blocked) return res.status(403).json({ OK: false, status: 403, error: `Could not find user: ${name_vr}` });
    if (sendto.pro && rec.pro) return res.status(403).json({ OK: false, status: 403, error: `${sendto.displayName} already has this plan enabled` });
    if (sendto.subdomain && rec.subdomain) return res.status(403).json({ OK: false, status: 403, error: `${sendto.displayName} already has this plan enabled` });

    await receipt.updateOne({ uuid: rec.uuid }, { $set: { user: sendto._id } });
    if (rec.badge && rec.receipt.split('-')[1]) {
        await badge.updateOne({ badge: rec.receipt.split('-')[1] }, { $push: { users: { user: sendto._id, disabled: false, date: Date.now() } } });
        return res.json({ OK: true, status: 200, text: `Redeemed User Badge` });
    };

    res.json({ OK: true, status: 200, text: `Added $${rec.amount} to your balance` });
});

a.get('/account/create_auth', async function (req, res) {
    let { session } = req.cookies;

    try {
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

        let u = await user.findOne({ session }).lean();
        if (u.TFA) return res.status(403).json({ OK: false, status: 403, error: "Account already has 2FA enabled" });

        var formattedKey = authenticator.generateKey();

        var qr = authenticator.generateTotpUri(formattedKey, `${u.name}`, "ferret.page", 'SHA1', 6, 30);
        if (!qr) return res.status(500).json({ OK: false, error: `Could not load QR Image` });
        QRCode.toDataURL(qr, function (err, url) {
            var img = Buffer.from(url.split('base64,')[1], 'base64');
            res.writeHead(200, {
                'Content-Type': `image/png`,
                'Content-Length': img.length
            });
            res.end(img);
        });
        await user.updateOne({ session }, { $set: { google_backup: encrypt(formattedKey) } });
        // res.json({ OK: true, text: `OK` });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: `${e}` });
    };
});

a.get('/account/verify_auth', async function (req, res) {
    let { session } = req.cookies;

    try {
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

        let u = await user.findOne({ session }).lean();
        if (u.TFA) return res.status(403).json({ OK: false, status: 403, error: "Account already has 2FA enabled" });

        if (!u.google_backup) return res.status(403).json({ OK: false, status: 403, error: "Account does not have verification token. Contact support" });
        let verify = authenticator.verifyToken(decrypt(u.google_backup), `${req.query.code}`);
        if (!verify) return res.status(403).json({ OK: false, error: `Invalid Code` });
        if (!u.TFA) {
            await user.updateOne({ session }, { $set: { TFA: true } });
            await badge.updateOne({ id: '35d071f4-0504-4e10-90ef-42c582b24817' }, { $push: { users: [{ user: u._id, date: Date.now(), disabled: true }] } });
            res.json({ OK: true, text: `Added 2FA to your account!` });
            await new notification({
                author: u._id,
                from: u._id,
                text: `2FA has been added to your account`,
                friendRequest: false,
                hidden: false,
                date: Date.now(),
                uuid: randomUUID()
            }).save();
            return
        }

        res.json({ OK: true, text: `Sucessfully Authenticated` });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: `${e}` });
    };
});

a.post('/v1/account/settings/2fa', async function (req, res) {
    let { session } = req.cookies;
    let { OAuth_vr } = req.body;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, false);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    if (!OAuth_vr) return res.status(400).json({ OK: false, status: 400, error: `Please input 2FA code` });

    let u = await user.findOne({ session }).lean();
    if (!u.TFA) return res.status(403).json({ OK: false, status: 403, error: "Account does not have 2FA enabled" });

    let verify = authenticator.verifyToken(decrypt(u.google_backup), OAuth_vr);
    if (!verify) return res.status(403).json({ OK: false, error: `Invalid Code` });
    await user.updateOne({ session }, { $set: { TFA: false, google_backup: "" } });
    await badge.updateOne({ id: '35d071f4-0504-4e10-90ef-42c582b24817' }, { $pull: { users: { uuid: u.uuid } } });

    await new notification({
        author: u._id,
        from: u._id,
        text: `2FA has been removed from your account`,
        friendRequest: false,
        hidden: false,
        date: Date.now(),
        uuid: randomUUID()
    }).save();
    res.json({ OK: true, status: 200, text: `Removed 2FA on your account` });
});

a.get('/admin/reserved/:name', async function (req, res) {
    let { session } = req.cookies;

    try {
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

        if (!req.params.name && req.query.name) {
            let is = await misc.findOne({ uuid: "a09ddcc5-0e36-4dc2-bb36-dc59959c114f", "reserved.name": req.params.name.toLowerCase() }).lean();
            if (!is) return res.sendStatus(403);
            res.json({ OK: true, invite: is.invite });
        }

        let invite = Math.random().toString(32).substring(4).toUpperCase();
        let is = await misc.findOne({ uuid: "a09ddcc5-0e36-4dc2-bb36-dc59959c114f", "reserved.name": req.params.name.toLowerCase() }).lean();
        if (is) return res.sendStatus(403);
        await misc.updateOne({ uuid: "a09ddcc5-0e36-4dc2-bb36-dc59959c114f" }, { $push: { reserved: [{ name: req.params.name.toLowerCase(), invite: encrypt(invite), uuid: randomUUID() }] } });

        res.json({ OK: true, text: `Sucessfully Reserved` });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: `${e}` });
    };
});

a.get('/admin/link/:domain', async function (req, res) {
    let { session } = req.cookies;
    let { warn, blocked } = req.query;

    try {
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

        let warn2 = false;
        let blocked2 = false;
        if (warn && warn == 'true') warn2 = true;
        if (blocked && blocked == 'true') blocked2 = true;
        if (!warn2 && !blocked2) return res.sendStatus(403);
        let is = await misc.findOne({ uuid: "f23b87dc-7c61-4a9e-8f7d-998b649f3614", "links.url": req.params.domain.toLowerCase() }).lean();
        if (is) return res.sendStatus(403);
        await misc.updateOne({ uuid: "f23b87dc-7c61-4a9e-8f7d-998b649f3614" }, { $push: { links: { url: req.params.domain.toLowerCase(), warn: warn2, blocked: blocked2 } } });

        res.json({ OK: true, text: `Sucessfully Added Domain to List` });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: `${e}` });
    };
});

a.get('/admin/reserved', async function (req, res) {
    let { session } = req.cookies;

    try {
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

        if (!req.query.name) return res.sendStatus(404);

        let is = await misc.findOne({ uuid: "a09ddcc5-0e36-4dc2-bb36-dc59959c114f", "reserved.name": req.query.name.toLowerCase() }).lean();
        if (!is) return res.sendStatus(403);

        is.reserved.forEach(elm => {
            if (req.query.name.toLowerCase() == elm.name.toLowerCase()) is = elm;
        });

        res.json({ OK: true, invite: decrypt(is.invite), encrpyted: is.invite });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: `${e}` });
    };
});

a.get('/admin/remove_views/:name', async function (req, res) {
    let { session } = req.cookies;
    let { unix } = req.query;
    let { name } = req.params;

    try {
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

        if (!unix || !name) return res.sendStatus(404);

        let u = await user.findOne({ nameToFind: name.toUpperCase() }).lean();
        if (!u) return res.status(404).json({ OK: false, status: 404, error: `User not found` });
        if (u.blocked) return res.status(404).json({ OK: false, status: 403, error: `User is blocked` });

        u.views.forEach(async elm => {
            if (unix < new Date(elm.date).valueOf()) await user.updateOne({ uuid: u.uuid }, { $pull: { views: { uuid: elm.uuid } } });
        });

        res.json({ OK: true, status: 200 });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: `${e}` });
    };
});

a.post('/admin/account/edit', async function (req, res) {
    let { session } = req.cookies;
    let { display_vr, name_vr, bio_vr, location_vr, pronouns_vr, darktheme_vr, border_vr } = req.body;
    let { uuid } = req.query;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

    if (!uuid) return res.status(403).json({ OK: false, status: 403, error: `You must specify a UUID` });
    if (!name_vr) return res.status(403).json({ OK: false, status: 403, error: `You must have a username` });

    let acc = await user.findOne({ uuid }).lean();
    let char = /^[a-zA-Z0-9_]+$/;
    let darktheme = "";

    if (!display_vr) {
        await user.updateOne({ uuid }, { $set: { displayName: acc.name } });
        res.json({ OK: true, status: 200, status: "Set display name to: None" });
        return
    };

    if (display_vr) {
        if (display_vr.length > 28) return res.status(403).json({ OK: false, status: 403, error: `Invalid length: ${display_vr.length}/28` });
        // if (!char.test(display_vr)) return res.status(403).json({ OK: false, status: 403, error: `Invalid Display Name` });
        if (acc.ogname) {
            if (!display_vr.includes(' ') && display_vr.toUpperCase() !== acc.nameToFind) return res.status(403).json({ OK: false, status: 403, error: `Display name must include username` });

            let splitName = display_vr.split(' ');
            let isname = false;
            splitName.forEach(elm => {
                if (elm.toUpperCase() == acc.nameToFind) isname = true;
            });

            if (!isname) return res.status(403).json({ OK: false, status: 403, error: `Display name must include username` });
        }

        await user.updateOne({ uuid }, { $set: { displayName: display_vr } });
    };

    if (name_vr && acc.nameToFind !== name_vr.toUpperCase()) {
        name_vr = encodeURIComponent(name_vr);

        if (!char.test(name_vr)) return res.status(403).json({ OK: false, status: 403, error: `Invalid regex form` });

        if (name_vr.length < 2) return res.status(400).json({ OK: false, status: 400, error: `Username must be greater than 2 characters` });
        if (name_vr.length > 15) return res.status(400).json({ OK: false, status: 400, error: `Username must be less than 16 characters` });
        
        let checkname = await user.findOne({ nameToFind: name_vr.toUpperCase(), hidden: false }, { uuid: 1 }).lean();
        if (checkname) return res.status(403).json({ OK: false, status: 403, error: `Username is already taken` });

        await user.updateOne({ uuid }, { $set: { name: name_vr, nameToFind: name_vr.toUpperCase() } });
        await user.updateOne({ uuid }, { $push: { nameHistory: [{ name: name_vr, date: Date.now(), hidden: false, uuid: randomUUID() }] } });
    };

    if (bio_vr && bio_vr.length > 95) return res.status(400).json({ OK: false, status: 400, error: `Bio must be less than 96 characters` });
    if (location_vr.length > 57) return res.status(400).json({ OK: false, status: 400, error: `Location must be less than 58 characters` });

    let pronoun = { hh: "he/him", hi: "he/it", hs: "he/she", ht: "he/they", ih: "it/him", ii: "it/its", is: "it/she", it: "it/they", shh: "she/he", sh: "she/her", si: "she/it", st: "she/they", th: "they/he", ti: "they/it", ts: "they/she", tt: "they/them", any: "Any pronouns", other: "Other pronouns", ask: "Please ask", avoid: "Avoid pronouns" };
    if (!pronouns_vr) pronoun = null;
    if (pronouns_vr == "Unspecified...") pronoun = null;
    if (pronouns_vr && pronoun && !pronoun[pronouns_vr.toLowerCase()]) pronoun = null;
    if (pronouns_vr && pronoun && pronoun[pronouns_vr.toLowerCase()]) pronoun = pronoun[pronouns_vr.toLowerCase()];

    let pBorder = 'none';
    let crossBorder = { "lesbian": "lesbian", "gay": "gay", "bisexual": "bisexual", "trans": "trans", "queer": "queer", "intersex": "intersex", "asexual": "asexual", "agender": "agender", "aroace": "aroace", "aromantic": "aromantic", "nonbinary": "nonbinary", "polyamorous": "polyamorous", "poly": "poly", "gaymale": "gaymale", "gayfemale": "gayfemale", "genderqueer": "genderqueer", "omni": "omni", "ally": "ally" };
    if (border_vr && crossBorder[border_vr.toLowerCase()]) {
        pBorder = border_vr.toLowerCase();
    };

    if (location_vr.length < 1) {
        location_vr = "";
    }
    if (acc.pro && darktheme_vr == "on") darktheme = "dark";
    await user.updateOne({ uuid }, { $set: { location: encrypt(location_vr), bio: encrypt(bio_vr), pronouns: pronoun, theme: darktheme, personal_border: pBorder } });

    res.json({ OK: true, status: 200, status: `Updated profile` });
});

a.post('/admin/account/edit/avatar', async function (req, res) {
    let { session } = req.cookies;
    let { uuid } = req.query;

    try {
        if (!session) return res.status(403).json({ OK: false, error: `Invalid session` });
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });
        var up = upload.single('pfp');

        let u = await user.findOne({ uuid }).lean();

        up(req, res, async function (e) {
            if (e) console.log(e);
            if (e) return res.status(500).json({ OK: false, error: `${e}` });
            if (!e) {
                let file = null;
                let fileExtension = null;
                let upl = null;
                let authT = null;
                if (req.file) file = req.file;
                if (req.file) fileExtension = req.file.originalname.match(/\.(jpg|JPG|jpeg|JPEG|png|PNG|gif|GIF)$/);
                if (fileExtension) fileExtension = fileExtension[0];

                if (!file) {
                    let current = u.pfp;

                    if (current !== "https://f004.backblazeb2.com/file/ferrets/user_avatar/default_avatar.png") {
                        b2.getFileInfo({
                            fileId: u.pfp_id
                        }).then(async tt => {
                            let data = tt.data;

                            b2.deleteFileVersion({
                                fileId: data.fileId,
                                fileName: data.fileName
                            });
                            await user.updateOne({ uuid }, { $set: { pfp: `https://f004.backblazeb2.com/file/ferrets/user_avatar/default_avatar.png`, pfp_id: "4_zd5afb20446dd61128b590419_f106e64e803b29f2b_d20221230_m174015_c004_v0402001_t0028_u01672422015619" } });
                            delete avatarCache[u.uuid];
                        });
                    };
                    return res.json({ OK: true, status: 200, text: `Updated avatar` });
                }

                if (file && file.mimetype !== "image/gif") {
                    await sharp(file.buffer).resize({ width: 256, height: 256 }).toBuffer().then(data => {
                        if (data) file.buffer = data; file.size = data.length;
                    });
                };

                if (u.pfp !== "https://f004.backblazeb2.com/file/ferrets/user_avatar/default_avatar.png") {
                    b2.getFileInfo({
                        fileId: u.pfp_id
                    }).then(async tt => {
                        let data = tt.data
                        b2.deleteFileVersion({
                            fileId: data.fileId,
                            fileName: data.fileName
                        });
                    });
                };

                b2.getUploadUrl({
                    bucketId: 'd5afb20446dd61128b590419'
                }).then(tt => {
                    upl = tt.data.uploadUrl; 
                    authT = tt.data.authorizationToken;

                    b2.uploadFile({
                        uploadUrl: upl,
                        uploadAuthToken: authT,
                        fileName: randomUUID(),
                        contentLength: file.size,
                        mime: file.mimetype,
                        data: file.buffer,
                        hash: '',
                        onUploadProgress: (event) => {}
                    }).then(async fin => { await user.updateOne({ uuid }, { $set: { pfp: `https://f004.backblazeb2.com/file/ferrets/${fin.data.fileName}`, pfp_id: fin.data.fileId } }); delete avatarCache[u.uuid]; });
                });

                res.json({ OK: true, status: 200, text: `Updated avatar` });
            };
        });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: e });
    };
});

a.post('/admin/account/edit/banner', async function (req, res) {
    let { session } = req.cookies;
    let { uuid } = req.query;

    try {
        if (!session) return res.status(403).json({ OK: false, error: `Invalid session` });
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });
        var up = upload.single('banner');

        let u = await user.findOne({ uuid }).lean();

        up(req, res, async function (e) {
            if (e) console.log(e);
            if (e) return res.status(500).json({ OK: false, error: `${e}` });
            if (!e) {
                let file = null;
                let fileExtension = null;
                let upl = null;
                let authT = null;
                if (req.file) file = req.file;
                if (req.file) fileExtension = req.file.originalname.match(/\.(jpg|JPG|jpeg|JPEG|png|PNG|gif|GIF)$/);
                if (fileExtension) fileExtension = fileExtension[0];

                if (!file) {
                    let current = u.banner;

                    if (current !== "") {
                        b2.getFileInfo({
                            fileId: u.banner_id
                        }).then(async tt => {
                            let data = tt.data;

                            b2.deleteFileVersion({
                                fileId: data.fileId,
                                fileName: data.fileName
                            });
                        });
                    };
                    delete bannerCache[u.uuid];
                    await user.updateOne({ uuid }, { $set: { banner: "", banner_id: "" } });
                    return res.json({ OK: true, status: 200, text: `Updated banner` });
                }

                if (file && file.mimetype !== "image/gif") {
                    await sharp(file.buffer).resize({ width: 350, height: 150 }).toBuffer().then(data => {
                        if (data) file.buffer = data; file.size = data.length;
                    });
                };

                if (u.banner !== "") {
                    b2.getFileInfo({
                        fileId: u.banner_id
                    }).then(async tt => {
                        let data = tt.data
                        b2.deleteFileVersion({
                            fileId: data.fileId,
                            fileName: data.fileName
                        });
                    });
                };

                b2.getUploadUrl({
                    bucketId: 'd5afb20446dd61128b590419'
                }).then(tt => {
                    upl = tt.data.uploadUrl; 
                    authT = tt.data.authorizationToken;

                    b2.uploadFile({
                        uploadUrl: upl,
                        uploadAuthToken: authT,
                        fileName: randomUUID(),
                        contentLength: file.size,
                        mime: file.mimetype,
                        data: file.buffer,
                        hash: '',
                        onUploadProgress: (event) => {}
                    }).then(async fin => { await user.updateOne({ uuid }, { $set: { banner: `https://f004.backblazeb2.com/file/ferrets/${fin.data.fileName}`, banner_id: fin.data.fileId } }) });
                });

                delete bannerCache[u.uuid];
                res.json({ OK: true, status: 200, text: `Updated banner` });
            };
        });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: e });
    };
});

a.post('/admin/receipt/:uuid', async function (req, res) {
    let { session } = req.cookies;
    let { uuid } = req.params;
    let { type_vr, years_vr } = req.body;

    try {
        if (!session) return res.status(403).json({ OK: false, error: `Invalid session` });
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

        if (!type_vr) return res.status(403).json({ OK: false, status: 403, error: `Missing fields` });
        if (type_vr.toLowerCase() == 'badge' && !req.query.badge) return res.status(403).json({ OK: false, status: 403, error: `Missing fields` });

        let s = await user.findOne({ session }, { nameHistory: 0, email: 0, password: 0, pfp: 0, pfp_id: 0, banner: 0, banner_id: 0, recEmail: 0, apiKey: 0, bio: 0, url: 0, location: 0, reason: 0, linkLimit: 0, links: 0, views: 0, verified: 0, vrverified: 0, ogname: 0, pro: 0, pronouns: 0, hidden: 0, createdIP: 0, createdAt: 0, last_login: 0, connectedUser: 0, __v: 0, google_backup: 0, theme: 0, personal_border: 0, fonts: 0, socials: 0, signin_id: 0, subdomain: 0 }).lean();
        let u = await user.findOne({ uuid }, { nameHistory: 0, email: 0, password: 0, pfp: 0, pfp_id: 0, banner: 0, banner_id: 0, recEmail: 0, apiKey: 0, bio: 0, url: 0, location: 0, reason: 0, linkLimit: 0, links: 0, views: 0, verified: 0, vrverified: 0, ogname: 0, pronouns: 0, hidden: 0, createdIP: 0, createdAt: 0, last_login: 0, connectedUser: 0, __v: 0, google_backup: 0, theme: 0, personal_border: 0, fonts: 0, socials: 0, signin_id: 0 }).lean();

        if (!u) return res.status(404).json({ OK: false, status: 404, error: `Invalid UUID` });
        if (u.blocked) return res.status(403).json({ OK: false, status: 403, error: `This user is blocked` });

        let ispro = false;
        let isproplus = false;
        let issubdomain = false;
        let iscustomdomain = false;
        let isbadge = false;
        let iscredit = false;
        let camount = '0';
        let token = Math.random().toString(32).substring(5).toUpperCase();
        if (type_vr.toLowerCase() == 'pro') ispro = true;
        if (type_vr.toLowerCase() == 'subdomain') issubdomain = true;
        if (type_vr.toLowerCase() == 'credit') iscredit = true;
        if (type_vr.toLowerCase() == 'credit' && years_vr) { camount = years_vr; if (!camount.includes('.')) camount = `${camount}.00`; };
        if (type_vr.toLowerCase() == 'badge') isbadge = true;

        let yr = new Date().setFullYear(new Date().getFullYear()+1);
        if (years_vr && !isNaN(years_vr) && years_vr > 0 && years_vr < 251) yr = new Date().setFullYear(new Date().getFullYear()+parseInt(years_vr));
        if (type_vr.toLowerCase() == 'credit') yr = null;

        if (isbadge && req.query.badge) token = `${token}-${req.query.badge}`;

        new receipt({
            user: null,
            receipt: token,
            pro: ispro,
            pro_plus: isproplus,
            subdomain: issubdomain,
            customdomain: iscustomdomain,
            badge: isbadge,
            credit: iscredit,
            gift: true,
            admin_gift: false,
            gift_from: u._id,
            amount: camount,
            valid_until: yr,
            valid: true,
            uuid: randomUUID(),
            date: Date.now()
        }).save();

        res.json({ OK: true, status: 200, text: `Created receipt: ${token}` });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: e });
    };
});

a.post('/admin/account/credits/:uuid', async function (req, res) {
    let { session } = req.cookies;
    let { uuid } = req.params;
    let { cred_vr } = req.body;

    try {
        if (!session) return res.status(403).json({ OK: false, error: `Invalid session` });
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

        if (!cred_vr) return res.status(403).json({ OK: false, status: 403, error: `Missing fields` });

        let u = await user.findOne({ uuid }, { nameHistory: 0, email: 0, password: 0, pfp: 0, pfp_id: 0, banner: 0, banner_id: 0, recEmail: 0, apiKey: 0, bio: 0, url: 0, location: 0, reason: 0, linkLimit: 0, links: 0, views: 0, verified: 0, vrverified: 0, ogname: 0, pronouns: 0, hidden: 0, createdIP: 0, createdAt: 0, last_login: 0, connectedUser: 0, __v: 0, google_backup: 0, theme: 0, personal_border: 0, fonts: 0, socials: 0, signin_id: 0 }).lean();

        if (!u) return res.status(404).json({ OK: false, status: 404, error: `Invalid UUID` });
        if (u.blocked) return res.status(403).json({ OK: false, status: 403, error: `This user is blocked` });

        if (!cred_vr.includes('.')) cred_vr = `${cred_vr}.00`;
        if (cred_vr.includes('-')) cred_vr = `0.00`;
        let camount = cred_vr;
        if (cred_vr > 0) cred_vr = `${parseInt(u.credit)+parseInt(cred_vr)}.00`;

        await user.updateOne({ uuid }, { $set: { credit: cred_vr } });
        if (cred_vr > 0) {
            new receipt({
                user: u._id,
                receipt: Math.random().toString(32).substring(5).toUpperCase(),
                pro: false,
                pro_plus: false,
                subdomain: false,
                customdomain: false,
                badge: false,
                credit: true,
                gift: false,
                admin_gift: true,
                gift_from: null,
                amount: camount,
                valid_until: null,
                valid: true,
                uuid: randomUUID(),
                date: Date.now()
            }).save();
        };

        res.json({ OK: true, status: 200, text: `New credit amount: $${cred_vr}` });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: e });
    };
});

a.get('/admin/remove_url/:uuid', async function (req, res) {
    let { session } = req.cookies;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });
    
    let urls = await short_url.findOne({ uuid: req.params.uuid }).populate([{ path:"author", select: {displayName: 1, name: 1, pfp: 1, uuid: 1, hcverified: 1, hidden: 1} }]).lean();
    if (!urls) return res.status(404).json({ OK: false, status: 404, error: `Could not find URL` });

    if (urls.thumbnail_pro_id !== "") {
        b2.getFileInfo({
            fileId: urls.thumbnail_pro_id
        }).then(async tt => {
            let data = tt.data
            b2.deleteFileVersion({
                fileId: data.fileId,
                fileName: data.fileName
            });
        });
    };

    delete faviconCache[urls.id];
    await short_url.deleteOne({ uuid: urls.uuid });
    res.json({ OK: true, status: 200, status: `Removed link` });
});

a.post('/admin/edit_url/:uuid', async function (req, res) {
    let { session } = req.cookies;
    let { title_vr, subtitle_vr, order_vr, url_vr, highlight_vr, limit_vr, llC } = req.body;

    let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
    if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });
    
    let u = await user.findOne({ uuid: req.params.uuid }).lean();
    if (!u) return res.status(404).json({ OK: false, status: 404, error: `User not found` });
    let urls = await short_url.findOne({ author: u._id, uuid: req.query.uuid }).populate([{ path:"author", select: {displayName: 1, name: 1, pfp: 1, uuid: 1, hcverified: 1, hidden: 1} }]).lean();
    if (!urls) return res.status(404).json({ OK: false, status: 404, error: `Could not find URL` });

    let title = title_vr;
    let stitle = subtitle_vr;
    let highlight = false
    let isLimit = urls.limitClicks;
    let isLimitNum = parseInt(urls.limitClick);
    let thumb = `https://t1.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=${url_vr}&size=128`;
    if (decrypt(urls.thumbnail).includes('backblazeb2.com')) thumb = decrypt(urls.thumbnail);

    if (!title) title = decrypt(urls.title);
    if (!url_vr) url_vr = decrypt(urls.link);

    let regex = /(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})/
    let url = regex.test(url_vr);
    let limitClicks = true;
    if (!llC) limitClicks = false;
    if (!url) return res.status(403).json({ OK: false, status: 403, error: `Invalid URL` });

    if (u.pro && highlight_vr && highlight_vr == "on") highlight = true;
    if (u.pro && limitClicks) {
        if (!isNaN(limit_vr)) {
            limit_vr = parseInt(limit_vr);
            if (limit_vr > 2500) return res.status(403).json({ OK: false, status: 403, error: `Upgrade plan to increase the click limit: ${limit_vr}/2500` });
            if (limit_vr < 1) return res.status(403).json({ OK: false, status: 403, error: `Click limit must be greater than 1: ${limit_vr}/2500` });
            isLimitNum = limit_vr;
        };
    };
    if (url_vr.includes('ferret.page')) thumb = "https://ferret.page/public/default.png";
    if (url_vr.includes('twitter.com')) thumb = "https://ferret.page/public/i/assets/twitter_normal.png";

    delete faviconCache[urls.id];
    await short_url.updateOne({ uuid: urls.uuid, blocked: false }, { $set: { title: encrypt(title), subtitle: encrypt(stitle), thumbnail: encrypt(thumb), order: parseInt(order_vr), link: encrypt(url_vr), highlight, limitClick: isLimitNum, limitClicks } });
    res.json({ OK: true, status: 200, text: `Updated link` });
});

a.post('/admin/edit_url/:uuid/icon', async function (req, res) {
    let { session } = req.cookies;

    try {
        if (!session) return res.status(403).json({ OK: false, error: `Invalid session` });
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });
        var up = upload.single('favicon');

        let u = await user.findOne({ uuid: req.params.uuid }).lean();
        if (!u) return res.status(403).json({ OK: false, status: 403, error: `User not found` });
        if (u.blocked) return res.status(403).json({ OK: false, status: 403, error: `User is blocked` });
        let urls = await short_url.findOne({ author: u._id, uuid: req.query.uuid }).populate([{ path:"author", select: {displayName: 1, name: 1, pfp: 1, uuid: 1, hcverified: 1, hidden: 1} }]).lean();
        if (!urls) return res.status(404).json({ OK: false, status: 404, error: `Could not find URL` });

        up(req, res, async function (e) {
            if (e) console.log(e);
            if (e) return res.status(500).json({ OK: false, error: `${e}` });
            if (!e) {
                let file = null;
                let fileExtension = null;
                let upl = null;
                let authT = null;
                if (req.file) file = req.file;
                if (req.file) fileExtension = req.file.originalname.match(/\.(jpg|JPG|jpeg|JPEG|png|PNG|gif|GIF)$/);
                if (fileExtension) fileExtension = fileExtension[0];

                if (!file) {
                    urls.link = decrypt(urls.link);
                    urls.thumbnail = decrypt(urls.thumbnail);
                    let current = urls.thumbnail;
                    let thumb = `https://t1.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=${urls.link}&size=128`;
                    if (urls.link.includes('ferret.page')) thumb = "https://ferret.page/public/default.png";
                    if (urls.link.includes('twitter.com')) thumb = "https://ferret.page/public/i/assets/twitter_normal.png";

                    if (current.includes('backblaze') && urls.thumbnail_pro_id !== "") {
                        b2.getFileInfo({
                            fileId: urls.thumbnail_pro_id
                        }).then(async tt => {
                            let data = tt.data;

                            b2.deleteFileVersion({
                                fileId: data.fileId,
                                fileName: data.fileName
                            });
                        });
                    };
                    delete faviconCache[urls.id];
                    await short_url.updateOne({ uuid: urls.uuid }, { $set: { thumbnail: encrypt(thumb), thumbnail_pro_id: "" } });
                    return res.json({ OK: true, status: 200, text: `Updated icon` });
                }

                if (file && file.mimetype !== "image/gif") {
                    await sharp(file.buffer).resize({ width: 128, height: 128 }).toBuffer().then(data => {
                        if (data) file.buffer = data; file.size = data.length;
                    });
                };

                if (urls.thumbnail_pro_id !== "") {
                    b2.getFileInfo({
                        fileId: urls.thumbnail_pro_id
                    }).then(async tt => {
                        let data = tt.data
                        b2.deleteFileVersion({
                            fileId: data.fileId,
                            fileName: data.fileName
                        });
                    });
                };

                b2.getUploadUrl({
                    bucketId: 'd5afb20446dd61128b590419'
                }).then(tt => {
                    upl = tt.data.uploadUrl; 
                    authT = tt.data.authorizationToken;

                    b2.uploadFile({
                        uploadUrl: upl,
                        uploadAuthToken: authT,
                        fileName: randomUUID(),
                        contentLength: file.size,
                        mime: file.mimetype,
                        data: file.buffer,
                        hash: '',
                        onUploadProgress: (event) => {}
                    }).then(async fin => { await short_url.updateOne({ uuid: urls.uuid }, { $set: { thumbnail: encrypt(`https://f004.backblazeb2.com/file/ferrets/${fin.data.fileName}`), thumbnail_pro_id: fin.data.fileId } }); delete faviconCache[urls.id]; });
                });

                delete faviconCache[urls.id];
                res.json({ OK: true, status: 200, text: `Updated icon` });
            };
        });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: e });
    };
});

a.get('/admin/upgrade_plan/:name', async function (req, res) {
    let { session } = req.cookies;
    let { plan, admin_gift, years } = req.query;
    let { name } = req.params;

    try {
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

        if (!plan || !name) return res.sendStatus(404);

        let u = await user.findOne({ nameToFind: name.toUpperCase() }).lean();
        if (!u) return res.status(404).json({ OK: false, status: 404, error: `User not found` });
        if (u.blocked) return res.status(404).json({ OK: false, status: 403, error: `User is blocked` });

        if (!u.pro && plan.toLowerCase() == "pro") {
            let ag = false;
            let yr = new Date().setFullYear(new Date().getFullYear()+1);

            if (admin_gift && admin_gift == 'true') ag = true;
            if (years) yr = new Date().setFullYear(new Date().getFullYear()+parseInt(years))
            new receipt({
                user: u._id,
                receipt: Math.random().toString(32).substring(5).toUpperCase(),
                pro: true,
                pro_plus: false,
                subdomain: false,
                customdomain: false,
                badge: false,
                gift: false,
                admin_gift: ag,
                gift_from: null,
                amount: "0",
                valid_until: yr,
                valid: true,
                uuid: randomUUID(),
                date: Date.now()
            }).save();
            await user.updateOne({ uuid: u.uuid }, { $set: { pro: true, linklimit: "50", theme: "dark" } });
        };
        if (u.pro && plan.toLowerCase() == "free") {
            let rr = await receipt.findOne({ user: u._id, pro: true, valid: true }).lean();
            if (rr) await receipt.updateOne({ user: u._id, pro: true, valid: true }, { $set: { valid: false } });

            await user.updateOne({ uuid: u.uuid }, { $set: { pro: false, linklimit: "25", theme: "" } });
        };

        res.redirect(`/${u.uuid}/edit`);
        // res.json({ OK: true, status: 200 });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: `${e}` });
    };
});

a.get('/admin/block_user/:name', async function (req, res) {
    let { session } = req.cookies;
    let { type } = req.query;
    let { name } = req.params;

    try {
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

        if (!type || !name) return res.sendStatus(404);

        let u = await user.findOne({ nameToFind: name.toUpperCase() }).lean();
        if (!u) return res.status(404).json({ OK: false, status: 404, error: `User not found` });

        let blocked = false;
        let hidden = false;

        if (type == "blocked" && !u.blocked) blocked = true;
        if (type == "hidden" && !u.hidden) { hidden = true; blocked = true; };

        await user.updateOne({ uuid: u.uuid }, { $set: { blocked, hidden } });

        res.redirect(`/${u.uuid}/edit`);
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: `${e}` });
    };
});

a.get('/admin/allow_subdomain/:name', async function (req, res) {
    let { session } = req.cookies;
    let { name } = req.params;
    let { admin_gift, years } = req.query;

    try {
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

        if (!name) return res.sendStatus(404);

        let u = await user.findOne({ nameToFind: name.toUpperCase() }).lean();
        if (!u) return res.status(404).json({ OK: false, status: 404, error: `User not found` });
        if (u.blocked) return res.status(404).json({ OK: false, status: 403, error: `User is blocked` });

        let allow = false;
        if (!u.subdomain) allow = true;

        if (!u.subdomain) {
            let ag = false;
            let yr = new Date().setFullYear(new Date().getFullYear()+1);
    
            if (admin_gift && admin_gift == 'true') ag = true;
            if (years) yr = new Date().setFullYear(new Date().getFullYear()+parseInt(years));
            new receipt({
                user: u._id,
                receipt: Math.random().toString(32).substring(5).toUpperCase(),
                pro: false,
                pro_plus: false,
                subdomain: true,
                customdomain: false,
                badge: false,
                gift: false,
                admin_gift: ag,
                gift_from: null,
                amount: "0",
                valid_until: yr,
                valid: true,
                uuid: randomUUID(),
                date: Date.now()
            }).save();
        };
        if (u.subdomain) {
            let rr = await receipt.findOne({ user: u._id, subdomain: true, valid: true }).lean();
            if (rr) await receipt.updateOne({ user: u._id, subdomain: true, valid: true }, { $set: { valid: false } });
        };
        await user.updateOne({ uuid: u.uuid }, { $set: { subdomain: allow } });

        res.redirect(`/${u.uuid}/edit`);
        // res.json({ OK: true, status: 200 });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, error: `${e}` });
    };
});

a.get('/admin/cached_images/:name', async function (req, res) {
    let { name } = req.params;
    let { session } = req.cookies;

    try {
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });
    
        if (!name) return res.status(404).json({ OK: false, status: 404, error: `Please specify a user` });
        let s = await user.findOne({ nameToFind: name.toUpperCase() }, { password: 0, createdIP: 0, __v: 0, recEmail: 0, session: 0, apiKey: 0, google_backup: 0, TFA: 0, email: 0, connectedUser: 0, staff: 0, socials: 0, links: 0, verified: 0, vrverified: 0, ogname: 0, linklimit: 0, pfp: 0, banner: 0, views: 0, nameHistory: 0, bio: 0, location: 0, reason: 0, pro: 0, last_login: 0, theme: 0, personal_border: 0, fonts: 0, signin_id: 0, subdomain: 0, pfp_id: 0, banner_id: 0, url: 0, pronouns: 0 }).lean();
        let u;
        if (s && !s.blocked && !s.hidden) u = await short_url.find({ author: s._id }, { _id: 0, clicks: 0, link: 0, title: 0, subtitle: 0, order: 0, highlight: 0, __v: 0, limitClick: 0, limitClicks: 0, thumbnail: 0, thumbnail_pro_id: 0 }).lean();
    
        let result = { OK: true, status: 200, loaded: { favicon: [] } };
        let av;
        let bn;
        let fi = [];
    
        if (u && u.length > 0) {
            u.forEach(elm => {
                if (faviconCache[elm.id]) fi.push(`${req.protocol}://${req.hostname}/favicon/${elm.id}`);
            });
        };
    
        if (s && !s.blocked && !s.hidden && avatarCache[s.uuid]) av = `${req.protocol}://${req.hostname}/avatar/${s.uuid}`;
        if (s && !s.blocked && !s.hidden && bannerCache[s.uuid]) bn = `${req.protocol}://${req.hostname}/banner/${s.uuid}`;
        if (s && !s.blocked && !s.hidden) result = { OK: true, status: 200, loaded: { avatar: av, banner: bn, favicon: fi } };
        res.setHeader('Content-Type', 'application/json');
        res.send(JSON.stringify(result, null, 2.5));
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, status: 500, error: `Unable to load this endpoint` });
    };
});

a.post('/admin/create_verified_session', async function (req, res) {
    let { session } = req.cookies;
    let { OAuth } = req.body;

    try {
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

        if (!OAuth) return res.status(403).json({ OK: false, status: 403, error: `Missing fields` });
    
        let s = await user.findOne({ session }, { password: 0, createdIP: 0, __v: 0, recEmail: 0, session: 0, apiKey: 0, email: 0, connectedUser: 0, staff: 0, socials: 0, links: 0, verified: 0, vrverified: 0, ogname: 0, linklimit: 0, pfp: 0, banner: 0, views: 0, nameHistory: 0, bio: 0, location: 0, reason: 0, pro: 0, last_login: 0, theme: 0, personal_border: 0, fonts: 0, signin_id: 0, subdomain: 0, pfp_id: 0, banner_id: 0, url: 0, pronouns: 0 }).lean();
        if (!s) return res.status(403).json({ OK: false, status: 403, error: `Invalid session` });
        if (s.blocked) return res.status(403).json({ OK: false, status: 403, error: `Invalid session` });
        if (!s.TFA) return res.status(403).json({ OK: false, status: 403, error: `Staff must have 2FA enabled` });

        let verify = authenticator.verifyToken(decrypt(s.google_backup), `${OAuth}`);
        if (!verify) return res.status(403).json({ OK: false, status: 403, error: `Invalid OAuth Code` });

        let code = randomUUID();
        authCode[code] = code;

        res.cookie('verified_session', code);
        res.json({ OK: true, status: 200, text: `Created session` });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, status: 500, error: `Unable to load this endpoint` });
    };
});

a.get('/admin/create_verified_session', async function (req, res) {
    let { session } = req.cookies;
    let { c } = req.query;

    try {
        let check = await auth(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`, true);
        if (!check.OK) return res.status(403).json({ OK: false, status: 403, error: check.error });

        if (!c) return res.status(403).json({ OK: false, status: 403, error: `Invalid code` });
    
        let s = await user.findOne({ session }, { password: 0, createdIP: 0, __v: 0, recEmail: 0, session: 0, apiKey: 0, email: 0, connectedUser: 0, staff: 0, socials: 0, links: 0, verified: 0, vrverified: 0, ogname: 0, linklimit: 0, pfp: 0, banner: 0, views: 0, nameHistory: 0, bio: 0, location: 0, reason: 0, pro: 0, last_login: 0, theme: 0, personal_border: 0, fonts: 0, signin_id: 0, subdomain: 0, pfp_id: 0, banner_id: 0, url: 0, pronouns: 0 }).lean();
        if (!s) return res.status(403).json({ OK: false, status: 403, error: `Invalid session` });
        if (s.blocked) return res.status(403).json({ OK: false, status: 403, error: `Invalid session` });
        if (!s.TFA) return res.status(403).json({ OK: false, status: 403, error: `Staff must have 2FA enabled` });

        if (c !== process.env.ADMIN_SESSION_CODE) return res.status(403).json({ OK: false, status: 403, error: `Invalid code` });
        
        let code = randomUUID();
        authCode[code] = code;

        res.cookie('verified_session', code);
        res.json({ OK: true, status: 200, text: `Created session` });
    } catch (e) {
        console.log(e);
        res.status(500).json({ OK: false, status: 500, error: `Unable to load this endpoint` });
    };
});

module.exports = a;