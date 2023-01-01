require('dotenv').config()
const express = require("express");
const { createServer } = require("http");
const moment = require('moment');
const app = express();
const mongo = require('mongoose');
const fetch = require('node-fetch');
const cryptojs = require('crypto-js');
const tokens = require('./db/account/tokens');
const httpServer = createServer(app);

mongo.connect(
    process.env.MONGO, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        useFindAndModify: false
    }).catch(err => {
    console.log('There was an error while trying to connect to the DataBase.')
});

app.set('view engine', 'ejs');
// app.set('trust proxy', true);
app.use(require('cookie-parser')());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static('./public'));
app.use('/', require('./routers/index')); // Main Routes
app.use('/api', require('./routers/api/index')); // API route
app.use('/api', require('./routers/api/account')); // Account API route
app.use("/public", express.static('public'));

function encrypt(g, s = process.env.SALT) {
    return cryptojs.AES.encrypt(g, s).toString();
}

function decrypt(g, s = process.env.SALT) {
    return cryptojs.AES.decrypt(g, s).toString(cryptojs.enc.Utf8);
}

app.get('*', async function (req, res) {
    let {theme, session} = req.cookies;
    if (!theme) theme = "";
    if (theme == "dark") theme = "dark";
    let acc = null;
    if (session) {
        let auth = await (await fetch(`${req.protocol}://${req.hostname}/api/v1/auth?session=${session}`)).json();
        if (auth && auth.status == 200) acc = JSON.parse(decrypt(auth.account));
    };
    res.render('error', { errorMessage: `Could not find page.`, theme: theme, acc });
});

httpServer.listen(process.env.PORT || 80, async function () {
    console.log('The site is up!');
});