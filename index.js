import express from "express";
import bodyParser from "body-parser";
import bcrypt, {hash} from "bcrypt";
import passport from "passport";
import {Strategy} from "passport-local";
import pg from "pg";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
env.config();

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
}));
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT
});
db.connect();

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
})

app.get("/logout", (req, res) => {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        res.redirect("/");
    })
});

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("secrets.ejs");
    } else {
        res.redirect("/login");
    }
});


const saltRnd = 10;
app.post("/register", (req, res) => {
    const ipEmail = req.body.username;
    const ipPasswd = req.body.password;
    bcrypt.hash(ipPasswd, saltRnd, async (err, hashCode) => {
        if (err) {
            console.error("Hashing error!");
        } else {
            try {
                const result = await db.query("insert into users (email, password) values ($1,$2) returning *;", [ipEmail, hashCode]);
                const entry = result.rows[0];
                req.login(entry, (err) => {
                    console.log("success");
                    res.redirect("/secrets");
                });
            } catch (e) {
                console.log(e);
                res.redirect("/login");
            }
        }
    });
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login"
}));

passport.use(new Strategy(async function verify(ipEmail, ipPasswd, cb) {
    try {
        const result = await db.query("select * from users where email = $1;", [ipEmail]);
        if (result.rows.length === 0) {
            return cb("User NOT found!");
        } else {
            const entry = result.rows[0];
            const usr = entry.username;
            const hashCode = entry.password;
            bcrypt.compare(ipPasswd, hashCode, (err, result) => {
                if (err) {
                    console.log("Comparison error!");
                    return cb(err);
                } else if (result === true) {
                    return cb(null, entry);
                } else {
                    return cb(null, false);
                }
            });
        }
    } catch (e) {
        console.log(e);
    }
}));

passport.serializeUser((user, cb) => {
    cb(null, user);
})

passport.deserializeUser(((user, cb) => {
    cb(null, user);
}));

app.listen(port, () => {
    console.log(`Server running at port ${port}`);
});