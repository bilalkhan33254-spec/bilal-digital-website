require("dotenv").config();


const Database = require("better-sqlite3");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");

const db = new Database("bilal-digital.db");

db.prepare(`
    CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`).run();

const cors = require("cors");

const app = express();


app.use(cors({
    origin: [
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    credentials: true
}));


app.use(express.json());


app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        maxAge: 1000 * 60 * 60
    }
}));


if (!process.env.ADMIN_USERNAME ||
    !process.env.ADMIN_PASSWORD ||
    !process.env.SESSION_SECRET) {
    throw new Error("Admin login settings missing in .env file");
}

const adminPasswordHash = bcrypt.hashSync(
    process.env.ADMIN_PASSWORD,
    12
);

function requireAdmin(req, res, next) {
    if (req.session && req.session.isAdmin === true) {
        return next();
    }

    return res.status(401).json({
        success: false,
        message: "Please log in first."
    });
}

app.post("/api/admin/login", function (req, res, next) {
    const username = req.body.username;
    const password = req.body.password;

    if (typeof username !== "string" ||
        typeof password !== "string") {
        return res.status(400).json({
            success: false,
            message: "Username and password are required."
        });
    }

    const usernameMatches =
        username === process.env.ADMIN_USERNAME;

    bcrypt.compare(password, adminPasswordHash, function (err, matches) {
        if (err) return next(err);

        if (!usernameMatches || !matches) {
            return res.status(401).json({
                success: false,
                message: "Invalid username or password."
            });
        }

        req.session.regenerate(function (err) {
            if (err) return next(err);

            req.session.isAdmin = true;

            req.session.save(function (err) {
                if (err) return next(err);

                res.json({
                    success: true,
                    message: "Login successful."
                });
            });
        });
    });
});

app.post("/api/admin/logout", requireAdmin, function (req, res, next) {
    req.session.destroy(function (err) {
        if (err) return next(err);

        res.clearCookie("connect.sid");

        res.json({
            success: true,
            message: "Logged out successfully."
        });
    });
});

app.get("/api/admin/status", function (req, res) {
    res.json({
        loggedIn: Boolean(req.session && req.session.isAdmin === true)
    });
});


const PORT = 3000;

app.get("/", function (req, res) {
    res.send("Bilal Digital Backend is running!");
});

app.get("/api/test", function (req, res) {
    res.json({
        success: true,
        message: "Bilal Digital API is working!"
    });
});

app.post("/api/contact", function (req, res) {

const name = req.body.name;
const email = req.body.email;
const message = req.body.message;

const insert = db.prepare(`
    INSERT INTO contacts (name, email, message)
    VALUES (?, ?, ?)
`);

insert.run(name, email, message);

console.log("New Contact Message:");
console.log("Name:", name);
console.log("Email:", email);
console.log("Message:", message);

res.json({
    success: true,
    message: "Your message was saved successfully!"
});
});

app.get("/api/contacts", requireAdmin, function (req, res) {

    const contacts = db.prepare(`
        SELECT * FROM contacts
        ORDER BY id DESC
    `).all();

    res.json(contacts);

});


app.get("/api/admin/backup", requireAdmin, function (req, res, next) {
    try {
        const backupPath = require("path").join(
            __dirname,
            "bilal-digital-backup.db"
        );

        db.backup(backupPath)
            .then(function () {
                res.download(
                    backupPath,
                    "bilal-digital-backup.db"
                );
            })
            .catch(next);

    } catch (error) {
        next(error);
    }
});


app.delete("/api/contacts/:id", requireAdmin, function (req, res) {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({
            success: false,
            message: "Invalid message ID."
        });
    }

    const result = db.prepare(
        "DELETE FROM contacts WHERE id = ?"
    ).run(id);

    if (result.changes === 0) {
        return res.status(404).json({
            success: false,
            message: "Message not found."
        });
    }

    res.json({
        success: true,
        message: "Message deleted successfully."
    });
});


const server = app.listen(PORT, function () {
    console.log(`Backend server running on http://localhost:${PORT}`);
});

server.on("close", function () {
    console.log("Server closed.");
});

server.on("error", function (error) {
    console.log("Server error:", error);
});
