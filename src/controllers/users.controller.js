const bcrypt = require('bcryptjs');
const fs = require('fs');
const yaml = require('js-yaml');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const pool = require('../services/db.service');
const isAdminUtil = require('../utils/isAdminUtil');

dotenv.config();
const competitionConf = yaml.load(fs.readFileSync(process.env.SOK_CONFIG, 'utf8'));

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: true,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD,
    },
});

const signToken = (username, expTime) => jwt.sign(username, process.env.TOKEN_SECRET, { expiresIn: expTime });

const sendMail = (destination, subject, text, html) => {
    console.log('wysylam', html);
    const message = {
        from: process.env.SMTP_FROM,
        to: destination,
        subject,
        text,
        html,
    };
    transporter.sendMail(message);
};

const sendTokenEmail = (token, dest) => {
    sendMail(
        dest,
        'Weryfikacja rejestracji',
        `Dziękuję za rejestrację! Aby aktywować nowe konto należy kliknąć w poniższy link: ${process.env.CLIENT_URL}/verification?token=${token}<br />`,
        `<h1><b>Dziękuję za rejestrację! </b></h1><br /> Aby aktywować nowe konto należy kliknąć w poniższy link:<br />
        <a href="${process.env.CLIENT_URL}/verification?token=${token}">Weryfikuj</a><br />`,
    );
};

const sendVerifyToken = (token, dest) => {
    sendMail(
        dest,
        'Zmiana hasła',
        `Aby zmienić hasło należy kliknąć w poniższy link: ${process.env.CLIENT_URL}/passChange?token=${token}<br />`,
        `<p>Aby zmienić hasło należy kliknąć w poniższy link:<br /><a href="${process.env.CLIENT_URL}/passChange?token=${token}">Weryfikuj</a><br /></p>`,
    );
};

const register = async (request, response) => {
    const { email, name, password, passwordRep } = request.body;
    const validEmailFormat = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    const validEmailDomain = email.endsWith('@alo.pwr.edu.pl');
    const validNameLength = name.length >= 5 && name.length <= 12;
    const validNameFormat = /^[a-zA-Z0-9._-]+$/.test(name);
    const validPasswordFormat = /^[a-zA-Z0-9!@#$%^&*()_+=[\]{}|;:'"<>,\\./?`~-]{8,32}$/.test(password);
    const passwordsMatch = password === passwordRep;

    if (!validEmailFormat || !validEmailDomain) {
        return response.status(401).send('Nieprawidłowy adres email!');
    }
    if (!validNameLength) {
        return response.status(401).send('Błędna długość nazwy!');
    }
    if (!validNameFormat) {
        return response.status(401).send('Nazwa powinna zawierać tylko litery, liczby, kropki, myślniki i podkreślniki!');
    }
    if (!validPasswordFormat) {
        return response.status(401).send('Nieprawidłowe hasło!');
    }
    if (!passwordsMatch) {
        return response.status(401).send('Hasła są różne!');
    }

    const dbRes = await pool.query('SELECT * FROM users WHERE verified = true AND (email = $1 OR name = $2)', [email, name]);

    if (dbRes.rowCount) {
        return response.status(401).send('Konto o danym mailu lub nazwie już istnieje!');
    }

    const unverified = await pool.query('SELECT id FROM users WHERE verified = false AND email = $1', [email]);
    if (unverified.rowCount) {
        pool.query('DELETE FROM users WHERE id = $1', [unverified.rows[0].id]);
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    await pool.query('INSERT INTO users (name, email, password) VALUES ($1, $2, $3)', [name, email, hash]);

    const token = signToken({ email }, '8h');
    sendTokenEmail(token, email);
    return response.status(201).send('User registered');
};

const changePassword = async (request, response) => {
    const { email, password, passwordRep } = request.body;

    const validPasswordFormat = /^[a-zA-Z0-9!@#$%^&*()_+=[\]{}|;:'"<>,\\./?`~-]{8,32}$/.test(password);
    const passwordsMatch = password === passwordRep;
    if (!validPasswordFormat) {
        return response.status(401).send('Nieprawidłowe hasło!');
    }
    if (!passwordsMatch) {
        return response.status(401).send('Hasła są różne!');
    }
    const dbRes = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (!dbRes.rows.length) {
        return response.status(401).send('Konto o danym mailu nie istnieje!');
    }
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const token = signToken({ email, hash }, '900s');
    sendVerifyToken(token, email);
    return response.status(201).send('Mail sent!');
};

const verifyRegistration = async (request, response) => {
    const { token } = request.body;
    const tokenRes = jwt.verify(token, process.env.TOKEN_SECRET);
    if (!tokenRes.email) {
        return response.status(401).send('Cannot verify token');
    }

    await pool.query('UPDATE users SET verified = true WHERE email=$1', [tokenRes.email]);
    return response.status(200).send('Account verified!');
};

const verifyPasswordChange = async (request, response) => {
    const { token } = request.body;
    const tokenRes = jwt.verify(token, process.env.TOKEN_SECRET);
    if (!tokenRes.email || !tokenRes.hash) {
        return response.status(401).send('Cannot verify token');
    }
    await pool.query('UPDATE users SET password = $1 WHERE email=$2', [tokenRes.hash, tokenRes.email]);
    return response.status(200).send('Password change verified!');
};

const login = async (request, response) => {
    const { email, password } = request.body;
    const dbRes = await pool.query('SELECT * FROM users WHERE email = $1 AND verified = true', [email]);
    if (!dbRes.rowCount) {
        return response.status(401).send('Nieprawidłowe dane!');
    }
    const baseHash = dbRes.rows[0].password;
    const cmpRes = await bcrypt.compare(password, baseHash);
    if (cmpRes) {
        const token = signToken({ id: dbRes.rows[0].id }, '43200s');
        return response.status(200).send({ token, email: dbRes.rows[0].email, name: dbRes.rows[0].name });
    }
    return response.status(401).send('Nieprawidłowe dane!');
};

const isLogged = (request, response) => {
    const { id } = request.body;
    if (id) {
        return response.status(200).send(id.toString());
    }
    return response.status(200).send(false);
};

const solves = async (request, response) => {
    const { id } = request.body;
    if (!id) {
        return response.status(403).send('Not permited!');
    }
    const dbRes = await pool.query('SELECT solves FROM users WHERE id = $1 AND verified = true', [id]);
    if (!dbRes.rowCount) {
        return response.status(400).send('User does not exist');
    }
    return response.status(200).send(dbRes.rows[0].solves);
};

const ranking = async (request, response) => {
    const { id } = request.body;
    const admin = await isAdminUtil(id);
    const { freeze } = competitionConf;
    let dbRes;
    if (freeze === 'true' && !admin) {
        const freezeTime = new Date(Date.parse(competitionConf.freezeTime));
        dbRes = await pool.query(
            `
            SELECT
                u.name,
                COALESCE(SUM(CASE WHEN s.correct = true THEN c.points ELSE -1 END), 0) AS points
            FROM
                users u
            JOIN
                submits s ON u.id = s.usr_id
            JOIN
                challenges c ON s.chall_id = c.id
            WHERE
                admin = 0 AND verified = true AND sent <= $1
            GROUP BY
                u.id, u.name
            ORDER BY
                points DESC, MAX(s.sent) ASC, u.name;
            `,
            [freezeTime.toISOString()],
        );
    } else {
        dbRes = await pool.query(
            `
            SELECT
                u.name,
                COALESCE(SUM(CASE WHEN s.correct = true THEN c.points ELSE -1 END), 0) AS points
            FROM
                users u
            JOIN
                submits s ON u.id = s.usr_id
            JOIN
                challenges c ON s.chall_id = c.id
            WHERE
                admin = 0 AND verified = true
            GROUP BY
                u.id, u.name
            ORDER BY
                points DESC, MAX(s.sent) ASC, u.name;
            `,
        );
    }
    const dbRows = dbRes.rows;
    for (let i = 0; i < dbRes.rows.length; i += 1) {
        dbRows[i].position = i + 1;
    }
    return response.status(200).send(dbRows);
};

const isAdmin = async (request, response) => {
    const { id } = request.body;
    if (!id) {
        return response.status(200).send(false);
    }
    const dbRes = await pool.query('SELECT admin FROM users WHERE id=$1 AND verified = true', [id]);
    if (!dbRes.rowCount) {
        return response.status(200).send(false);
    }
    return response.status(200).send(dbRes.rows[0].admin === 2);
};

module.exports = {
    login,
    register,
    solves,
    isLogged,
    ranking,
    isAdmin,
    verifyRegistration,
    changePassword,
    verifyPasswordChange,
};
