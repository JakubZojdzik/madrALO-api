const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');

dotenv.config();

const { Pool } = require('pg');

const pool = new Pool({
    host: process.env.PG_HOST,
    port: process.env.PG_PORT,
    user: process.env.PG_USER,
    password: process.env.PG_PASSWORD,
    database: process.env.PG_DB,
});

pool.query(
    `CREATE TABLE IF NOT EXISTS public.announcements
    (
        id integer NOT NULL GENERATED ALWAYS AS IDENTITY ( INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 2147483647 CACHE 1 ),
        title text COLLATE pg_catalog."default" CHECK (LENGTH(title) <= 40),
        author text COLLATE pg_catalog."default" CHECK (LENGTH(author) <= 30),
        content text COLLATE pg_catalog."default",
        added timestamp without time zone NOT NULL DEFAULT NOW(),
        PRIMARY KEY (id)
    )`,
    (error) => {
        if (error) {
            throw error;
        }
    },
);

pool.query(
    `CREATE TABLE IF NOT EXISTS public.challenges
    (
        id integer NOT NULL GENERATED ALWAYS AS IDENTITY ( INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 2147483647 CACHE 1 ),
        title text COLLATE pg_catalog."default" NOT NULL CHECK (LENGTH(title) <= 40),
        content text COLLATE pg_catalog."default" NOT NULL,
        author text COLLATE pg_catalog."default" CHECK (LENGTH(author) <= 30),
        points integer NOT NULL,
        answer text COLLATE pg_catalog."default" NOT NULL CHECK (LENGTH(answer) <= 100),
        solves integer NOT NULL DEFAULT 0,
        start timestamp without time zone NOT NULL DEFAULT NOW(),
        PRIMARY KEY (id)
    )`,
    (error) => {
        if (error) {
            throw error;
        }
    },
);

pool.query(
    `CREATE TABLE IF NOT EXISTS public.submits
    (
        id integer NOT NULL GENERATED ALWAYS AS IDENTITY ( INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 2147483647 CACHE 1 ),
        usr_id integer NOT NULL,
        chall_id integer NOT NULL,
        sent timestamp without time zone NOT NULL DEFAULT NOW(),
        answer text COLLATE pg_catalog."default" NOT NULL CHECK (LENGTH(answer) <= 100),
        correct boolean NOT NULL,
        PRIMARY KEY (id),
        FOREIGN KEY (usr_id) REFERENCES public.users (id),
        FOREIGN KEY (chall_id) REFERENCES public.challenges (id)
    )`,
    (error) => {
        if (error) {
            throw error;
        }
    },
);

pool.query(
    `CREATE TABLE IF NOT EXISTS public.users
    (
        id integer NOT NULL GENERATED ALWAYS AS IDENTITY ( INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 2147483647 CACHE 1 ),
        name text COLLATE pg_catalog."default" UNIQUE CHECK (LENGTH(name) >= 5 AND LENGTH(name) <= 12),
        email text COLLATE pg_catalog."default" UNIQUE,
        password text COLLATE pg_catalog."default",
        solves integer[] NOT NULL DEFAULT ARRAY[]::integer[],
        verified boolean NOT NULL DEFAULT false,
        admin integer NOT NULL DEFAULT 0,
        PRIMARY KEY (id)
    )`,
    (error) => {
        if (error) {
            throw error;
        }
    },
);

pool.query('SELECT * FROM users', (error, dbRes) => {
    if (!dbRes || dbRes.rowCount) return;
    if (error) {
        throw error;
    }
    bcrypt
        .genSalt(10)
        .then((salt) => bcrypt.hash(process.env.ADMIN_PASS, salt))
        .then((hash) => {
            pool.query('INSERT INTO users (name, email, password, verified, admin) VALUES ($1, $2, $3, true, 2)', [
                process.env.ADMIN_NAME,
                process.env.ADMIN_EMAIL,
                hash,
            ]);
        })
        .catch((err) => console.error(err.message));
});

module.exports = pool;
