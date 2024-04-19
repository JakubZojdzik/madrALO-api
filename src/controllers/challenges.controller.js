const fs = require('fs');
const yaml = require('js-yaml');
const pool = require('../services/db.service');
const isAdmin = require('../utils/isAdmin');
const logSubmit = require('../utils/logSubmit');

const competitionConf = yaml.load(fs.readFileSync(process.env.SOK_CONFIG, 'utf8'));

const isSolved = async (usrId, challId) => {
    try {
        const dbRes = await pool.query('SELECT ($1 = ANY ((SELECT solves FROM users WHERE id=$2 AND verified=true)::int[]))::text', [challId, usrId]);
        if (!dbRes.rowCount) {
            return 'false';
        }
        return dbRes.rows[0].text;
    } catch (error) {
        console.error(error);
        return error;
    }
};

const timeToSubmit = async (usrId) => {
    const dbRes = await pool.query(
        `
        WITH diff AS (
            SELECT
                submitted - NOW() AT TIME ZONE 'CEST' + INTERVAL '10 minutes' AS difftime
            from
                users
            WHERE
                id=$1
        )

        SELECT
            CASE
                WHEN difftime <= INTERVAL '0 seconds' THEN CEIL(EXTRACT(EPOCH FROM (INTERVAL '0 minutes'))/60)
            ELSE
                CEIL(EXTRACT(EPOCH FROM (difftime))/60)
            END AS minutes
        FROM diff
    `,
        [usrId],
    );
    return dbRes.rows[0].minutes;
};

// eslint-disable-next-line no-extend-native
Date.prototype.fixZone = function fn() {
    this.setHours(this.getHours() + 2);
    return this;
};

const compAnswers = async (chall, answer, usrId) => {
    try {
        const endTime = new Date(Date.parse(competitionConf.endTime));
        const currentTime = new Date().fixZone();

        const admin = await isAdmin(usrId);
        if (admin) {
            if (chall.answer === answer) {
                return { correct: true, info: '' };
            }
            return { correct: false, info: 'Błędna odpowiedź' };
        }

        // during competition
        if (endTime >= currentTime) {
            if (chall.answer === answer) {
                await pool.query(
                    'UPDATE users SET points=points+$1, solves=array_append(solves,$2), submitted_ac=now() WHERE id=$3 AND verified = true',
                    [chall.points, chall.id, usrId],
                );
                await pool.query('UPDATE challenges SET solves=solves+1 WHERE id=$1', [chall.id]);
                return { correct: true, info: '' };
            }

            await pool.query("UPDATE users SET points=points-1, submitted=now() AT TIME ZONE 'CEST' WHERE id=$1 AND verified = true", [usrId]);
            return { correct: false, info: 'Przed nastepną odpowiedzią musisz odczekać 10 min' };
        }

        // after competition
        if (chall.answer === answer) {
            await pool.query('UPDATE users SET solves=array_append(solves,$1) WHERE id=$2 AND verified = true', [chall.id, usrId]);
            return { correct: true, info: '' };
        }

        return { correct: false, info: 'Błędna odpowiedź' };
    } catch (error) {
        console.error(error);
        throw error;
    }
};

const getCurrent = async (request, response) => {
    const { id } = request.body;
    const admin = await isAdmin(id);
    const startTime = new Date(Date.parse(competitionConf.startTime));
    const currentTime = new Date().fixZone();

    if (startTime >= currentTime && !admin) {
        return response.status(200).send([]);
    }
    return pool.query(
        "SELECT id, title, content, author, points, solves, start FROM challenges WHERE start <= now() AT TIME ZONE 'CEST' ORDER BY start DESC, points DESC",
        (error, results) => {
            if (error) {
                console.error(error);
                return response.status(500).send('Internal Server Error');
            }
            return response.status(200).send(results.rows);
        },
    );
};

const getInactive = async (request, response) => {
    const { id } = request.body;
    if (!id) {
        return response.status(403).send('Not permited!');
    }
    const admin = await isAdmin(id);
    if (!admin) {
        return response.status(403).send('Not permited');
    }
    return pool.query(
        "SELECT id, title, content, author, points, solves, start FROM challenges WHERE start > now() AT TIME ZONE 'CEST' ORDER BY start DESC, points DESC",
        (error, results) => {
            if (error) {
                console.error(error);
                return response.status(500).send('Internal Server Error');
            }
            return response.status(200).send(results.rows);
        },
    );
};

const getById = async (request, response) => {
    const { id } = request.body;
    const { challId } = request.query;
    const startTime = new Date(Date.parse(competitionConf.startTime));
    const currentTime = new Date().fixZone();

    const admin = await isAdmin(id);
    let tmp = " AND start <= now() AT TIME ZONE 'CEST'";
    if (admin) {
        tmp = '';
    } else if (startTime >= currentTime) {
        return response.status(400).send('Challenge does not exist');
    }
    return pool.query(`SELECT id, title, content, author, points, solves, start FROM challenges WHERE id = $1${tmp}`, [challId], (error, dbRes) => {
        if (error) {
            console.error(error);
            return response.status(500).send('Internal Server Error');
        }
        if (!dbRes.rowCount) {
            return response.status(400).send('Challenge does not exist');
        }
        return response.status(200).send(dbRes.rows[0]);
    });
};

const sendAnswer = async (request, response) => {
    const { id, challId, answer } = request.body;
    if (answer.length >= 100) {
        return response.status(400).send('Za długa odpowiedź!');
    }
    if (answer.length === 0) {
        return response.status(400).send('Wpisz odpowiedź!');
    }
    const t = await timeToSubmit(id);
    if (t !== '0') {
        return response.status(400).send(`Musisz odczekać jeszcze ${t} min`);
    }
    const v = await isSolved(id, challId);
    if (v !== 'true' && v !== 'false') throw v;
    if (v === 'true') {
        return response.status(200).send(false);
    }
    const dbRes = await pool.query(
        "SELECT id, title, content, author, points, answer, solves, start FROM challenges WHERE id=$1 AND start <= now() AT TIME ZONE 'CEST'",
        [challId],
    );
    if (!dbRes.rowCount) {
        return response.status(400).send('Challenge does not exist');
    }
    const corr = await compAnswers(dbRes.rows[0], answer, id);
    logSubmit(id, challId, answer, corr.correct);
    return response.status(200).send(corr);
};

const correctAnswer = async (request, response) => {
    const { id } = request.body;
    const { challId } = request.query;
    const admin = await isAdmin(id);
    if (!admin) {
        return response.status(403).send('You have to be admin');
    }
    return pool.query('SELECT answer FROM challenges WHERE id=$1', [challId], (error, dbRes) => {
        if (error) {
            console.error(error);
            return response.status(500).send('Internal Server Error');
        }
        if (!dbRes.rowCount) {
            return response.status(400).send('Challenge does not exist');
        }
        return response.status(200).send(dbRes.rows[0].answer);
    });
};

const add = async (request, response) => {
    const { id, title, content, author, points, answer, start } = request.body;

    const admin = await isAdmin(id);
    if (!admin) {
        return response.status(403).send('You have to be admin');
    }
    return pool.query(
        'INSERT INTO challenges (title, content, author, points, answer, start) VALUES ($1, $2, $3, $4, $5, $6)',
        [title, content, author, points, answer, start],
        (error) => {
            if (error) {
                console.error(error);
                return response.status(500).send('Internal Server Error');
            }
            return response.status(201).send('Challenge added');
        },
    );
};

const edit = async (request, response) => {
    const { id, title, content, author, points, answer, solves, start, challId } = request.body;

    const admin = await isAdmin(id);
    if (!admin) {
        return response.status(403).send('You have to be admin');
    }
    return pool.query(
        'UPDATE challenges SET title=$1, content=$2, author=$3, points=$4, answer=$5, solves=$6, start=$7 WHERE id=$8',
        [title, content, author, points, answer, solves, start, challId],
        (error) => {
            if (error) {
                console.error(error);
                return response.status(500).send('Internal Server Error');
            }
            return response.status(201).send('Challenge updated');
        },
    );
};

const remove = async (request, response) => {
    const { id, challId } = request.body;

    const admin = await isAdmin(id);
    if (!admin) {
        return response.status(403).send('You have to be admin');
    }
    return pool.query('DELETE FROM challenges WHERE id=$1', [challId], (error) => {
        if (error) {
            console.error(error);
            return response.status(500).send('Internal Server Error');
        }
        return response.status(201).send('Challenge removed');
    });
};

module.exports = {
    sendAnswer,
    getById,
    getInactive,
    getCurrent,
    add,
    remove,
    edit,
    correctAnswer,
};
