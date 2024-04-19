const pool = require('../services/db.service');
const isAdminUtil = require('../utils/isAdminUtil');

const getAll = async (request, response) => {
    const { id } = request.body;
    const admin = await isAdminUtil(id);
    if (!admin) {
        return response.status(403).send('You dont have permissions');
    }

    return pool.query(
        `
            SELECT submits.id AS "id", users.name AS "name", challenges.title AS "title", challenges.answer AS "corr_ans",
                   submits.answer AS "given_ans", submits.correct AS "correct", submits.sent AS "sent"
            FROM ((submits
            INNER JOIN users ON submits.usr_id = users.id)
            INNER JOIN challenges ON submits.chall_id = challenges.id)
            ORDER BY submits.sent DESC
        `,
        [],
        (error, dbRes) => {
            if (error) {
                console.error(error);
                return response.status(500).send('Internal Server Error');
            }
            return response.status(200).send(dbRes.rows);
        },
    );
};

const getById = async (request, response) => {
    const { id } = request.body;
    if (!id) {
        return response.status(403).send('You are not logged in');
    }

    return pool.query(
        `
            SELECT submits.id AS "id", users.name AS "name", challenges.title AS "title",
                   submits.answer AS "given_ans", submits.correct AS "correct", submits.sent AS "sent"
            FROM ((submits
            INNER JOIN users ON submits.usr_id = users.id)
            INNER JOIN challenges ON submits.chall_id = challenges.id)
            WHERE users.id = $1
            ORDER BY submits.sent DESC
        `,
        [id],
        (error, dbRes) => {
            if (error) {
                console.error(error);
                return response.status(500).send('Internal Server Error');
            }
            return response.status(200).send(dbRes.rows);
        },
    );
};

module.exports = {
    getAll,
    getById,
};
