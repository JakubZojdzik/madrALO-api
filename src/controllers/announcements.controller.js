const pool = require('../services/db.service');
const isAdminUtil = require('../utils/isAdminUtil');

const getCurrent = async (request, response) => {
    const results = await pool.query("SELECT * FROM announcements WHERE added <= now() AT TIME ZONE 'CEST' ORDER BY added DESC");
    return response.status(200).send(results.rows);
};

const getInactive = async (request, response) => {
    const { id } = request.body;
    if (!id) {
        return response.status(403).send('Not permitted!');
    }

    const admin = await isAdminUtil(id);
    if (!admin) {
        return response.status(403).send('Not permitted');
    }
    return pool
        .query("SELECT * FROM announcements WHERE added > now() AT TIME ZONE 'CEST' ORDER BY added DESC")
        .then((results) => response.status(200).send(results.rows))
        .catch((error) => {
            console.error(error);
            return response.status(500).send('Internal Server Error');
        });
};

const getById = async (request, response) => {
    const { id } = request.body;
    const { annId } = request.query;

    let tmp = " AND added <= now() AT TIME ZONE 'CEST'";
    const admin = await isAdminUtil(id);
    if (admin) {
        tmp = '';
    } else if (new Date(Date.parse(process.env.COMPETITION_START)) >= new Date().fixZone()) {
        return response.status(400).send('Challenge does not exist');
    }

    return pool.query(`SELECT id, title, content, author, added FROM announcements WHERE id = $1${tmp}`, [annId], (error, dbRes) => {
        if (error) {
            console.error(error);
            return response.status(500).send('Internal Server Error');
        }
        if (!dbRes || !dbRes.rows || !dbRes.rows.length) {
            return response.status(400).send('Announcement does not exist');
        }
        return response.status(200).send(dbRes.rows[0]);
    });
};

const add = async (request, response) => {
    const { id, title, content, author, added } = request.body;
    const admin = await isAdminUtil(id);
    if (!admin) {
        return response.status(403).send('You have to be admin');
    }
    return pool.query(
        'INSERT INTO announcements (title, author, content, added) VALUES ($1, $2, $3, $4)',
        [title, author, content, added],
        (error) => {
            if (error) {
                console.error(error);
                return response.status(500).send('Internal Server Error');
            }
            return response.status(201).send('Announcement added');
        },
    );
};

const edit = async (request, response) => {
    const { id, annId, title, content, author, added } = request.body;
    const admin = await isAdminUtil(id);
    if (!admin) {
        return response.status(403).send('You have to be admin');
    }
    return pool.query(
        'UPDATE announcements SET title=$1, content=$2, author=$3, added=$4 WHERE id=$5',
        [title, content, author, added, annId],
        (error) => {
            if (error) {
                console.error(error);
                return response.status(500).send('Internal Server Error');
            }
            return response.status(201).send('Announcement updated');
        },
    );
};

const remove = async (request, response) => {
    const { id, annId } = request.body;
    const admin = isAdminUtil(id);
    if (!admin) {
        return response.status(403).send('You have to be admin');
    }
    return pool.query('DELETE FROM announcements WHERE id=$1', [annId], (error) => {
        if (error) {
            console.error(error);
            return response.status(500).send('Internal Server Error');
        }
        return response.status(201).send('Announcement removed');
    });
};

module.exports = {
    getCurrent,
    getById,
    remove,
    add,
    getInactive,
    edit,
};
