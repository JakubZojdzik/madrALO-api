const pool = require('../services/db.service');

const logSubmit = async (usrId, challId, answer, correct) => {
    await pool.query(
        'INSERT INTO submits (usr_id, chall_id, sent, answer, correct) VALUES ($1, $2, NOW(), $3, $4)',
        [usrId, challId, answer, correct],
        (error) => {
            if (error) {
                throw error;
            }
            return 0;
        },
    );
};

module.exports = logSubmit;
