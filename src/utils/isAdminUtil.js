const pool = require('../services/db.service');

const isAdminUtil = async (usrId) => {
    const dbRes = await pool.query('SELECT admin FROM users WHERE id=$1 AND verified = true', [usrId]);
    if (!dbRes || !dbRes.rows || !dbRes.rows.length) {
        return false;
    }
    return dbRes.rows[0].admin === 2;
};

module.exports = isAdminUtil;
