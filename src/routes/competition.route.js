const express = require('express');

const router = express.Router();
const competitionController = require('../controllers/competition.controller');
const authenticateToken = require('../middlewares/auth');
const errorHandler = require('../middlewares/errorHandler');

router.use('/edit', authenticateToken);
router.use('/uploadIcon', authenticateToken);

router.get('/title', errorHandler(competitionController.getTitle));
router.get('/rules', errorHandler(competitionController.getRules));
router.get('/timeRange', errorHandler(competitionController.getTimeRange));
router.get('/icon', errorHandler(competitionController.icon));

router.post('/edit', errorHandler(competitionController.edit));
router.post('/uploadIcon', errorHandler(competitionController.uploadIcon));

module.exports = router;
