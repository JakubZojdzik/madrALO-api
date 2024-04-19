const express = require('express');

const router = express.Router();
const usersController = require('../controllers/users.controller');
const authenticateToken = require('../middlewares/auth');
const errorHandler = require('../middlewares/errorHandler');

router.use('/solves', authenticateToken);
router.use('/islogged', authenticateToken);
router.use('/isAdmin', authenticateToken);

router.get('/solves', errorHandler(usersController.solves));
router.get('/islogged', errorHandler(usersController.isLogged));
router.get('/ranking', errorHandler(usersController.ranking));
router.get('/isAdmin', errorHandler(usersController.isAdmin));

router.post('/verify', errorHandler(usersController.verifyRegistration));
router.post('/verifyPass', errorHandler(usersController.verifyPasswordChange));
router.post('/register', errorHandler(usersController.register));
router.post('/changePassword', errorHandler(usersController.changePassword));
router.post('/login', errorHandler(usersController.login));

module.exports = router;
