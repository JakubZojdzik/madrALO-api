const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const usersRouter = require('./src/routes/users.route');
const challengesRouter = require('./src/routes/challenges.route');
const announcementsRouter = require('./src/routes/announcements.route');
const submitsRouter = require('./src/routes/submits.route');
const competitionRouter = require('./src/routes/competition.route');

const app = express();
const port = 3000;

app.use(cors());
app.use(
    bodyParser.urlencoded({
        extended: true,
    }),
);

const defLimiter = rateLimit({
    windowMs: 10 * 1000, // 10 seconds
    max: 30000, // 30 requests per 10 seconds
    standardHeaders: false, // Disable rate limit info in the `RateLimit-*` headers
    legacyHeaders: true, // Enable the `X-RateLimit-*` headers
});

const longLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 100, // 1 requests per minute
    standardHeaders: false, // Disable rate limit info in the `RateLimit-*` headers
    legacyHeaders: true, // Enable the `X-RateLimit-*` headers
});

app.use('/', defLimiter);
app.use('/users/register', longLimiter);
app.use('/users/changePassword', longLimiter);
app.use('/users/verifyPass', longLimiter);
app.use('/users/verify', longLimiter);

app.get('/', (request, response) => {
    response.send({ info: 'Node.js, Express, and Postgres API' });
});
app.use('/users', usersRouter);
app.use('/challenges', challengesRouter);
app.use('/announcements', announcementsRouter);
app.use('/submits', submitsRouter);
app.use('/competition', competitionRouter);

app.listen(port, () => {
    console.log(`App running on port ${port}.`);
});
