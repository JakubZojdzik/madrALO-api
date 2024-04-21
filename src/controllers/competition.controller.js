const fs = require('fs');
const yaml = require('js-yaml');
const multer = require('multer');
const path = require('path');
const isAdminUtil = require('../utils/isAdminUtil');

const competitionConf = yaml.load(fs.readFileSync(process.env.SOK_CONFIG, 'utf8'));

const getTitle = (request, response) => response.status(200).send(competitionConf.title);

const getRules = (request, response) => response.status(200).send(competitionConf.rules);

const getTimeRange = (request, response) => {
    response.status(200).send({ start: competitionConf.startTime, end: competitionConf.endTime });
};

const getFreeze = (request, response) => {
    const freezeDate = new Date(Date.parse(competitionConf.endTime));
    response.status(200).send(competitionConf.freeze && freezeDate < new Date());
};

const getFreezeTime = (request, response) => {
    response.status(200).send(competitionConf.freezeTime);
};

const edit = async (request, response) => {
    const { id, title, rules, start, end, freeze, freezeTime } = request.body;

    const admin = await isAdminUtil(id);
    if (!admin) {
        return response.status(403).send('You dont have permissions');
    }
    competitionConf.title = title;
    competitionConf.rules = rules;
    competitionConf.startTime = start;
    competitionConf.endTime = end;
    competitionConf.freeze = freeze;
    competitionConf.freezeTime = freezeTime;
    fs.writeFileSync(process.env.SOK_CONFIG, yaml.dump(competitionConf));
    return response.status(201).send('Competition updated');
};

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, './uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, 'icon.png');
    },
});

const upload = multer({ storage });

const uploadIcon = async (request, response) => {
    const { id } = request.body;

    const admin = await isAdminUtil(id);
    if (!admin) {
        return response.status(403).send('You dont have permissions');
    }
    return upload.single('icon')(request, response, (err) => {
        if (err) {
            return response.status(400).send(err);
        }
        return response.status(200).send('File uploaded successfully.');
    });
};

const icon = async (request, response) => {
    const iconPath = path.resolve(__dirname, '/app/uploads', 'icon.png');
    return response.status(200).sendFile(iconPath);
};

module.exports = {
    getTitle,
    getRules,
    getTimeRange,
    getFreeze,
    getFreezeTime,
    edit,
    uploadIcon,
    icon,
};
