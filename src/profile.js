const mongoose = require("mongoose");
const Profile = mongoose.model("profile", require('./profileSchema'));

let profiles = {
    'RDesRoches': {
        headline: 'This is my headline!',
        email: 'foo@bar.com',
        zipcode: 12345,
        phone: '123-456-7890',
        dob: '128999122000',
        avatar: 'https://upload.wikimedia.org/wikipedia/en/thumb/4/4e/DWLeebron.jpg/220px-DWLeebron.jpg',
    }
};

function getProfileAttribute(req, res, attribute) {
    const username = req.params.user ? req.params.user : req.username;
    // const user = profiles[username];
    // if (user && user[attribute]) {
    //     let response = { username: username };
    //     response[attribute] = user[attribute];
    //     res.send(response);
    // } else {
    //     res.status(404).send({ error: 'User or attribute not found' });
    // }

    const user = Profile.findOne({ username });
    if (user && user[attribute]) {
        let response = { username };
        response[attribute] = user[attribute];
        res.send(response);
    } else {
        res.status(404).send({ error: 'User or attribute not found' });
    }
}

function updateProfileAttribute(req, res, attribute) {
    const username = req.params.user;
    // const user = profiles[username];
    // if (user) {
    //     user[attribute] = req.body[attribute];
    //     res.send({ username: username, [attribute]: user[attribute] });
    // } else {
    //     res.status(404).send({ error: 'User not found' });
    // }
    let user = Profile.findOne({ username });
    if (user) {
        user[attribute] = req.body[attribute];
        user.save();
        profiles[username][attribute] = user[attribute];
        res.send({ username, [attribute]: user[attribute] });
    } else {
        res.status(404).send({ error: 'User not found' });
    }
}

module.exports = (app) => {
    // GET endpoints
    app.get('/headline/:user?', (req, res) => getProfileAttribute(req, res, 'headline'));
    app.get('/email/:user?', (req, res) => getProfileAttribute(req, res, 'email'));
    app.get('/dob', (req, res) => getProfileAttribute(req, res, 'dob'));
    app.get('/zipcode/:user?', (req, res) => getProfileAttribute(req, res, 'zipcode'));
    app.get('/phone/:user?', (req, res) => getProfileAttribute(req, res, 'phone'));
    app.get('/avatar/:user?', (req, res) => getProfileAttribute(req, res, 'avatar'));

    // PUT endpoints
    app.put('/headline', (req, res) => updateProfileAttribute(req, res, 'headline'));
    app.put('/email', (req, res) => updateProfileAttribute(req, res, 'email'));
    app.put('/zipcode', (req, res) => updateProfileAttribute(req, res, 'zipcode'));
    app.put('/phone', (req, res) => updateProfileAttribute(req, res, 'phone'));
    app.put('/avatar', (req, res) => updateProfileAttribute(req, res, 'avatar'));
};
