const auth = require('./src/auth');
const articles = require('./src/articles');
const profile = require('./src/profile');
const following = require('./src/following');

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const connectionString = 'mongodb+srv://ya15://@cluster0.n2ntn.mongodb.net/?retryWrites=true&w=majority'; //removed password

// const hello = (req, res) => res.send({ hello: 'world' });

// const addUser = (req, res) => {
//     (async () => {
//         const connector = mongoose.connect(connectionString, { useNewUrlParser: true, useUnifiedTopology: true });
//         // add a user to the database
//         const {username, created} = req.body;
//         const user = new User({ username, created });
//         await user.save();
//         await (connector.then(()=> {}));
//         res.send({name: username});
//     })();
// };

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());
// app.get('/', hello);
// app.post('/users/:uname', addUser);
auth(app);
articles(app);
profile(app);
following(app);

// Get the port from the environment, i.e., Heroku sets it
const port = process.env.PORT || 3000;

// TODO: put password back
mongoose.connect('mongodb+srv://ya15://@cluster0.n2ntn.mongodb.net/?retryWrites=true&w=majority');

const server = app.listen(port, () => {
     const addr = server.address();
     console.log(`Server listening at http://${addr.address}:${addr.port}`)
});