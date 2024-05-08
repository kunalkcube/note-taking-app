import 'dotenv/config';
import express from 'express';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import './utils/db.js'
import User from './models/User.js';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use('/style', express.static('style'));

app.use(cookieParser());

const secretKey = process.env.JWT_SECRET;

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const authToken = req.cookies.authToken;
    if (!authToken) {
        req.user = null;
        next();
    } else {
        jwt.verify(authToken, secretKey, (err, decoded) => {
            if (err) {
                req.user = null;
                next();
            } else {
                req.user = decoded;
                next();
            }
        });
    }
};

const isAuthenticated = (req, res, next) => {
    const authToken = req.cookies.authToken;
    if (authToken) {
        res.redirect('/');
    } else {
        next();
    }
};

app.use(verifyToken);

app.get('/', async (req, res) => {
    try {
        const authToken = req.cookies.authToken;
        if (!authToken) {
            return res.render('index', { user: null });
        }

        const decodedToken = jwt.verify(authToken, secretKey);
        const user = await User.findOne({ username: decodedToken.username }, 'username name email');

        res.render('index', { user });
    } catch (err) {
        console.error(err);
        res.status(500).send('Something went wrong!');
    }
});


app.get('/signup', isAuthenticated, (req, res) => {
    res.render('signup');
});

app.post('/create-user', async (req, res) => {
    try {
        const { username, name, email, password } = req.body;

        const existingUser = await User.findOne({ $or: [{ username: username }, { email: email }] });
        if (existingUser) {
            res.status(400).send('Username or email already exists');
            return;
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            username: username,
            name: name,
            email: email,
            password: hashedPassword
        });
        await newUser.save();

        const authToken = jwt.sign({ username: username }, secretKey);
        res.cookie('authToken', authToken, { httpOnly: true });

        res.redirect('/');
    } catch (err) {
        console.error(err);
        res.status(500).send('Something went wrong!');
    }
});

app.get('/signin', isAuthenticated, (req, res) => {
    res.render('signin');
});

app.post('/signin', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email });

        if (!user) {
            res.status(400).send('Invalid email or password');
            return;
        }

        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            res.status(400).send('Invalid email or password');
            return;
        }

        const authToken = jwt.sign({ username: user.username }, secretKey);
        res.cookie('authToken', authToken, { httpOnly: true });
        res.redirect('/');
    } catch (err) {
        console.error(err);
        res.status(500).send('Something went wrong!');
    }
});

app.post('/logout', (req, res) => {
    res.clearCookie('authToken');
    res.redirect('/');
});

app.listen(3000, () => {
    console.log('App listening on port 3000!');
});