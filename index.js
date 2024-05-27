import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import './utils/db.js'
import User from './models/User.js';
import Note from './models/Note.js';
import verifyToken from './middleware/verifyToken.js';
import errorHandler from './middleware/errorHandler.js';
import noteRoutes from './routes/noteRoutes.js';
import signupRoutes from './routes/signupRoutes.js';
import signinRoutes from './routes/signinRoutes.js';
import logoutRoute from './routes/logoutRoute.js';
import userRoutes from './routes/userRoutes.js';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use('/style', express.static('style'));
app.use('/script', express.static('script'));

app.use(cookieParser());

const secretKey = process.env.JWT_SECRET;

app.use(verifyToken);

app.get('/', async (req, res, next) => {
    try {
        const authToken = req.cookies.authToken;
        if (!authToken) {
            return res.render('index', { user: null, notes: [] });
        }

        const decodedToken = jwt.verify(authToken, secretKey);
        const user = await User.findOne({ username: decodedToken.username }, 'username name email');

        if (!user || !user._id) {
            return res.render('index', { user: null, notes: [] });
        }

        const notes = await Note.find({ author: user._id }).lean();

        res.render('index', { user, notes });
    } catch (err) {
        next(err);
    }
});


app.use('/signup', signupRoutes);

app.use('/signin', signinRoutes);

app.use('/note', noteRoutes);

app.use('/profile', userRoutes);

app.use('/logout', logoutRoute);

app.use(errorHandler);

app.listen(3000, () => {
    console.log('App listening on port 3000!');
});