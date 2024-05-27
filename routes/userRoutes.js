import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import Note from '../models/Note.js';
import verifyToken from '../middleware/verifyToken.js';

const router = express.Router();
const secretKey = process.env.JWT_SECRET;

// Middleware to check if user is authenticated
router.use(verifyToken);

// Profile page
router.get('/', async (req, res, next) => {
    try {
        const authToken = req.cookies.authToken;
        if (!authToken) {
            return res.redirect('/signin');
        }

        const decodedToken = jwt.verify(authToken, secretKey);
        const user = await User.findOne({ username: decodedToken.username });

        if (!user) {
            return res.redirect('/signin');
        }

        res.render('profile', { user });
    } catch (err) {
        next(err);
    }
});

// Edit profile page
router.get('/edit', async (req, res, next) => {
    try {
        const authToken = req.cookies.authToken;
        if (!authToken) {
            return res.redirect('/signin');
        }

        const decodedToken = jwt.verify(authToken, secretKey);
        const user = await User.findOne({ username: decodedToken.username });

        if (!user) {
            return res.redirect('/signin');
        }

        res.render('edit-profile', { user });
    } catch (err) {
        next(err);
    }
});

// Update profile
router.post('/edit', async (req, res, next) => {
    try {
        const { name, password } = req.body;
        const authToken = req.cookies.authToken;

        if (!authToken) {
            return res.redirect('/signin');
        }

        const decodedToken = jwt.verify(authToken, secretKey);
        const user = await User.findOne({ username: decodedToken.username });

        if (!user) {
            return res.redirect('/signin');
        }

        user.name = name;
        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            user.password = hashedPassword;
        }
        await user.save();

        res.redirect('/profile');
    } catch (err) {
        next(err);
    }
});

// Delete account
router.post('/delete', async (req, res, next) => {
    try {
        const authToken = req.cookies.authToken;

        if (!authToken) {
            return res.redirect('/signin');
        }

        const decodedToken = jwt.verify(authToken, secretKey);
        const user = await User.findOne({ username: decodedToken.username });

        if (!user) {
            return res.redirect('/signin');
        }

        await Note.deleteMany({ author: user._id });
        await User.deleteOne({ _id: user._id });

        res.clearCookie('authToken');
        res.redirect('/');
    } catch (err) {
        next(err);
    }
});

export default router;
