import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import speakeasy from 'speakeasy';
import isAuthenticated from '../middleware/isAuthenticated.js';

const router = express.Router();
const secretKey = process.env.JWT_SECRET;
const cookieMaxAge = 86400 * 30 * 1000;

// Sign-in page
router.get('/', isAuthenticated, (req, res) => {
    res.render('signin');
});

// Sign-in logic
router.post('/', async (req, res, next) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).send('Invalid email or password');
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).send('Invalid email or password');
        }

        if (user.isTwoFactorEnabled) {
            const tempToken = jwt.sign({ username: user.username }, secretKey, { expiresIn: '10m' });
            res.cookie('tempAuthToken', tempToken, { httpOnly: true, maxAge: 10 * 60 * 1000 }); // 10 minutes
            return res.redirect('/signin/signin-verify-2fa');
        }

        const authToken = jwt.sign({ username: user.username }, secretKey, { expiresIn: '30d' });
        res.cookie('authToken', authToken, { httpOnly: true, maxAge: cookieMaxAge });

        res.redirect('/');
    } catch (err) {
        next(err);
    }
});

// 2FA verification page
router.get('/signin-verify-2fa', (req, res) => {
    res.render('signin-verify-2fa');
});

// 2FA verification logic
router.post('/signin-verify-2fa', async (req, res, next) => {
    try {
        const { token } = req.body;
        const tempAuthToken = req.cookies.tempAuthToken;

        if (!tempAuthToken) {
            return res.redirect('/signin');
        }

        const decodedToken = jwt.verify(tempAuthToken, secretKey);
        const user = await User.findOne({ username: decodedToken.username });

        if (!user) {
            return res.redirect('/signin');
        }

        const verified = speakeasy.totp.verify({ secret: user.twoFactorSecret, encoding: 'base32', token });
        if (!verified) {
            return res.status(400).send('Invalid 2FA token');
        }

        const authToken = jwt.sign({ username: user.username }, secretKey, { expiresIn: '30d' });
        res.cookie('authToken', authToken, { httpOnly: true, maxAge: cookieMaxAge });
        res.clearCookie('tempAuthToken');

        res.redirect('/');
    } catch (err) {
        next(err);
    }
});

export default router;
