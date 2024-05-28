import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
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

// 2FA setup page
router.get('/setup-2fa', async (req, res, next) => {
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

        const secret = speakeasy.generateSecret({ length: 20 });
        user.twoFactorSecret = secret.base32;
        await user.save();

        qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
            res.render('setup-2fa', { user, qrCode: data_url, secret: secret.base32 });
        });
    } catch (err) {
        next(err);
    }
});

// Verify 2FA setup
router.post('/verify-2fa', async (req, res, next) => {
    try {
        const { token, secret } = req.body;
        const verified = speakeasy.totp.verify({ secret, encoding: 'base32', token });

        if (!verified) {
            return res.status(400).send('Invalid token');
        }

        const authToken = req.cookies.authToken;
        if (!authToken) {
            return res.redirect('/signin');
        }

        const decodedToken = jwt.verify(authToken, secretKey);
        const user = await User.findOne({ username: decodedToken.username });

        if (!user) {
            return res.redirect('/signin');
        }

        user.isTwoFactorEnabled = true;
        await user.save();

        res.redirect('/profile');
    } catch (err) {
        next(err);
    }
});

// Disable 2FA
router.post('/disable-2fa', async (req, res, next) => {
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

        user.isTwoFactorEnabled = false;
        user.twoFactorSecret = null; // Optionally clear the secret
        await user.save();

        res.redirect('/profile');
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
