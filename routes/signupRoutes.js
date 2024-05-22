import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import isAuthenticated from '../middleware/isAuthenticated.js';

const router = express.Router();
const secretKey = process.env.JWT_SECRET;
const cookieMaxAge = 86400 * 30 * 1000;

router.get('/', isAuthenticated, (req, res) => {
    res.render('signup');
});

router.post('/create-user', async (req, res, next) => {
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

        const authToken = jwt.sign({ username: username }, secretKey, { expiresIn: '30d' });
        res.cookie('authToken', authToken, { httpOnly: true, maxAge: cookieMaxAge });

        res.redirect('/');
    } catch (err) {
        next(err);
    }
});

export default router;
