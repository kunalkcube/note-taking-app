import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import isAuthenticated from '../middleware/isAuthenticated.js';

const router = express.Router();
const secretKey = process.env.JWT_SECRET;

router.get('/', isAuthenticated, (req, res) => {
    res.render('signin');
});

router.post('/', async (req, res, next) => {
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
        next(err);
    }
});

export default router;