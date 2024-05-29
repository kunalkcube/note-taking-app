import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import User from '../models/User.js';
import nodemailer from 'nodemailer';

const router = express.Router();

const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
        user: process.env.User,
        pass: process.env.Password,
    },
});

// Request password reset page
router.get('/reset-password', (req, res) => {
    res.render('reset-password', { message: null });
});

// Handle password reset request
router.post('/reset-password', async (req, res, next) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.render('reset-password', { message: 'User with this email does not exist' });
        }

        const resetToken = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const resetUrl = `${req.protocol}://${req.get('host')}/reset-password/${resetToken}`;

        const message = {
            from: {
                name: "Kunal Kongkan Dev",
                address: process.env.User
            },
            to: user.email,
            subject: 'Password Reset Request',
            html: `<p>You requested a password reset. Click the link below to reset your password:</p>
                   <a href="${resetUrl}">Reset Password</a>`
        };

        // Send email using NodeMailer
        const response = await transporter.sendMail(message);

        res.render('reset-password', { message: 'Password reset link has been sent to your email' });
    } catch (err) {
        console.error('Error sending email:', err);
        next(err);
    }
});

// Reset password page
router.get('/reset-password/:token', async (req, res, next) => {
    try {
        const { token } = req.params;
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.render('reset-password', { message: 'Password reset token is invalid or has expired' });
        }

        res.render('new-password', { token, message: null });
    } catch (err) {
        next(err);
    }
});

// Handle new password
router.post('/reset-password/:token', async (req, res, next) => {
    try {
        const { token } = req.params;
        const { password } = req.body;

        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.render('new-password', { token, message: 'Password reset token is invalid or has expired' });
        }

        user.password = await bcrypt.hash(password, 10);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.render('new-password', { token, message: 'Password has been reset successfully' });
    } catch (err) {
        next(err);
    }
});

export default router;
