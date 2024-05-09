import express from 'express';
import jwt from 'jsonwebtoken';
import Note from '../models/Note.js';
import User from '../models/User.js';

const router = express.Router();

const secretKey = process.env.JWT_SECRET;

router.post('/create', async (req, res, next) => {
    try {
        const authToken = req.cookies.authToken;
        if (!authToken) {
            res.status(401).send('Unauthorized');
            return;
        }

        const decodedToken = jwt.verify(authToken, secretKey);
        const user = await User.findOne({ username: decodedToken.username });

        const { title, content } = req.body;

        const newNote = new Note({
            title: title,
            content: content,
            author: user._id
        });

        await newNote.save();

        user.notes.push(newNote._id);
        await user.save();

        res.redirect('/');
    } catch (err) {
        next(err);
    }
});

router.get('/:_id', async (req, res, next) => {
    try {
        const noteId = req.params._id;
        const note = await Note.findById(noteId);

        if (!note) {
            res.status(404).send('Note not found');
            return;
        }

        res.render('note', { note });
    } catch (err) {
        next(err);
    }
});

router.get('/edit/:_id', async (req, res, next) => {
    try {
        const noteId = req.params._id;
        const note = await Note.findById(noteId);

        if (!note) {
            res.status(404).send('Note not found');
            return;
        }

        res.render('edit-note', { note });
    } catch (err) {
        next(err);
    }
});

router.post('/update', async (req, res, next) => {
    try {
        const { noteId, title, content } = req.body;
        const updatedNote = await Note.findByIdAndUpdate(
            noteId,
            { title: title, content: content },
            { new: true }
        );

        if (!updatedNote) {
            res.status(404).send('Note not found');
            return;
        }

        res.redirect('/');
    } catch (err) {
        next(err);
    }
});

router.post('/delete', async (req, res, next) => {
    try {
        const { noteId } = req.body;
        const deletedNote = await Note.findByIdAndDelete(noteId);

        if (!deletedNote) {
            res.status(404).send('Note not found');
            return;
        }

        const user = await User.findOne({ notes: noteId });

        if (user) {
            user.notes.pull(noteId);
            await user.save();
        }

        res.redirect('/');
    } catch (err) {
        next(err);
    }
});

export default router;
