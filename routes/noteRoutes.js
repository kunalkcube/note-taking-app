import express from 'express';
import jwt from 'jsonwebtoken';
import Note from '../models/Note.js';
import User from '../models/User.js';
import authorizeNote from '../middleware/authorizeNote.js';

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

router.get('/:_id', authorizeNote, async (req, res, next) => {
    try {
        const shareableLink = `${req.protocol}://${req.get('host')}/note/shared/${req.note._id}`;
        res.render('note', { note: req.note, shareableLink });
    } catch (err) {
        next(err);
    }
});

router.get('/edit/:_id', authorizeNote, async (req, res, next) => {
    try {
        res.render('edit-note', { note: req.note });
    } catch (err) {
        next(err);
    }
});

router.post('/update', authorizeNote, async (req, res, next) => {
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

router.post('/delete', authorizeNote, async (req, res, next) => {
    try {
        const deletedNote = await Note.findByIdAndDelete(req.note._id);

        if (!deletedNote) {
            res.status(404).send('Note not found');
            return;
        }

        const user = await User.findOne({ notes: req.note._id });

        if (user) {
            user.notes.pull(req.note._id);
            await user.save();
        }

        res.redirect('/');
    } catch (err) {
        next(err);
    }
});

router.post('/share', authorizeNote, async (req, res, next) => {
    try {
        const { email, permission } = req.body;
        const note = req.note;

        const alreadyShared = note.sharedWith.find(user => user.email === email);
        if (alreadyShared) {
            res.status(400).send('Note already shared with this user');
            return;
        }

        note.sharedWith.push({ email, permission });
        await note.save();

        res.redirect(`/note/${note._id}`);
    } catch (err) {
        next(err);
    }
});

router.post('/remove-shared-user', authorizeNote, async (req, res, next) => {
    try {
        const { email } = req.body;
        const note = req.note;

        note.sharedWith = note.sharedWith.filter(user => user.email !== email);
        await note.save();

        res.redirect(`/note/${note._id}`);
    } catch (err) {
        next(err);
    }
});

// Route to view shared note
router.get('/shared/:_id', async (req, res, next) => {
    try {
        const noteId = req.params._id;
        const authToken = req.cookies.authToken;
        const decodedToken = jwt.verify(authToken, secretKey);
        const user = await User.findOne({ username: decodedToken.username });
        const note = await Note.findById(noteId);

        if (!note) {
            res.status(404).send('Note not found');
            return;
        }

        const sharedWithUser = note.sharedWith.find(sharedUser => sharedUser.email === user.email);
        if (!sharedWithUser) {
            res.status(403).send('You do not have access to this note');
            return;
        }

        res.render('shared-note', { note, permission: sharedWithUser.permission });
    } catch (err) {
        next(err);
    }
});

export default router;
