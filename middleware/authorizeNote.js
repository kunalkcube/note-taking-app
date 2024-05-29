import jwt from 'jsonwebtoken';
import Note from '../models/Note.js';
import User from '../models/User.js';

const secretKey = process.env.JWT_SECRET;

const authorizeNote = async (req, res, next) => {
    try {
        const authToken = req.cookies.authToken;
        if (!authToken) {
            res.status(401).send('Unauthorized');
            return;
        }

        const decodedToken = jwt.verify(authToken, secretKey);
        const user = await User.findOne({ username: decodedToken.username });
        const noteId = req.params._id || req.body.noteId;
        const note = await Note.findById(noteId);

        if (!note) {
            res.status(404).send('Note not found');
            return;
        }

        if (!note.author.equals(user._id)) {
            res.status(403).send('Forbidden');
            return;
        }

        req.note = note;
        next();
    } catch (err) {
        next(err);
    }
};

export default authorizeNote;
