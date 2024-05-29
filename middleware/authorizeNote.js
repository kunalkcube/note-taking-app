import jwt from 'jsonwebtoken';
import Note from '../models/Note.js';
import User from '../models/User.js';

const secretKey = process.env.JWT_SECRET;

const authorizeNote = async (req, res, next) => {
    try {
        const authToken = req.cookies.authToken;
        if (!authToken) {
            return res.status(401).send('Unauthorized');
        }

        const decodedToken = jwt.verify(authToken, secretKey);
        const user = await User.findOne({ username: decodedToken.username });
        if (!user) {
            return res.status(401).send('Unauthorized');
        }

        const noteId = req.params._id || req.body.noteId;
        const note = await Note.findById(noteId);

        if (!note) {
            return res.status(404).send('Note not found');
        }

        const isAuthor = note.author.equals(user._id);
        const sharedWithUser = note.sharedWith.find(sharedUser => sharedUser.email === user.email);

        if (!isAuthor && (!sharedWithUser)) {
            return res.status(403).send('Forbidden');
        }

        req.note = note;
        next();
    } catch (err) {
        next(err);
    }
};

export default authorizeNote;
