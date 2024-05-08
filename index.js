import 'dotenv/config';
import express from 'express';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import './utils/db.js'
import User from './models/User.js';
import Note from './models/Note.js';

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use('/style', express.static('style'));
app.use('/script', express.static('script'));

app.use(cookieParser());

const secretKey = process.env.JWT_SECRET;

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const authToken = req.cookies.authToken;
    if (!authToken) {
        req.user = null;
        next();
    } else {
        jwt.verify(authToken, secretKey, (err, decoded) => {
            if (err) {
                req.user = null;
                next();
            } else {
                req.user = decoded;
                next();
            }
        });
    }
};

const isAuthenticated = (req, res, next) => {
    const authToken = req.cookies.authToken;
    if (authToken) {
        res.redirect('/');
    } else {
        next();
    }
};

app.use(verifyToken);

app.get('/', async (req, res) => {
    try {
        const authToken = req.cookies.authToken;
        if (!authToken) {
            return res.render('index', { user: null, notes: [] });
        }

        const decodedToken = jwt.verify(authToken, secretKey);
        const user = await User.findOne({ username: decodedToken.username }, 'username name email');

        if (!user || !user._id) {
            return res.render('index', { user: null, notes: [] });
        }

        const notes = await Note.find({ author: user._id }).lean();

        res.render('index', { user, notes });
    } catch (err) {
        console.error(err);
        res.status(500).send('Something went wrong!');
    }
});


app.get('/signup', isAuthenticated, (req, res) => {
    res.render('signup');
});

app.post('/create-user', async (req, res) => {
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

        const authToken = jwt.sign({ username: username }, secretKey);
        res.cookie('authToken', authToken, { httpOnly: true });

        res.redirect('/');
    } catch (err) {
        console.error(err);
        res.status(500).send('Something went wrong!');
    }
});

app.get('/signin', isAuthenticated, (req, res) => {
    res.render('signin');
});

app.post('/signin', async (req, res) => {
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
        console.error(err);
        res.status(500).send('Something went wrong!');
    }
});

app.post('/create-note', async (req, res) => {
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
        console.error(err);
        res.status(500).send('Something went wrong!');
    }
});

app.get('/note/:_id', async (req, res) => {
    try {
        const noteId = req.params._id;
        const note = await Note.findById(noteId);

        if (!note) {
            res.status(404).send('Note not found');
            return;
        }

        res.render('note', { note });
    } catch (err) {
        console.error(err);
        res.status(500).send('Something went wrong!');
    }
});


app.get('/edit-note/:_id', async (req, res) => {
    try {
        const noteId = req.params._id;
        const note = await Note.findById(noteId);

        if (!note) {
            res.status(404).send('Note not found');
            return;
        }

        res.render('edit-note', { note });
    } catch (err) {
        console.error(err);
        res.status(500).send('Something went wrong!');
    }
});

app.post('/update-note', async (req, res) => {
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
        console.error(err);
        res.status(500).send('Something went wrong!');
    }
});

app.post('/delete-note', async (req, res) => {
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
        console.error(err);
        res.status(500).send('Something went wrong!');
    }
});


app.post('/logout', (req, res) => {
    res.clearCookie('authToken');
    res.redirect('/');
});

app.listen(3000, () => {
    console.log('App listening on port 3000!');
});