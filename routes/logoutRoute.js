import express from 'express';

const router = express.Router();

router.post('/', (req, res) => {
    res.clearCookie('authToken');
    res.redirect('/');
});

export default router;
