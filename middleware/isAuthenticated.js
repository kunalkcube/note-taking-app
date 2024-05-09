const isAuthenticated = (req, res, next) => {
    const authToken = req.cookies.authToken;
    if (authToken) {
        res.redirect('/');
    } else {
        next();
    }
};

export default isAuthenticated;
