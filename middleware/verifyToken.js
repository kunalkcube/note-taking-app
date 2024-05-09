import 'dotenv/config';
import jwt from 'jsonwebtoken';

const secretKey = process.env.JWT_SECRET;

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

export default verifyToken;
