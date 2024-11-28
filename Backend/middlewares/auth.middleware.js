const userModel = require('../models/user.model');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();
const BlacklistTokenModel = require('../models/blacklistToken.model');


module.exports.authUser = async (req, res, next) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const isBlacklisted = await BlacklistTokenModel.findOne({ token: token });
    if (isBlacklisted) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await userModel.findById(decoded._id);
        if (!user) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
};
