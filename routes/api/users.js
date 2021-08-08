import express from 'express';
const router = express.Router();
import gravatar from 'gravatar';
import jwt from 'jsonwebtoken';
import config from 'config';
import bcrypt from 'bcryptjs';
import { check, validationResult } from 'express-validator';
import normalize from 'normalize-url';

const User = require('../../models/User');

// @route       POST api/users
// @desc        Register user
// @access      Public
router.post(
    '/',
    check('name', 'Name is required').notEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check(
        'password',
        'Please enter a password with 6 or more characters'
    ).isLength({ min: 6 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email, password } = req.body;

        try {
            let user = await User.findOne({ email });

            // see if the user exists
            if (user) {
                return res.status(400).json({ errors: [{ msg: 'User already exists' }] });
            }

            // get user gravatar
            const avatar = normalize(
                gravatar.url(email, {
                    s: '200',
                    r: 'pg',
                    d: 'mm'
                }),
                { forceHttps: true }
            );

            user = new User({
                name,
                email,
                avatar,
                password
            });

            // encrypt password
            const salt = await bcrypt.genSalt(10);

            user.password = await bcrypt.hash(password, salt);

            await user.save();

            // return jsonwebtoken
            const payload = {
                user: {
                    id: user.id,
                    name: user.name
                }
            };

            jwt.sign(
                payload,
                config.get('jwtSecret'),
                { expiresIn: '1 days' },
                (err, token) => {
                    if (err) throw err;
                    res.json({ token });
                }
            );
        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server error');
        }

    }
);

module.exports = router;