const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../users/users-model');
const { JWT_SECRET } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, async(req, res, next) => {
    /**
      [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

      response:
      status 201
      {
        "user"_id: 3,
        "username": "anna",
        "role_name": "angel"
      }
     */
    try {
        const { username, password, role_name } = req.body;
        const validUser = await User.findBy({ username });
        if (!validUser) {
            const addUser = await User.add({
                username,
                password: await bcrypt.hash(password, 10),
                role_name
            })
            return res.status(201).json(addUser)
        } else {
            return res.status(400).json({ message: 'Username already taken' })
        }
    } catch (err) {
        next(err)
    }
});


router.post("/login", checkUsernameExists, async(req, res, next) => {
    /**
      [POST] /api/auth/login { "username": "sue", "password": "1234" }

      response:
      status 200
      {
        "message": "sue is back!",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
      }

      The token must expire in one day, and must provide the following information
      in its payload:

      {
        "subject"  : 1       // the user_id of the authenticated user
        "username" : "bob"   // the username of the authenticated user
        "role_name": "admin" // the role of the authenticated user
      }
     */
    const { username, password } = req.body;
    try {
        const user = await User.findBy({ username });
        const userPass = await bcrypt.compare(password, user.password);
        if (!user) {
            return res.status(400).json({ message: 'cannot find that username' })
        } else if (!userPass) {
            return res.status(400).status({ message: 'Incorrect password' })
        } else {
            const token = jwt.sign({ //generate token if valid user
                subject: user.user_id,
                username: user.username,
                role_name: user.role_name
            }, JWT_SECRET);
            res.cookie('token', token);
            return res.json(200).json({ message: `${username} is back!` })
        }

    } catch (err) {
        next(err)
    }
});

module.exports = router;