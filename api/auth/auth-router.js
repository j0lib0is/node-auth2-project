const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs");
const users = require('../users/users-model');

router.post("/register", validateRoleName, (req, res, next) => {
  const user = req.body;
  const hash = bcrypt.hashSync(user.password, 12);
  user.password = hash;

  const constructedUser = {
    username: user.username.trim(),
    password: user.password.trim(),
    role_name: req.role_name
  }

  users.add(constructedUser)
    .then(newUser => {
      req.user = newUser;
      res.status(201).json(newUser);
    })
    .catch(next);
    
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
});

function generateToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  };

  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' });
}


router.post("/login", checkUsernameExists, (req, res, next) => {
  const { username, password } = req.body;

  if (bcrypt.compareSync(password, req.user.password)) {
    const token = generateToken(req.user);
    res.json({ message: `${username} is back!`, token });
  } else {
    next({ status: 401, message: 'Invalid credentials' });
  }
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
});

module.exports = router;
