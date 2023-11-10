const User = require('../models/user');
const Cryptr = require('cryptr');
const cryptr = new Cryptr('yournotsave');
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'oaiwehreareawhregowio234q927a4g0q8234'

module.exports = {
  register: async (req, res) => {
    const { username, email, password } = req.body;

    try {
      const existingUser = await User.findOne({ $or: [{ email }, { username }] });
      if (existingUser) {
        return res.status(400).json({ error: 'Email or username is already registered' });
      }

      const encryptedPassword = cryptr.encrypt(password);
      const user = await User.create({ username, email, password: encryptedPassword });
      const token = generateToken(user.id);
      res.json({ user, token });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  },

  login: async (req, res) => {
    const { email, password } = req.body;

    try {
      const user = await User.findOne({ email });
      if (user) {
        const decryptedPassword = cryptr.decrypt(user.password);

        if (decryptedPassword === password) {
          const token = generateToken(user.id);
          res.json({ user, token });
        } else {
          res.status(401).json({ error: 'Invalid credentials' });
        }
      } else {
        res.status(401).json({ error: 'Invalid credentials' });
      }
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  },
};

function generateToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '1h' });
}
