const jwt = require('jsonwebtoken')

const generateAccessToken = (uid, role) => jwt.sign({_id: uid, role}, process.env.JWT_SECRET, { expiresIn: '3d'})
// const generateAccessToken = (uid, role) => jwt.sign({_id: uid, role}, process.env.JWT_SECRET, { expiresIn: '15s'})
const generateRefreshAccessToken = (uid) => jwt.sign({_id: uid}, process.env.JWT_SECRET, { expiresIn: '7d'})
// const generateRefreshAccessToken = (uid) => jwt.sign({_id: uid}, process.env.JWT_SECRET, { expiresIn: '60s'})

module.exports = {
  generateAccessToken,
  generateRefreshAccessToken
}