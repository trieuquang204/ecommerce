const User = require('../models/user')
const asyncHandler = require('express-async-handler')
const {generateAccessToken, generateRefreshAccessToken} = require('../middlewares/jwt')
const jwt = require('jsonwebtoken')
const sendMail = require('../ultils/sendMail')
const crypto = require('crypto')


const register = asyncHandler(async(req, res) => {
  const {email, password, firstname, lastname } = req.body

  if(!email || !password || !firstname || !lastname) {
    return res.status(400).json({
      sucess: false,
      mes: 'Missing inputs'
    })
  }
  const user = await User.findOne({email})
  if(user) {
    throw new Error('User already exists')
  }
  else {
    const newUser = await User.create(req.body)
    return res.status(200).json({
      sucess: newUser ? true : false,
      mes: newUser ? 'Register is successfully' : 'Something went wrong'
    })
  }
})

const login = asyncHandler(async(req, res) => {
  const {email, password} = req.body

  if(!email || !password) {
    return res.status(400).json({
      sucess: false,
      mes: 'Missing inputs'
    })
  }

  // Refresh token dung de cap moi accessToken khi accessToken het han
  // accessToken dung de xac thuc nguoi dung, quyen va phan quyen nguoi dung
  const response = await User.findOne({email})
  if(response && await response.isCorrectPassword(password)) {
    // Khi tk va mat khau dung dang nhap thanh cong. Tao mot cai access token va fresh token. Luu fresh token vaof cookie va tra ve access token cho nguoi dung
    const { password, role, ...userData} = response.toObject()
    const accessToken = generateAccessToken(response._id, role)
    const refreshToken = generateRefreshAccessToken(response._id)
    // Luu refresh vao db
    await User.findByIdAndUpdate(response._id, { refreshToken}, { new: true })
    // Luu refresh vao cookie
    res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000})

    return res.status(200).json({
      sucess: true,
      accessToken,
      userData
    })
  } else {
    throw new Error('Invalid credentials!')
  }
})


const getCurrent = asyncHandler(async(req, res) => {
  const { _id } = req.user
  const user = await User.findById(_id).select('-refreshToken -password -role')

  return res.status(200).json({
    success: false,
    rs: user ? user : "User not found!"
  })
})

const refreshAccessToken = asyncHandler(async (req, res) => {
  // Lay token tu cookie
  const cookie = req.cookies
  if(!cookie && !cookie.refreshToken) {
    throw new Error('No refresh token in cookies')
  }
  const rs = await jwt.verify(cookie.refreshToken, process.env.JWT_SECRET)
  const response = await User.findOne({_id: rs._id, refreshToken: cookie.refreshToken})
  return res.status(200).json({
    success: response ? true : false,
    newAccessToken: response ? generateAccessToken(response._id, response.role) : 'Refresh token not match!'
  })

  // jwt.verify(cookie.refreshToken, process.env.JWT_SECRET, async (err, decode) => {
  //   if(err) throw new Error('Invalid refresh token')
  //   // Check token co giong vs token da luu trong db k

  //   const response = await User.findOne({_id: decode._id, refreshToken: cookie.refreshToken})
  //   return res.status(200).json({
  //     success: response ? true : false,
  //     newAccessToken: response ? generateAccessToken(response._id, response.role) : 'Refresh token not match!'
  //   })
  // })
})

const logout = asyncHandler(async (req, res) => {
  const cookie = req.cookies
  if(!cookie || !cookie.refreshToken) throw new Error('No refresh token in cookies')

  // Xoa refreshToken trong DB
  await User.findOneAndUpdate({refreshToken: cookie.refreshToken}, { refreshToken: ''}, { new: true })
  // Xoa refreshToken o cookie trinh duyet
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: true
  })
  return res.status(200).json({
    success: true,
    mes: 'Logout successfully!'
  })
})

// Reset password
// Client gui len email dung de dang ky
// Server check xem email do co hop le hay k
// Neu hop le se gui mail kem theo link (password change token )
// Clent check mail va click vao link da gui trong mail do
// Khi click vao link trong email do client gui api kem theo token do
// Server check xem token co giong vs token da gui truoc do k
// Cho thay doi
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.query
  if(!email) throw new Error('Missing email')

  const user = await User.findOne({email})
  if(!user) throw new Error('User not found!')
  const resetToken = user.createPasswordChangedToken()
  await user.save()

  const html = `Xin vui long click de doi mat khau. Het han sau 15p. <a href=${process.env.URL_SERVER}/api/user/reset-password/${resetToken}>Click here</a>`

  const data = {
    email,
    html
  }

  const rs = await sendMail(data)
  return res.status(200).json({
    success: true,
    rs
  })
})

const resetPassword = asyncHandler(async ( req, res ) => {
  const { password, token } = req.body
  if(!password || !token) throw new Error('Missing inputs')

  const passwordResetToken = crypto.createHash('sha256').update(token).digest('hex');
  const user = await User.findOne({passwordResetToken, passwordResetExpires: {$gt: Date.now() }})
  if(!user) throw new Error('Invalid reset token')
  user.password = password
  user.passwordResetToken = undefined
  user.passwordChangedAt = Date.now()
  user.passwordResetExpires = undefined
  await user.save()

  return res.status(200).json({
    success: user ? true : false,
    mes: user ? 'Updated password' : 'Something went wrong'
  })
})

module.exports = {
  register,
  login,
  getCurrent,
  refreshAccessToken,
  logout,
  forgotPassword,
  resetPassword
}