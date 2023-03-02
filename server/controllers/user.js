const User = require('../models/user')
const asyncHandler = require('express-async-handler')
const {generateAccessToken, generateRefreshAccessToken} = require('../middlewares/jwt')


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

module.exports = {
  register,
  login,
  getCurrent
}