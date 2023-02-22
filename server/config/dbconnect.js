const { default: mongoose } = require('mongoose')
mongoose.set('strictQuery', false)

const dbConnect = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI)

    if(conn.connection.readyState === 1) {
      console.log('connect success')
    } else {
      console.log('connect fail')
    }
  } catch (error) {
    // console.log(error)
    throw new Error(error)
  }
}

module.exports = dbConnect