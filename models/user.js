const Mongoose = require('mongoose')

var Schema = new Mongoose.Schema({
    username: { type: String },
    password: { type: String },
    email: { type: String },
    firstname: { type: String },
    lastname: { type: String },
    age: { type: Number },
})

const User = Mongoose.model('User', Schema)

module.exports = User