const express = require('express')
const routes = express.Router()


// article routes
const articleRoute = require('./article/articleRoute')
routes.use("/articles", articleRoute)

// auth routes
const authRoutes = require('./auth/authRoute')
routes.use("/", authRoutes)

module.exports = routes