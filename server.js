const express = require('express');
const app = express();
const port = 7500;
const cors = require('cors')
const morgan = require('morgan')

app.use(express.json())
app.use(cors())
app.use(morgan('dev'))


const ConnectionMongoDB = require('./models/mongoDB/ConnectionMongoDB')
ConnectionMongoDB()

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

// Routes
const Routes = require('./routes/routes')
app.use('/api/v1', Routes)