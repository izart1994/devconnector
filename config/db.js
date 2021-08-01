const mongoose = require('mongoose');
const config = require('config');
const mongoURI =  "mongodb+srv://izart1994:124578@devconnector.3bwjv.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"

const connectDB = async () => {
    try {
        await mongoose.connect(mongoURI, {
            useNewUrlParser: true,
            useCreateIndex: true,
            useFindAndModify: false,
            useUnifiedTopology: true
        });

        console.log('MongoDB Connected...');
    } catch (err) {
        console.error(err.message);
        // Exit process with failure
        process.exit(1);
    }
};

module.exports = connectDB;