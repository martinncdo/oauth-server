const mongoose = require('mongoose');

const oauthUserSchema = new mongoose.Schema({ email: String, refresh_token: String });

module.exports = {
    oauthUserSchema
}