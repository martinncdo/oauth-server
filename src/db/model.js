const mongoose = require('mongoose');
const oauthUser = require('./schemas/oauthUser.js');
const oauthUserSchema = oauthUser.oauthUserSchema;

// Conectar a la base de datos una vez al iniciar el módulo
mongoose.connect('mongodb://127.0.0.1:27017/worklink', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log("Connection is successful");
  })
  .catch(error => {
    console.error("Database connection error:", error);
  });

// Definir el modelo una vez
const oauthUserModel = mongoose.model('oAuthUser', oauthUserSchema, 'oauthUsers');

// Función para crear un usuario OAuth
async function createOAuthUser(email, refresh_token) {
  try {
    const user = await oauthUserModel.findOneAndUpdate(
      { email: email },
      { email: email, refresh_token: refresh_token },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );
  } catch (error) {
    console.error('Error creating user:', error);
  }
}

// Función para buscar un usuario por email
async function findOAuthUserByEmail(email) {
  try {
    const user = await oauthUserModel.findOne({ email: email });
    if (user) {
      console.log('User found:', user);
      return user;
    } else {
      console.log('User not found');
      return null;
    }
  } catch (error) {
    console.error('Error finding user:', error);
    throw error; // Propagar el error para manejarlo en el nivel superior
  }
}

module.exports = {
  createOAuthUser,
  findOAuthUserByEmail
};
