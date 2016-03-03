/*!
 * Mongoose Pythia
 */


var pythia = require('pythia-sdk');

module.exports = exports = function pythiaPlugin (schema, pythiaClientSelector, options) {

  var passwordField;
  var pythiaServerURL;

  if (options && options.pythiaServerURL) {
    pythiaServerURL = options.pythiaServerURL;
  }
  else {
    pythiaServerURL = 'http://pythia.cornelltech.io';
  }

  //can this fail? What happens when it does?
  pythia.setup(pythiaClientSelector, pythiaServerURL);

  if (options && options.pythiaPasswordField) {
    passwordField = options.pythiaPasswordField;
  }
  else {
    passwordField = 'password'
  }

  var itemsToAdd = {};
  itemsToAdd[passwordField] = String;

  schema.add(itemsToAdd);

/**
 * If the password has been modified, hashes the password, then sends to Pythia
 * server to be hashed again. The resulting hashed password is stored in the db.
 * This is called prior to saving the user object
 */
  schema.pre('save', function(next) {
      var user = this;

      var password = user.get(passwordField);
      if (!password) {
        return next(new Error("Password field is inconsistent"));
      }

      if (!user.isModified(passwordField)) {
          return next();
      }

      pythia.hash(password, function(err, hash) {
          if (err) {
              return next(new Error(err));
          }
          user.set(passwordField, hash);
          next();
      });
  });

/**
 * Sets the password (plain text) for the user
 * This is called prior to saving the user object
 * NOTE: the presave function will be invoked when the object is saved
 *
 * @param {string} password
 * @api public
 */
  schema.methods.setPassword = function(password) {
    var user = this;
    user.set(passwordField, password);
  };

/**
 * Checks to see if this password matches the stored password for the user
 * The specified password is hashed then sent to the Pythia server and hashed
 * again. The result is compared to the password hash stored in the database for
 * the user. When finished, cb is invoked with an error (if any) and a
 * boolean specifying whether the password hashes match.
 *
 * @param {string} password
 * @param {Function} cb
 * @api public
 */
  schema.methods.comparePassword = function(password, cb) {

    var user = this;
    var savedPassword = user.get(passwordField);
    if (!savedPassword) {
      return next(new Error("Password field is inconsistent"));
    }

    pythia.compare(password, savedPassword, function(err, isMatch) {

      if (err) {
          return cb(err);
      }

      if (isMatch) {
          return cb(null, true);
      }

      cb(null, false);

    });
  };
}
