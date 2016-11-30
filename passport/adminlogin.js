var LocalStrategy = require('passport-local').Strategy;
var User = require('../models/User');
//Salasanan kryptaus/dekryptaus moduuli
var bCrypt = require('bcrypt-nodejs');

module.exports = function(passport){
// passport/login.js
passport.use('adminlogin', new LocalStrategy({
	usernameField : 'email',
	passwordField : 'password',
    passReqToCallback : true
  },
  function(req, email, password, done) { 
    // Löytyykö tietokannasta käyttäjä annetulla sähköpostiosoitteella
    User.findOne({ 'email' :  req.body.email }, 
      function(err, user) {
        // Hakiessa tapahtuu jokin virhe
        if (err)
          return done(err);
        // Sähköpostiosoitetta ei löydy tietokannasta
        if (!user){
          console.log('Kayttajaa ei loytynyt annetulla sahkopostiosoitteella '+ req.body.email);
          return done(null, false, { message : 'Kayttajaa ei loytynyt.' });                 
        }
        // Sähköpostiosoite on olemassa, mutta salasana on väärä 
        if (!isValidPassword(user, password)){
          console.log('Virheellinen salasana');
          return done(null, false, { message : 'Virheellinen salasana' });
        }
		if (user.admin === false){
			console.log("Kayttajalla ei ole yllapitajan oikeuksia");
			return done(null, false, { message : 'Kayttajalla ei ole yllapitajan oikeuksia' });
		}
        /*Sekä sähköpostiosoite, että salasana ovat oikein ja käyttäjällä on ylläpitäjän oikeudet. Done-metodi palauttaa käyttäjän tiedot sisältävän objektin*/
		console.log("Kayttaja loytyi tietokannasta, salasana oikein.");
        return done(null, user);
      }
    );
})
);
	//Metodi, joka tarkistaa annetun selkokielisen salasanan tietokannasta löytyvää kryptattua vastaan
	var isValidPassword = function(user, password){
		return bCrypt.compareSync(password, user.password);
	}
}