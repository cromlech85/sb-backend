var JwtStrategy = require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;
var jwt = require('jwt-simple');
var User = require('../models/User');
var config = require('../config/database');

/*Funktio ajetaan käyttäjän navigoidessa suojattuun api-pisteeseen. Tarkistetaan lähettääkö käyttäjä pyyntönsä headerissa tunnistautunutta käyttäjää vastaavan id:n. Tieto on varastoituna salattuun webtokeniin, jonka kirjautunut käyttäjä on saanut onnistuneen kirjautumisen yhteydessä. "jwt_payload"-muuttuja sisältää webtokenin tiedot, joista salaus on purettu.*/
module.exports = function(passport) {
	var opts = {};
	opts.secretOrKey = config.secret;
	opts.jwtFromRequest = ExtractJwt.fromAuthHeader();
	opts.passReqToCallback = true;
	passport.use(new JwtStrategy(opts, function(req, jwt_payload, done) {
		User.findOne({_id: jwt_payload._id}, function(err, user) {
			if(err){
				return done(err, false);
			}
			if(user){
				console.log(user);
				done(null, user);
			} else {
				done(null, false);
			}
		});
	}));
};