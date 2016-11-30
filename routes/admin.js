//Tietokannan ajuri
var mongoose = require('mongoose');
//Otetaan käyttöön mongoosen vaatima Schema
var User = require('../models/User');
var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var bCrypt = require('bcrypt-nodejs');
var passport = require('passport');

router.use(bodyParser.urlencoded({ extended : true }));
router.use(methodOverride(function(req, res){
	if(req.body && typeof req.body === 'object' && '_method' in req.body){
		var method = req.body;
		delete req.body._method;
		return method;
	}
}));
module.exports = function(passport){
	var createHash = function(password){
        return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
    }
	function checkAdmin(status){
		var result;
		if(status === "on"){
			result = true;
		} else {
			result = false;
		}
		return result;
	};

	var isAuthenticated = function (req, res, next) {
	// if user is authenticated in the session, call the next() to call the next request handler 
	// Passport adds this method to request object. A middleware is allowed to add properties to
	// request and response objects
	if (req.isAuthenticated())
		return next();
	// if the user is not authenticated then redirect him to the login page
	console.log("Uudelleenohjataan kirjautumiseen");
	res.redirect('/admin');
	};
	
	router.get('/', function(req, res, next) {
		res.render('admin/admin', { title: 'Ylläpidon sisäänkirjautuminen' });
	});
	
	router.post('/', passport.authenticate('adminlogin', {
		successRedirect: '/admin/userlist',
		failureRedirect: '/admin'
	}));
	
	router.get('/logout', isAuthenticated, function(req, res){
		console.log("Istunto poistettu, ohjataan kirjautumiseen")
		req.logout();
		res.redirect('/admin/');
	});
	
	//Kaikkien käyttäjien hakeminen
	router.route('/userlist')
		.get(isAuthenticated, function(req, res, next) {
		//Metodi etsii mongo-kannan kaikki dokumentit
			User.find(function (err, users) {
				if (err) {
					return console.error(err);
				} else {
					//response-objekti lähetetään sekä html, että json muodossa
					res.format({
						//HTML responsen perusteella renderoidaan jade-templaatti, joka näyttää kaikki haetut käyttjät
						html: function(){
							res.render('admin/userlist', {
								title: 'Käyttäjät',
								"users" : users
							});
						},
						//Haetut käyttäjät JSON muodossa
						json: function(){
							res.json(infophotos);
						}
					});
				}     
			});
		})
	//Uuden käyttäjän luonti
		.post(function(req, res) {
			// Otetaan arvot req objektista
			var username = req.body.username;
			var email = req.body.email;
			var password = req.body.password;
			//Tarkistetaan onko luotavalle käyttäjälle annettu admin-status
			

			var newUser = new User({
				username: req.body.username,
				email: req.body.email,
				password: req.body.password,
				admin: checkAdmin(req.body.admin)
			});
			//Kutsutaan metodia, joka luo dokumentin mongo-kantaan annetuilla tiedoilla
			newUser.save(function (err, user) {
				if (err) {
					res.send("Tietojen lisaamisessa tietokantaan tapahtui virhe.");
				} else {
					//Ei virheitä, käyttäjä luodaan tietokantaan
					console.log('Luodaan uusi kayttaja: ' + user.email);
					//Paluutieto voidaan format funktiolla lähettää samaan aikaan eri muodoissa, tässä html ja json, olemassa myös text
					res.format({
						html: function(){
							res.location("/admin/userlist");
							res.redirect("/admin/userlist");
						},
						json: function(){
							res.json(user);
						}
					});
				  }
			})
		});

	router.get('/new', function(req, res){
		res.render('admin/new', { title : 'Lisää uusi käyttäjä'});
	});

	//Haetaan käyttäjä sähköpostiosoitteen perusteella
	router.get('/:email', isAuthenticated, function(req, res, next) {
		User.find({'email':req.params.email}, function (err, user) {
			if (err) {
				return next(err);
			} else {
				console.log('Haetaan sahkopostia: ' + user[0].email);
				res.format({
					html: function(){
						res.render('admin/show', {
							"user" : user[0]
							});
					},
					json: function(){
						res.json(user);
						}
				});
			}
		});
	});

	// Käyttäjän haku sähköpostilla, mahdollisuus muokata käyttäjän tietoja tai poistaa käyttäjä
		router.get('/:email/edit', isAuthenticated, function(req, res) {
			User.find({ 'email' : req.params.email }, function (err, user) {
				if (err) {
					console.log('GET Error: haussa tapahtui virhe: ' + err);
				} else {
					//Palautetaan käyttäjän tiedot
					console.log('Haetaan sahkopostiosoitetta: ' + user[0].email);
					res.format({
						//HTML response renderöi edit jade-templaatin
						html: function(){
							   res.render('admin/edit', {
								  title: 'User' + user[0].email,
								  "user" : user[0]
							  });
						 },
						 //JSON response
						json: function(){
							   res.json(user);
						 }
					});
				};
			});
		})
		//Käyttäjän tietojen muokkaus annettujen tietojen perusteella
		router.post('/:email/edit', isAuthenticated, function(req, res) {
			//Lomakkeelta saadut tiedot req-objektista
			var username = req.body.username;
			var email = req.body.email;
			var password = req.body.password;
			var admin = checkAdmin(req.body.admin);
			console.log(req.body.username + " " + req.body.email + " " + req.body.password);

			//Käyttäjän haku sähköpostiosoitteella
			User.findOneAndRemove({ 'email' : req.params.email }, function (err, user) {
				if(err){
					console.log(err);
				}
			});
			var newUser = new User({
				username: username,
				email: email,
				password: password,
				admin: admin
			});
				//Muokataan tiedot
			newUser.save(function (err, user) {
				if (err) {
					res.send("Tietojen paivittamisessa tietokantaan tapahtui virhe: " + err);
				} else {
					//Ohjataan käyttäjä takaisin kaikki käyttäjät listaavalle sivulle
					res.format({
						html: function(){
							res.redirect("/admin/userlist");
						},
						//JSON response, muokatut arvot
						json: function(){
							res.json(user);
						}
					});
				}
			});
		})
		//Käyttäjän poisto
		router.post('/:email/delete', isAuthenticated, function (req, res){
			//Käyttäjän haku sähköpostin perusteella
			User.findOneAndRemove({ 'email' : req.params.email }, req.body, function (err, user) {
				if (err) {
					return console.error(err);
				} else {
					//Poiston jälkeen palataan käyttäjälistaukseen
					res.format({
						html: function(){
							res.redirect('/admin/userlist');
						},
						json: function(){
							res.json({
								message:'deleted',
								item: user
								});
						}
					});
				}
			});
		});
	return router;
};
//module.exports = router;