//Tietokannan ajuri
var mongoose = require('mongoose');
//Otetaan käyttöön mongoosen vaatima Schema
var User = require('../models/User');
var express = require('express');
var router = express.Router();
var jwt = require('jwt-simple');
var config = require('../config/database');
require('../config/passport');

module.exports = function(passport) {
	router.post('/signup', function(req, res) {
		//Katsotaan puuttuuko jokin vaadituista rekisteröintitiedoista
		if(!req.body.username || !req.body.password || !req.body.email) {
			res.json({success: false, msg: 'Anna käyttäjänimi, salasana ja sähköpostiosoite.'});
		} else {
			var date = new Date()
			var dateMs = Date.parse(date);
			var createSteps = {
			stats: [
					{ 
						steps: 0,
						day: dateMs
					}
				]
			};
			//Luodaan uusi käyttäjäobjekti
			var newUser = new User({
				username: req.body.username,
				password: req.body.password,
				email: req.body.email,
				archive: createSteps
			});
			/*
			Tallennetaan uusi käyttäjä, salasana kryptataan ennen tämän funktion ajamista ks. ../models/User.js
			*/
			newUser.save(function(err) {
				if(err) {
					return res.json({success: false, msg: 'Nimi on jo käytössä.'});
				}
				res.json({success: true, msg: 'Uusi käyttäjä luotu onnistuneesti.'});
			});
		}
	});
	
	router.post('/authenticate', function(req, res) {
		User.findOne({
			'email': req.body.email
		}, function(err, user) {
			if(err) throw err;
			
			if(!user) {
				res.send({success: false, msg: "Annettua sähköpostiosoitetta ei löytynyt."});
			} else {
				user.comparePassword(req.body.password, function(err, isMatch) {
					if(isMatch && !err) {
						//Webtokeniin lisättävä tieto
						var payload = {
							_id: user._id
						}
						//Luodaan webtoken annetuilla tiedoilla
						var token = jwt.encode(payload, config.secret);
						//Lähetetään luotu webtoken pyynnön lähettäneelle käyttäjälle
						res.json({success: true, token: 'JWT ' + token});
					} else {
						res.send({success: false, msg: "Väärä salasana" + user});
					}
				});
			}
		});
	});
	router.get('/credcheck', passport.authenticate('jwt', { session: false } ), function(req, res) {
		//Etsitään webtokenia http-pyynnön headerista "Authorization: xxxxxxxx"
		var token = getToken(req.headers);
		if(token){
			//Purkaa tokenin sisältämän tiedon muuttujan sisään
			var decoded = jwt.decode(token, config.secret);
			User.findOne({
				_id: decoded._id
			}, function(err, user) {
				if(err) throw err;
				
				if(!user){
					return res.status(403).send({success: false, msg: 'Käyttäjätietojen tarkastus epäonnistui, annettua käyttäjää ei löytynyt.'});
				} else {
					res.json({success: true, msg: 'Käyttäjä ' + user.email + ' hyväksytty.'});
				}
			});
		} else {
			return res.status(403).send({success: false, msg: 'Webtokenia ei toimitettu'});
		}
	});
	
		router.get('/getsteps', passport.authenticate('jwt', { session: false } ), function(req, res) {
		//Etsitään webtokenia http-pyynnön headerista "Authorization: xxxxxxxx"
		var token = getToken(req.headers);
		if(token){
			//Purkaa tokenin sisältämän tiedon muuttujan sisään
			var decoded = jwt.decode(token, config.secret);
			User.findOne({
				_id: decoded._id
			}, function(err, user) {
				if(err) throw err;
				
				if(!user){
					return res.status(403).send({success: false, msg: 'Käyttäjätietojen tarkastus epäonnistui, annettua käyttäjää ei löytynyt.'});
				} else {
					res.json({success: true, msg: "käyttäjän askeleet haettu", archive:user.archive.stats });
				}
			});
		} else {
			return res.status(403).send({success: false, msg: 'Webtokenia ei toimitettu'});
		}
	});
	
	router.post('/sendsteps', passport.authenticate('jwt', { session: false } ), function(req, res) {
		//Etsitään webtokenia http-pyynnön headerista "Authorization: xxxxxxxx"
		var token = getToken(req.headers);
		if(token){
			//Purkaa tokenin sisältämän tiedon muuttujan sisään
			var decoded = jwt.decode(token, config.secret);
			
			console.log(decoded);	
			User.findOne({ _id: decoded._id}, function(err, user) {
				if(err) throw err;
				
				if(!user){
					res.send({success: false, msg: "id ei löytynyt."});
				} else {
					user.archive = req.body.stats;
					console.log(req.body);
					user.save();
					console.log('käyttäjän askeleet ' + console.debug(user.archive));	
					res.json({success: true, msg: 'tietoa voidaan lähettää'});	
				}
			});
		} 
	});
	
	
	//Funktio, joka etsii webtokenia http-pyynnön headerista, ja palauttaa sen
	getToken = function(headers){
		if(headers && headers.authorization) {
			var parted = headers.authorization.split(' ');
			if(parted.length === 2) {
				return parted[1];
			} else {
				return null;
			}
		} else {
			return null;
		}
	};
	return router;
};