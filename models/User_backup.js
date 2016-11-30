var mongoose = require('mongoose');
var passportLocalMongoose = require('passport-local-mongoose');
var bcrypt = require('bcrypt-nodejs');

var UserSchema = new mongoose.Schema({
	username: {
		type: String,
		unique: false,
		required: true
	},
	password: {
		type: String,
		unique: true,
		required: true
	},
	email: {
		type: String,
		unique: true,
		required: true
	},
	admin: {
		type: Boolean,
		default: false,
		required: false
	},
	archive: {
		stats: {
			type: [Number],
			default: [0]
		}
	}
});

/*Funktio ajetaan ennen "save"-funktion ajamista. Rekisteröityneen käyttäjän antama salasana kryptataan ennen tallennusta tietokantaan.*/
UserSchema.pre('save', function(next) {
	var user = this;
	if(this.isModified('password') || this.isNew) {
		/*Luodaan "suola", jota käyttäen salasana kryptataan ennen tietokantaan lisäämistä, bcrypt osaa erottaa suolan tarkisteesta ja tällä perusteella verrata "omia tekeleitään" toisiinsa.*/
		bcrypt.genSalt(10, function(err, salt) {
			if (err) {
				return next(err);
			}
			//Kryptataan salasana luodulla suolalla ja palautetaan se save-funktiolle
			bcrypt.hash(user.password, salt, function(err, hash) {
				if (err) {
					return next(err);
				}
				user.password = hash;
				next();
			});
		});
	} else {
		return next();
	}
});
/*Verrataan annettua salasanaa tietokannasta löytyvään hashiin*/
UserSchema.methods.comparePassword = function(passw, cb) {
	var self = this;
	bcrypt.compare(passw, self.password, function(err, isMatch) {
		console.log(passw + " " + self.password);
		if(err) {
			return cb(err);
		}
		cb(null, isMatch);
	});
};

UserSchema.plugin(passportLocalMongoose);
module.exports = mongoose.model('User', UserSchema);