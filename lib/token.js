
'use strict';

var jwt = require('jwt-simple'),
	crypto = require('crypto');

var Class = function() {
	
	this.generateObjectToken = (obj, secret, cb) => {
		var token = null,
			tokenBody = JSON.stringify(obj) + '|' + Date.now();
		try {
			token = jwt.encode(tokenBody, secret);
		}
		catch (e) {
			return cb(e);
		}
		
		cb(null, token);
	};
	
	
	this.generateRandomToken = (secret, cb) => {
		crypto.randomBytes(256, (err, buffer) => {
			var rnd = null,
				token = null,
				tokenBody = null;
			
		    if (err)  {
		    	return cb(err);
		    }

		    try {
		    	rnd = crypto.createHmac('sha1', secret).update(buffer).digest('hex');
		    	tokenBody = rnd + '|' + Date.now();
		    	token = jwt.encode(tokenBody, secret);
		    }
		    catch (e) {
		    	return cb(e);
		    }
		    
		    cb(null, token);
		  });
	};
	
	this.analyzeAccessToken = (token, secret, cb) => {
		var decoded = null;
		
		try {
			decoded = jwt.decode(token, secret); 
		}
		catch (e) {
			return cb (e);
		}

		cb(null, decoded);
	}
};

Class.prototype.jwt = jwt;

var instance = new Class();

module.exports = instance;