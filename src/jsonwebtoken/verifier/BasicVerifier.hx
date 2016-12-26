package jsonwebtoken.verifier;

import jsonwebtoken.Verifier;
import jsonwebtoken.Sequence;

using jsonwebtoken.Algorithm;
using jsonwebtoken.Codec;
using tink.CoreApi;

class BasicVerifier implements Verifier {
	
	var algorithm:Algorithm;
	var crypto:Crypto;
	var options:VerifyOptions;
	
	public function new(algorithm, crypto, ?options) {
		this.algorithm = algorithm;
		this.crypto = crypto;
		this.options = options;
	}
	
	public function verify<T:Claims>(token:String):Promise<T> {
		if(token == null || token == '') return new Error('Token missing');
		
		switch token.sanitize().split('.') {
			case [h, p, s]:
				var header:Header = Codec.decodeSegment(h);
				if(header.typ != 'JWT') return new Error('Invalid typ header');
				if(header.alg != algorithm.toString()) return new Error('Invalid algorithm');
				
				return crypto.encode('$h.$p', algorithm).next(function(sig):Outcome<T, Error> {
					if(sig != s) return Failure(new Error('Invalid signature'));
					
					var payload:Claims = Codec.decodeSegment(p);
					
					if(payload.nbf != null && Std.is(payload.nbf, Float) && Date.now().getTime() / 1000 < payload.nbf.toInt())
						return Failure(new Error('Not available yet (nbf)'));
					
					if(payload.exp != null && Std.is(payload.exp, Float) && Date.now().getTime() / 1000 > payload.exp.toInt())
						return Failure(new Error('Expired (exp)'));
					
					if(options != null) {
						if(options.iss != null) {
							if(options.iss.indexOf(payload.iss) == -1)
								return Failure(new Error('Invalid issuer (iss)'));
						}
						if(options.aud != null) {
							var aud:Dynamic = payload.aud;
							if(Std.is(aud, String)) {
								if(options.aud != aud) 
									return Failure(new Error('Invalid audience (aud)'));
							} else {
								if(payload.aud.indexOf(aud) == -1)
									return Failure(new Error('Invalid audience (aud)'));
							} 
						}
					}
					return Success(cast payload);
				});
				
			default:
				return new Error('Invalid token');
		}
	}
}

typedef VerifyOptions = {
	?aud:String,
	?iss:Sequence<String>,
}