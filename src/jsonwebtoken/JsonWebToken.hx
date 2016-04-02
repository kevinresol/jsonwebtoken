package jsonwebtoken;

import haxe.crypto.Hmac;
import jsonwebtoken.Algorithm;
import jsonwebtoken.JsonWebTokenError;

using haxe.io.Bytes;
using haxe.Json;
using haxe.crypto.Base64;
using StringTools;

class JsonWebToken
{
	static var DEFAULT_ALGORITHM:Algorithm = HS256;
	var secret:Secret;
	
	public function new(secret:Secret)
	{
		if(secret == null || secret.length == 0) throw ESecretNotSet;
		this.secret = secret;
	}
	
	public function sign(claims:Dynamic, ?options:SignOptions):String
	{
		if(options == null) options = {};
		var algorithm = options.algorithm != null ? options.algorithm : DEFAULT_ALGORITHM;
		
		var segments = [];
		
		try 
		{
			segments.push(encodeHeader(algorithm));
			segments.push(encodePayload(claims, options));
			segments.push(encodeSignature(segments.join("."), algorithm));
		}
		catch(e:Dynamic) {trace(e); trace(haxe.CallStack.toString(haxe.CallStack.exceptionStack()));}
		
		return segments.join(".").replace('+','-').replace('/','_');
	}
	
	public function verify<T>(token:String, ?options:VerifyOptions):T
	{
		if(token == null || token == "") throw ETokenNotSet;
		if(options == null) options = {};
		
		token = token.replace('-','+').replace('_','/');
		var pieces = token.split('.');
		if(pieces.length != 3) throw EInvalidNumberOfSegments;
		
		var header = pieces[0].decode().toString().parse();
		
		// verify algorithm
		var algorithm:Algorithm = header.alg;
		if(options.algorithm != null && options.algorithm != algorithm) throw EUnmatchedAlgorithm;
		var payload:Dynamic = pieces[1].decode().toString().parse();
		
		verifySignature(pieces, algorithm);
		verifyExpiration(payload.exp);
		verifyIssuer(options.issuers, payload.iss);
		verifyAudience(options.audience, payload.aud);
		
		return cast payload;
	}
	
	function encodeHeader(algorithm:Algorithm)
	{
		if(algorithm == null) algorithm = DEFAULT_ALGORITHM;
		
		var header = {
			alg: algorithm,
			typ: "JWT",
		}
		
		return header.stringify().ofString().encode(false).toString();
	}
	
	function encodePayload(claims:Dynamic, ?options:SignOptions)
	{
		var now = Std.int(Date.now().getTime() / 1000);
		
		if(options.expirySeconds != null)
			claims.exp = now + options.expirySeconds;
		if(options.notValidBeforeLeeway != null)
			claims.nbf = now - options.notValidBeforeLeeway;
		if(options.issuer != null)
			claims.iss = options.issuer;
		if(options.audience != null)
			claims.aud = options.audience;
		if(options.subject != null)
			claims.sub = options.subject;
		if(options.issuedAt)
			claims.iat = now;
		if(options.jwtId)
			claims.jti = Uuid.create();
			
		for(field in Reflect.fields(claims))
			if(Reflect.field(claims, field) == null) Reflect.deleteField(claims, field);
		
		return claims.stringify().ofString().encode(false).toString();
	}
	
	function encodeSignature(input:String, ?algorithm:Algorithm)
	{
		var bytes = input.ofString();
		
		if(algorithm == null) algorithm = DEFAULT_ALGORITHM;
		return switch algorithm 
		{
			case HS256: 
				var hmac = new Hmac(SHA256);
				hmac.make(secret, bytes).encode(false).toString();
				
			case HS384
			| HS512
			| RS256
			| RS384
			| RS512: throw EUnsupportedAlgorithm;
		}
	}
	
	function verifySignature(segments:Array<String>, ?algorithm:Algorithm)
	{
		if(algorithm == null) algorithm = DEFAULT_ALGORITHM;
		if(segments[2] != encodeSignature(segments[0] + '.' + segments[1], algorithm)) throw EInvalidSignature;
	}
	
	function verifyExpiration(expiry:Dynamic)
	{
		if(expiry == null) return;
		
		var exp = 
			if(Std.is(expiry, String))
				Std.parseInt(expiry);
			else if(Std.is(expiry, Int))
				expiry;
			else 
				null;
			
		if(exp != null && Date.now().getTime() / 1000 > exp) throw EExpired;
	}
	
	function verifyIssuer(expected:Array<String>, provided:Dynamic)
	{
		if(expected == null || expected.length == 0 || provided == null || !Std.is(provided, String)) return;
		if(expected.indexOf(provided) == -1) throw EInvalidIssuer;
	}
	
	function verifyAudience(expected:String, provided:Dynamic)
	{
		if(provided == null || expected == null) return;
		if(Std.is(provided, Array) && (provided:Array<String>).indexOf(expected) == -1) throw EInvalidAudience;
		if(Std.is(provided, String) && provided != expected) throw EInvalidAudience;
	}
}

typedef Claims = 
{
	?iss:String,
	?aud:Either<String, Array<String>>,
	?sub:String,
	?jti:String,
	?exp:Int,
	?nbf:Int,
	?iat:Int,
}

typedef SignOptions = 
{
	?algorithm:Algorithm,
	?expirySeconds:Int,
	?notValidBeforeLeeway:Int,
	
	?issuer:String,
	?audience:Either<String, Array<String>>,
	?subject:String,
	
	?issuedAt:Bool,
	?jwtId:Bool,
}

typedef VerifyOptions = 
{
	?audience:String,
	?issuers:Array<String>,
	?algorithm:Algorithm,
}

abstract Either<T1, T2>(Dynamic) from T1 from T2 {}