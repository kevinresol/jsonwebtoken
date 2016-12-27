package jsonwebtoken;

import jsonwebtoken.Algorithm;

using tink.CoreApi;

interface Crypto {
	function sign(input:String, algorithm:Algorithm):Promise<String>;
	function verify(input:String, algorithm:Algorithm, signature:String):Promise<Noise>;
}