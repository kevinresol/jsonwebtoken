package jsonwebtoken;

import jsonwebtoken.Algorithm;

using tink.CoreApi;

interface Crypto {
	function encode(input:String, algorithm:Algorithm):Promise<String>;
}