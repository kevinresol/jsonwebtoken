package jsonwebtoken;

import jsonwebtoken.Algorithm;

using tink.CoreApi;

interface Crypto {
	function sign(input:String, algorithm:Algorithm):Promise<String>;
}