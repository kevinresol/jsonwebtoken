package jsonwebtoken;

import jsonwebtoken.JsonWebTokenError;

@:enum
abstract Algorithm(String) to String
{
	var HS256 = "HS256";
	var HS384 = "HS384";
	var HS512 = "HS512";
	var RS256 = "RS256";
	var RS384 = "RS384";
	var RS512 = "RS512";
	
	@:from
	public static function fromString(v:String):Algorithm
	{
		return switch v
		{
			case HS256: HS256;
			case HS384
			| HS512
			| RS256
			| RS384
			| RS512: throw EUnsupportedAlgorithm;
			default: throw EInvalidAlgorithm;
		}
	}
}