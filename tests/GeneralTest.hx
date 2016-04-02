package;

import jsonwebtoken.JsonWebToken;
import jsonwebtoken.JsonWebTokenError;
import haxe.unit.TestCase;
import haxe.io.Bytes;

class GeneralTest extends TestCase
{
	
	function testNullSecret()
	{
		try new JsonWebToken(null) catch(e:JsonWebTokenError) assertEquals(ESecretNotSet, e);
	}
	
	function testEmptyStringSecret()
	{
		try new JsonWebToken("") catch(e:JsonWebTokenError) assertEquals(ESecretNotSet, e);
	}
	
	function testEmptyBytesSecret()
	{
		try new JsonWebToken(Bytes.alloc(0)) catch(e:JsonWebTokenError) assertEquals(ESecretNotSet, e);
	}
	
}