package;

import jsonwebtoken.JsonWebToken;
import jsonwebtoken.JsonWebTokenError;
import haxe.unit.TestCase;
import haxe.crypto.Base64;

@:access(jsonwebtoken.JsonWebToken)
class VerifyTest extends TestCase
{
	var jwt:JsonWebToken;
	
	override function setup()
	{
		jwt = new JsonWebToken('such secret');
	}
	
	function testFailOnInvalidNumberOfSegments()
	{
		try jwt.verify('abc') catch(e:JsonWebTokenError) assertEquals(EInvalidNumberOfSegments, e);
		try jwt.verify('abc.abc') catch(e:JsonWebTokenError) assertEquals(EInvalidNumberOfSegments, e);
		try jwt.verify('abc.abc.abc.abc') catch(e:JsonWebTokenError) assertEquals(EInvalidNumberOfSegments, e);
		try jwt.verify('abc.abc.abc.abc.abc') catch(e:JsonWebTokenError) assertEquals(EInvalidNumberOfSegments, e);
	}

	function testFailOnEmptyStringToken()
	{
		try jwt.verify('') catch(e:JsonWebTokenError) assertEquals(ETokenNotSet, e);
	}
	
	function testFailOnNullToken()
	{
		try jwt.verify(null) catch(e:JsonWebTokenError) assertEquals(ETokenNotSet, e);
	}
	// 
	// @Test(expected = IllegalStateException.class)
	// function testFailIfAlgorithmIsNotSetOnToken() throws Exception {
	// 	new JWTVerifier("such secret").getAlgorithm(JsonNodeFactory.instance.objectNode());
	// }
	// 
	// @Test(expected = IllegalStateException.class)
	// function testFailIfAlgorithmIsNotSupported() throws Exception {
	// 	new JWTVerifier("such secret").getAlgorithm(createSingletonJSONNode("alg", "doge-crypt"));
	// }
	// 
	// @Test
	// function testWorkIfAlgorithmIsSupported() throws Exception {
	//    new JWTVerifier("such secret").getAlgorithm(createSingletonJSONNode("alg", "HS256"));
	// }

	function testFailOnInvalidSignature()
	{
		var token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.suchsignature_plzvalidate_zomgtoken";
		var secret = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
		try new JsonWebToken(secret).verifySignature(token.split('.')) catch(e:JsonWebTokenError) assertEquals(EInvalidSignature, e);
	}
	
	function testVerifySignature()
	{
		var token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP+mB92K27uhbUJU1p1r/wW1gFWFOEjXk";
		var secret = Base64.decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ+EstJQLr/T+1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
		new JsonWebToken(secret).verifySignature(token.split('.'));
		assertTrue(true);
	}
	
	function testMatchedAlgorithm()
	{
		var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.4BjJWnO3nkNiYiR1ECGmMnsrLzpTm4l0zvYWpiPAtKw";
		jwt.verify(token, {algorithm: HS256});
		assertTrue(true);
	}
	
	function testFailOnUnmatchedAlgorithm()
	{
		var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.4BjJWnO3nkNiYiR1ECGmMnsrLzpTm4l0zvYWpiPAtKw";
		try jwt.verify(token, {algorithm: HS384}) catch(e:JsonWebTokenError) assertEquals(EUnmatchedAlgorithm, e);
	}
	
	function testFailWhenExpired()
	{
		var time = Std.int(Date.now().getTime() / 1000 - 5000);
		try jwt.verifyExpiration('$time') catch(e:JsonWebTokenError) assertEquals(EExpired, e);
		try jwt.verifyExpiration(time) catch(e:JsonWebTokenError) assertEquals(EExpired, e);
	}
	
	function testVerifyExpiration()
	{
		var time = Std.int(Date.now().getTime() / 1000 + 5000);
		jwt.verifyExpiration('$time');
		jwt.verifyExpiration(time);
		assertTrue(true);
	}
	
	function testVerifyIssuer()
	{
		jwt.verifyIssuer(['very issuer'], 'very issuer');
		jwt.verifyIssuer(['a', 'very issuer'], 'very issuer');
		assertTrue(true);
	}
	
	function testFailIssuer()
	{
		try jwt.verifyIssuer(['very issue'], 'very issuer') catch(e:JsonWebTokenError) assertEquals(EInvalidIssuer, e);
		try jwt.verifyIssuer(['very issue', 'abc'], 'very issuer') catch(e:JsonWebTokenError) assertEquals(EInvalidIssuer, e);
	}
	
	function testVerifyIssuerWhenNotFoundInClaimsSet()
	{
		jwt.verifyIssuer(['a', 'very issuer'], null);
		assertTrue(true);
	}
	
	function testVerifyAudience()
	{
		jwt.verifyAudience('amazing audience', 'amazing audience');
		assertTrue(true);
	}
	
	function testFailAudience()
	{
		try jwt.verifyAudience('amazing audienc', 'amazing audience') catch(e:JsonWebTokenError) assertEquals(EInvalidAudience, e);
	}
	
	function testVerifyAudienceWhenNotFoundInClaimsSet()
	{
		jwt.verifyAudience('amazing audience', null);
		assertTrue(true);
	}
	
	function testVerifyArrayAudience()
	{
		jwt.verifyAudience('amazing audience', ['amazing audience', 'another']);
		assertTrue(true);
	}
	
	function testFailArrayAudience()
	{
		try jwt.verifyAudience('amazing audience', ['foo']) catch(e:JsonWebTokenError) assertEquals(EInvalidAudience, e);
		try jwt.verifyAudience('amazing audience', ['foo', 'bar']) catch(e:JsonWebTokenError) assertEquals(EInvalidAudience, e);
	}
}