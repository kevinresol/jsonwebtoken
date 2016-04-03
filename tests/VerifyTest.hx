package;

import jsonwebtoken.JsonWebToken;
import jsonwebtoken.JsonWebTokenError;
import haxe.crypto.Base64;

@:access(jsonwebtoken.JsonWebToken)
class VerifyTest extends TestCaseBase
{
	var jwt:JsonWebToken;
	
	override function setup()
	{
		jwt = new JsonWebToken('such secret');
	}
	
	function testFailOnInvalidNumberOfSegments()
	{
		assertException(EInvalidNumberOfSegments, jwt.verify.bind('abc'));
		assertException(EInvalidNumberOfSegments, jwt.verify.bind('abc.abc'));
		assertException(EInvalidNumberOfSegments, jwt.verify.bind('abc.abc.abc.abc'));
		assertException(EInvalidNumberOfSegments, jwt.verify.bind('abc.abc.abc.abc.abc'));
	}

	function testFailOnEmptyStringToken()
	{
		assertException(ETokenNotSet, jwt.verify.bind(''));
	}
	
	function testFailOnNullToken()
	{
		assertException(ETokenNotSet, jwt.verify.bind(null));
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
		assertException(EInvalidSignature, new JsonWebToken(secret).verifySignature.bind(token.split('.')));
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
		assertException(EUnmatchedAlgorithm, jwt.verify.bind(token, {algorithm: HS384}));
	}
	
	function testFailWhenExpired()
	{
		var time = Std.int(Date.now().getTime() / 1000 - 5000);
		assertException(EExpired, jwt.verifyExpiration.bind('$time'));
		assertException(EExpired, jwt.verifyExpiration.bind(time));
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
		assertException(EInvalidIssuer, jwt.verifyIssuer.bind(['very issue'], 'very issuer'));
		assertException(EInvalidIssuer, jwt.verifyIssuer.bind(['very issue', 'abc'], 'very issuer'));
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
		assertException(EInvalidAudience, jwt.verifyAudience.bind('amazing audienc', 'amazing audience'));
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
		assertException(EInvalidAudience, jwt.verifyAudience.bind('amazing audience', ['foo']));
		assertException(EInvalidAudience, jwt.verifyAudience.bind('amazing audience', ['foo', 'bar']));
	}
}