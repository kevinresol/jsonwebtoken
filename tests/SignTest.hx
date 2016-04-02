package;

import jsonwebtoken.JsonWebToken;
import haxe.unit.TestCase;

using haxe.crypto.Base64;
using haxe.Json;

@:access(jsonwebtoken.JsonWebToken)
class SignTest extends TestCase
{
	var signer:JsonWebToken;
	
	override function setup()
	{
		signer = new JsonWebToken('my secret');
	}
	
	function testEncodeSignature()
	{
		var signature = signer.encodeSignature('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30');
		assertEquals('bYbzTu1BlXUhf+V8G0JCR2yarRl9J7fzZvssGRentYY', signature);
	}
	
	function testSignEmpty()
	{
		var payload = {};
		var token = signer.sign(payload);
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded(payload, segments[1]);
	}
	
	function testSignStringOrURI1()
	{
		var payload = {};
		var token = signer.sign(payload);
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded(payload, segments[1]);
		
		var token = signer.sign({iss: 'foo'});
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded({iss: 'foo'}, segments[1]);
	}
	
	function testSignStringOrURI2()
	{
		var payload = {sub: 'http://foo'};
		var token = signer.sign(payload);
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded(payload, segments[1]);
	}
	
	function testSignStringOrURI3()
	{
		var payload = {aud: ''};
		var token = signer.sign(payload);
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded(payload, segments[1]);
	}
	
	function testSignStringOrURICollection()
	{
		var payload = {aud: ['xyz', 'ftp://foo']};
		var token = signer.sign(payload);
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded(payload, segments[1]);
	}
	
	function testSignIntDate1()
	{
		var payload = {exp: 123};
		var token = signer.sign(payload);
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded(payload, segments[1]);
	}
	
	function testSignIntDate2()
	{
		var payload = {nbf: 0};
		var token = signer.sign(payload);
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded(payload, segments[1]);
	}
	
	function testSignIntDate3()
	{
		var payload = {iat: 9999999};
		var token = signer.sign(payload);
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded(payload, segments[1]);
	}
	
	function testSignString()
	{
		var payload = {jti: 'foo'};
		var token = signer.sign(payload);
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded(payload, segments[1]);
	}
	
	function testSignNullEqualsMissing()
	{
		var token = signer.sign({abc: null, bcd: null});
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded({}, segments[1]);
	}
	
	function testSignCustom()
	{
		var payload = {myInt:123};
		var token = signer.sign(payload);
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded(payload, segments[1]);
	}
	
	function testOptionsNone()
	{
		var payload = {};
		var token = signer.sign(payload, {});
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded({}, segments[1]);
	}
	
	function testOptionsissuer()
	{
		var token = signer.sign({}, {issuer: 'my issuer'});
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded({iss: 'my issuer'}, segments[1]);
	}
	
	function testOptionsAudience()
	{
		var token = signer.sign({}, {audience: 'my audience'});
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded({aud: 'my audience'}, segments[1]);
	}
	
	function testOptionsSubject()
	{
		var token = signer.sign({}, {subject: 'my subject'});
		var segments = token.split('.');
		assertEncoded({alg: "HS256", typ: "JWT"}, segments[0]);
		assertEncoded({sub: 'my subject'}, segments[1]);
	}
	
	function testOptionsAll()
	{
		var token = signer.sign({}, {
			expirySeconds: 1000,
			notValidBeforeLeeway: 5,
			issuer: 'my issuer',
			audience: 'my audience',
			subject: 'my subject',
			issuedAt: true,
			jwtId: true,
		});
		
		// cannot assert, because the time values vary
		assertTrue(true);
	}
	
	// function testOptionsAlgorithm()
	// {
	// 	var token = signer.sign({}, {
	// 		algorithm: HS512
	// 	});
	// 	assertEquals("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.e30.11MgCe-_uiheyy_kARCwhSZbeq3IkMn40GLQkczQ4Bjn_lkCYfSeqz0HeeYpitksiQ2bW47N0oGKCOYOlmQPyg", token);
	// }
	
	function assertEncoded(expected:{}, encoded:String, ?pos:haxe.PosInfos)
	{
		compare(expected, encoded.decode().toString().parse(), pos);
	}
	
	function compare(expected:Dynamic, actual:Dynamic, ?pos:haxe.PosInfos)
	{
		if(Std.is(expected, Array))
		{
			assertTrue(Std.is(actual, Array));
			assertEquals(expected.length, actual.length);
			for(e in (expected:Array<Dynamic>)) assertTrue((actual:Array<Dynamic>).indexOf(e) != -1);
		}
		else if(Reflect.isObject(expected) && Type.typeof(expected) == TObject)
		{
			assertTrue(Reflect.isObject(actual) && Type.typeof(actual) == TObject);
			assertEquals(Reflect.fields(expected).length, Reflect.fields(actual).length);
			for(field in Reflect.fields(expected)) compare(Reflect.field(expected, field), Reflect.field(actual, field));
		}
		else
		{
			assertEquals(expected, actual);
		}
	}
}