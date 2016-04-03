package;

import haxe.unit.TestCase;
import jsonwebtoken.JsonWebTokenError;

using haxe.crypto.Base64;
using haxe.Json;

class TestCaseBase extends TestCase
{
	function assertException(expected:JsonWebTokenError, fn:Void->Void, ?pos:haxe.PosInfos)
	{
		try {
			fn();
			assertTrue(false, pos);
		} catch(e:JsonWebTokenError)
			assertEquals(expected, e, pos);
	}
	
	function assertEncoded(expected:{}, encoded:String, ?pos:haxe.PosInfos)
	{
		compare(expected, encoded.decode().toString().parse(), pos);
	}
	
	function compare(expected:Dynamic, actual:Dynamic, ?pos:haxe.PosInfos)
	{
		if(Std.is(expected, Array))
		{
			assertTrue(Std.is(actual, Array), pos);
			assertEquals(expected.length, actual.length, pos);
			for(e in (expected:Array<Dynamic>)) assertTrue((actual:Array<Dynamic>).indexOf(e) != -1, pos);
		}
		else if(Reflect.isObject(expected) && Type.typeof(expected) == TObject)
		{
			assertTrue(Reflect.isObject(actual) && Type.typeof(actual) == TObject, pos);
			assertEquals(Reflect.fields(expected).length, Reflect.fields(actual).length, pos);
			for(field in Reflect.fields(expected)) compare(Reflect.field(expected, field), Reflect.field(actual, field), pos);
		}
		else
		{
			assertEquals(expected, actual, pos);
		}
	}
}