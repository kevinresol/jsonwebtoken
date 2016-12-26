package jsonwebtoken;

using StringTools;
using haxe.Json;
using haxe.crypto.Base64;
using haxe.io.Bytes;
using tink.CoreApi;
using jsonwebtoken.Codec;

class Codec {
	
	@:noUsing public static function encodeSegment(segment:{}) {
		return segment.stringify().ofString().encode().sanitize();
	}
	
	@:noUsing public static function decode(token:String) {
		return switch token.split('.') {
			case [h, p, _]:
				return Error.catchExceptions(function() return new Pair(decodeSegment(h), decodeSegment(p)));
			default:
				Failure(new Error('Invalid token'));
		}
	}
	
	@:noUsing public static function decodeSegment<T>(segment:String):T {
		return segment.unsanitize().decode().toString().parse();
	}
	
	public static function sanitize(s:String):String
		return s.replace('+', '-').replace('/', '_').replace('=', '');
	
	public static function unsanitize(s:String):String
		return s.replace('-', '+').replace('_', '/'); // TODO: add complements?
}