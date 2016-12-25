package jsonwebtoken;

using StringTools;
using haxe.Json;
using haxe.crypto.Base64;
using haxe.io.Bytes;
using tink.CoreApi;

class Codec {
	
	public static function encodeSegment(segment:{}) {
		return segment.stringify().ofString().encode(false).replace('+', '-').replace('-', '_');
	}
	
	public static function decode(token:String) {
		return switch token.split('.') {
			case [h, p, _]:
				return Error.catchExceptions(function() return new Pair(decodeSegment(h), decodeSegment(p)));
			default:
				Failure(new Error('Invalid token'));
		}
	}
	
	public static function decodeSegment(segment:String) {
		return segment.replace('-', '+').replace('_', '-').decode().toString().parse();
	}
}