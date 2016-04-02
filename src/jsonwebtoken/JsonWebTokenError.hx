package jsonwebtoken;

enum JsonWebTokenError
{
	ESecretNotSet;
	ETokenNotSet;
	EExpired;
	EInvalidSignature;
	EInvalidAlgorithm;
	EInvalidAudience;
	EInvalidIssuer;
	EInvalidNumberOfSegments;
	EUnsupportedAlgorithm;
	EUnmatchedAlgorithm;
}
