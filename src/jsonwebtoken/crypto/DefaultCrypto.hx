package jsonwebtoken.crypto;

typedef DefaultCrypto =
	#if cs CsCrypto
	#elseif java JavaCrypto
	#elseif nodejs NodeCrypto
	#elseif php PhpCrypto
	#elseif python PythonCrypto
	#else StdCrypto
	#end ;