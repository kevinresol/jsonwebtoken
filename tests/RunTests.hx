package;

import haxe.unit.TestRunner;

#if flash
import flash.system.System.exit;
#else
import Sys.exit;
#end

class RunTests
{
	static function main()
	{
		var t = new TestRunner();
		t.add(new GeneralTest());
		t.add(new VerifyTest());
		t.add(new SignTest());
		exit(t.run() ? 0 : 500);
	}
}