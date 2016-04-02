package;

import haxe.unit.TestRunner;

class RunTests
{
	static function main()
	{
		var t = new TestRunner();
		t.add(new GeneralTest());
		t.add(new VerifyTest());
		t.add(new SignTest());
		if(!t.run()) 
		{
			#if sys
			Sys.exit(500);
			#end
		}
	}
}