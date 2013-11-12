package demo.hello;

import com.sun.jna.Library;
import com.sun.jna.Native;

public interface TestLibrary extends Library {
	TestLibrary INSTANCE = (TestLibrary) Native.loadLibrary("test", TestLibrary.class);

	public int j_add(int a, int b);

	public void j_say(String str);
}
