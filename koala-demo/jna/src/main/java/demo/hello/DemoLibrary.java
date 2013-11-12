package demo.hello;

import com.sun.jna.Library;
import com.sun.jna.Native;

public interface DemoLibrary extends Library {
	DemoLibrary INSTANCE = (DemoLibrary) Native.loadLibrary("demo", DemoLibrary.class);

	public void d_say(String str);

	public int d_add(int a, int b);
}
