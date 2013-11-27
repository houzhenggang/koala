package demo.hello;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Platform;

public class JNARun {
    public static final String LD_LIBRARY = "java.library.path";

    public interface CLibrary extends Library {
        CLibrary INSTANCE = (CLibrary) Native.loadLibrary((Platform.isWindows() ? "msvcrt" : "c"), CLibrary.class);

        void printf(String format, Object... args);
    }

    public static void main(String[] args) {
        System.out.println("##" + System.getProperty("java.library.path") + "##");
        CLibrary.INSTANCE.printf("Hello, World!\n");
        for (int i = 0; i < args.length; i++) {
            CLibrary.INSTANCE.printf("Argument %d: %s/n", i, args[i]);
        }
        System.out.println("result:" + TestLibrary.INSTANCE.j_add(111, 222));
        TestLibrary.INSTANCE.j_say("$%^$#@##&");
        System.out.println("#########C++ Library JNA##########");
        System.out.println("result:" + DemoLibrary.INSTANCE.d_add(0, 111));
        DemoLibrary.INSTANCE.d_say("~!@~!$@%##$^#$");
    }
}
