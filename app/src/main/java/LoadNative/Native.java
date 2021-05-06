package LoadNative;

public class Native {
    static {
        System.loadLibrary("share");
    }

    public static native void init(int pid);

}
