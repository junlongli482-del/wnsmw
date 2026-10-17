package org.localresearch.stackprobe;
public class MainActivity extends android.app.Activity {
    @Override public void onCreate(android.os.Bundle state) {
        super.onCreate(state);android.widget.TextView text=new android.widget.TextView(this);
        text.setText("Framework factory native stack captured. Separate research package.");setContentView(text);
    }
}
