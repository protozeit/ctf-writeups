package p000io.cordova.hellocordova;

import android.os.Bundle;
import org.apache.cordova.CordovaActivity;

/* renamed from: io.cordova.hellocordova.MainActivity */
public class MainActivity extends CordovaActivity {
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Bundle extras = getIntent().getExtras();
        if (extras != null && extras.getBoolean("cdvStartInBackground", false)) {
            moveTaskToBack(true);
        }
        loadUrl(this.launchUrl);
    }
}
