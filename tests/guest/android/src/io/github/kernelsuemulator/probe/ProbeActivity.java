package io.github.kernelsuemulator.probe;
import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.SystemClock;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.widget.TextView;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.view.View;
import android.view.MotionEvent;
import android.media.AudioTrack;
import android.media.AudioFormat;
import android.media.AudioManager;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import org.json.JSONObject;
public class ProbeActivity extends Activity implements SensorEventListener {
 private String protectedRead=null, selinuxError=null; private JSONObject selinuxObserved=null;
 private volatile String rootResult="not requested"; private TextView text; private EditText keyboard; private Handler handler=new Handler(); private SensorManager sensors;
 private long frames=0, events=0, sensorTime=0, touches=0; private AudioTrack audio; private volatile boolean running=true; private volatile String http="pending", audioState="pending"; private boolean registered=false; private volatile String dns="pending";
 public void onCreate(Bundle b){super.onCreate(b);text=new TextView(this);text.setTextSize(20);text.setPadding(40,30,40,20);keyboard=new EditText(this);keyboard.setSingleLine(true);keyboard.setHint("Type through the MuMu window to test native keyboard input");LinearLayout layout=new LinearLayout(this);layout.setOrientation(LinearLayout.VERTICAL);layout.addView(keyboard);layout.addView(text);setContentView(layout);keyboard.requestFocus();text.setOnTouchListener(new View.OnTouchListener(){public boolean onTouch(View v,MotionEvent e){if(e.getAction()==MotionEvent.ACTION_DOWN)touches++;return true;}});
 if(getIntent().getBooleanExtra("request_root",false))new Thread(new Runnable(){public void run(){try{Process p=new ProcessBuilder("su","-c","id; /data/adb/ksud debug version").redirectErrorStream(true).start();ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buf=new byte[1024];int n;while((n=p.getInputStream().read(buf))>0)out.write(buf,0,n);rootResult="exit="+p.waitFor()+" "+out.toString("UTF-8");}catch(Exception e){rootResult=e.toString();}}}).start();
 sensors=(SensorManager)getSystemService(SENSOR_SERVICE);Sensor s=sensors.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);if(s!=null)registered=sensors.registerListener(this,s,SensorManager.SENSOR_DELAY_NORMAL);
 new Thread(new Runnable(){public void run(){try{dns=InetAddress.getByName("example.com").getHostAddress();}catch(Exception e){dns=e.toString();}}}).start();handler.post(tick);
 new Thread(new Runnable(){public void run(){try{HttpsURLConnection c=(HttpsURLConnection)new URL("https://example.com").openConnection();c.setConnectTimeout(10000);c.setReadTimeout(10000);http="HTTP "+c.getResponseCode();c.disconnect();}catch(Exception e){http=e.toString();}}}).start();
 new Thread(new Runnable(){public void run(){try{int size=Math.max(4096,AudioTrack.getMinBufferSize(8000,AudioFormat.CHANNEL_OUT_MONO,AudioFormat.ENCODING_PCM_16BIT));audio=new AudioTrack(AudioManager.STREAM_MUSIC,8000,AudioFormat.CHANNEL_OUT_MONO,AudioFormat.ENCODING_PCM_16BIT,size,AudioTrack.MODE_STREAM);audio.setVolume(0);audio.play();audioState="muted playback";short[] silent=new short[1024];while(running)audio.write(silent,0,silent.length);}catch(Exception e){audioState=e.toString();}}}).start();}
 private Runnable tick=new Runnable(){public void run(){frames++;JSONObject result=new JSONObject();try{result.put("root",rootResult);result.put("uid",android.os.Process.myUid());result.put("elapsedMs",SystemClock.elapsedRealtime());result.put("uiTicks",frames);result.put("sensorRegistered",registered);result.put("sensorEvents",events);result.put("sensorTimestampNs",sensorTime);result.put("dns",dns);result.put("https",http);result.put("touches",touches);result.put("nativeKeyboardText",keyboard.getText().toString());result.put("audio",audioState);result.put("audioFrames",audio==null?0:audio.getPlaybackHeadPosition());
 if(protectedRead==null){try(FileInputStream in=new FileInputStream("/data/local/tmp/ksu-selinux-canary")){in.read();protectedRead="allowed";}catch(Exception e){protectedRead=e.toString();}}result.put("protectedRead",protectedRead);
 if(selinuxObserved==null && selinuxError==null)try(FileInputStream in=new FileInputStream("/sys/fs/selinux/status")){byte[] status=new byte[20];if(in.read(status)!=20)throw new IOException("short SELinux status");ByteBuffer b=ByteBuffer.wrap(status).order(ByteOrder.LITTLE_ENDIAN);JSONObject observed=new JSONObject();observed.put("version",b.getInt());observed.put("sequence",b.getInt());observed.put("enforcing",b.getInt());observed.put("policyload",b.getInt());observed.put("deny_unknown",b.getInt());selinuxObserved=observed;}catch(Exception e){selinuxError=e.toString();}if(selinuxObserved!=null)result.put("selinuxStatus",selinuxObserved);if(selinuxError!=null)result.put("selinuxStatusError",selinuxError);
 try(FileOutputStream out=new FileOutputStream(new File(getFilesDir(),"report.json"))){out.write(result.toString(2).getBytes("UTF-8"));}
 text.setText("MuMu SELinux runtime probe\n\n"+result.toString(2));}catch(Exception e){text.setText(e.toString());}handler.postDelayed(this,500);}};
 public void onSensorChanged(SensorEvent e){events++;sensorTime=e.timestamp;}
 public void onAccuracyChanged(Sensor s,int a){}
 public void onDestroy(){running=false;if(audio!=null){audio.stop();audio.release();}handler.removeCallbacks(tick);sensors.unregisterListener(this);super.onDestroy();}
}
