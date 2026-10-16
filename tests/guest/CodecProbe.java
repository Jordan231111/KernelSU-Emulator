import android.graphics.SurfaceTexture;
import android.media.MediaCodec;
import android.media.MediaExtractor;
import android.media.MediaFormat;
import android.opengl.EGL14;
import android.opengl.EGLConfig;
import android.opengl.EGLContext;
import android.opengl.EGLDisplay;
import android.opengl.EGLSurface;
import android.opengl.GLES11Ext;
import android.opengl.GLES20;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import android.view.Surface;
import java.nio.ByteBuffer;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

/** Exercises the real codec service, graphic-buffer import and texture delivery. */
public final class CodecProbe {
    public static void main(String[] args) throws Exception {
        JSONObject result = new JSONObject();
        MediaExtractor extractor = new MediaExtractor();
        MediaCodec codec = null;
        SurfaceTexture texture = null;
        Surface surface = null;
        HandlerThread callbacks = new HandlerThread("codec-probe-frames");
        EGLDisplay display = EGL14.EGL_NO_DISPLAY;
        EGLContext context = EGL14.EGL_NO_CONTEXT;
        EGLSurface pbuffer = EGL14.EGL_NO_SURFACE;
        int frames = 0;
        long started = SystemClock.elapsedRealtime();
        try {
            if (args.length != 3) throw new IllegalArgumentException("FILE CODEC EXPECTED_FRAMES");
            result.put("codec", args[1]);
            result.put("clientUid", android.os.Process.myUid());
            display = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY);
            int[] version = new int[2];
            if (!EGL14.eglInitialize(display, version, 0, version, 1)) throw new Exception("eglInitialize");
            EGLConfig[] configs = new EGLConfig[1];
            int[] count = new int[1];
            int[] attrs = {EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
                EGL14.EGL_SURFACE_TYPE, EGL14.EGL_PBUFFER_BIT, EGL14.EGL_RED_SIZE, 8,
                EGL14.EGL_GREEN_SIZE, 8, EGL14.EGL_BLUE_SIZE, 8, EGL14.EGL_NONE};
            if (!EGL14.eglChooseConfig(display, attrs, 0, configs, 0, 1, count, 0) || count[0] == 0)
                throw new Exception("eglChooseConfig");
            context = EGL14.eglCreateContext(display, configs[0], EGL14.EGL_NO_CONTEXT,
                new int[]{EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE}, 0);
            pbuffer = EGL14.eglCreatePbufferSurface(display, configs[0],
                new int[]{EGL14.EGL_WIDTH, 1, EGL14.EGL_HEIGHT, 1, EGL14.EGL_NONE}, 0);
            if (!EGL14.eglMakeCurrent(display, pbuffer, pbuffer, context)) throw new Exception("eglMakeCurrent");
            int[] ids = new int[1];
            GLES20.glGenTextures(1, ids, 0);
            GLES20.glBindTexture(GLES11Ext.GL_TEXTURE_EXTERNAL_OES, ids[0]);
            texture = new SurfaceTexture(ids[0]);
            final Semaphore available = new Semaphore(0);
            callbacks.start();
            texture.setOnFrameAvailableListener(new SurfaceTexture.OnFrameAvailableListener() {
                public void onFrameAvailable(SurfaceTexture ignored) { available.release(); }
            }, new Handler(callbacks.getLooper()));
            surface = new Surface(texture);
            extractor.setDataSource(args[0]);
            int track = -1;
            for (int i = 0; i < extractor.getTrackCount(); i++) {
                if (extractor.getTrackFormat(i).getString(MediaFormat.KEY_MIME).startsWith("video/")) {
                    track = i; break;
                }
            }
            if (track < 0) throw new Exception("no video track");
            extractor.selectTrack(track);
            MediaFormat format = extractor.getTrackFormat(track);
            result.put("format", format.toString());
            codec = MediaCodec.createByCodecName(args[1]);
            codec.configure(format, surface, null, 0);
            codec.start();
            boolean inputEnded = false, outputEnded = false;
            MediaCodec.BufferInfo info = new MediaCodec.BufferInfo();
            long deadline = SystemClock.elapsedRealtime() + 20000;
            while (!outputEnded && SystemClock.elapsedRealtime() < deadline) {
                if (!inputEnded) {
                    int input = codec.dequeueInputBuffer(10000);
                    if (input >= 0) {
                        ByteBuffer bytes = codec.getInputBuffer(input);
                        int size = extractor.readSampleData(bytes, 0);
                        if (size < 0) {
                            codec.queueInputBuffer(input, 0, 0, 0, MediaCodec.BUFFER_FLAG_END_OF_STREAM);
                            inputEnded = true;
                        } else {
                            codec.queueInputBuffer(input, 0, size, extractor.getSampleTime(), 0);
                            extractor.advance();
                        }
                    }
                }
                int output = codec.dequeueOutputBuffer(info, 10000);
                if (output >= 0) {
                    outputEnded = (info.flags & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0;
                    boolean render = info.size > 0;
                    codec.releaseOutputBuffer(output, render);
                    if (render) {
                        if (!available.tryAcquire(2, TimeUnit.SECONDS)) throw new Exception("texture delivery timed out");
                        texture.updateTexImage();
                        if (GLES20.glGetError() != GLES20.GL_NO_ERROR) throw new Exception("texture GL error");
                        frames++;
                    }
                }
            }
            result.put("eos", outputEnded);
            result.put("passed", outputEnded && frames == Integer.parseInt(args[2]));
        } catch (Throwable error) {
            result.put("passed", false);
            result.put("error", error.toString());
        } finally {
            if (codec != null) { try { codec.release(); } catch (Exception ignored) {} }
            extractor.release();
            if (surface != null) surface.release();
            if (texture != null) texture.release();
            callbacks.quitSafely();
            if (display != EGL14.EGL_NO_DISPLAY) {
                EGL14.eglMakeCurrent(display, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT);
                if (pbuffer != EGL14.EGL_NO_SURFACE) EGL14.eglDestroySurface(display, pbuffer);
                if (context != EGL14.EGL_NO_CONTEXT) EGL14.eglDestroyContext(display, context);
                EGL14.eglTerminate(display);
            }
        }
        result.put("frames", frames);
        result.put("elapsedMs", SystemClock.elapsedRealtime() - started);
        System.out.println("CODEC_PROBE=" + result.toString());
        System.exit(result.optBoolean("passed") ? 0 : 2);
    }
}
