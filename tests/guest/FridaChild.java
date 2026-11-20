// SPDX-License-Identifier: MIT
package io.github.kernelsuemulator.frida;

/** A Java-owned child avoids holding GumJS's lock across fork/exec. */
public final class FridaChild implements Runnable {
    public static volatile int result = -100;
    public static volatile String error = "";
    public static volatile String control = "";

    public void run() {
        try {
            if (!control.isEmpty()) {
                long deadline = System.nanoTime() + 30000000000L;
                for (;;) {
                    try (java.io.FileInputStream input = new java.io.FileInputStream(control + ".go")) {
                        if (input.read() == '1') break;
                    }
                    if (System.nanoTime() > deadline) throw new java.io.IOException("Child trigger timed out");
                    Thread.sleep(10);
                }
            }
            result = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", "exit 23"}).waitFor();
        } catch (Exception exception) {
            error = exception.toString();
            result = -200;
        } finally {
            if (!control.isEmpty()) {
                try (java.io.FileOutputStream output = new java.io.FileOutputStream(control + ".result")) {
                    output.write(Integer.toString(result).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                } catch (Exception ignored) {}
            }
        }
    }
}
