/*
 * Copyright (c) 2003, 2022, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package sun.security.util;

import java.io.*;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.nio.*;
import java.nio.charset.*;
import java.util.Arrays;
import jdk.internal.access.SharedSecrets;
import jdk.internal.io.JdkConsole;
import jdk.internal.io.JdkConsoleImpl;
import jdk.internal.io.JdkConsoleProviderImpl;
import jdk.internal.util.OperatingSystem;
import jdk.internal.util.StaticProperty;
import sun.nio.cs.UTF_8;

import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * A utility class for reading passwords
 */
public class Password {
    /** Reads user password from given input stream. */
    public static char[] readPassword(InputStream in) throws IOException {
        return readPassword(in, false);
    }

    /** Reads user password from given input stream.
     * @param isEchoOn true if the password should be echoed on the screen
     */
    @SuppressWarnings("fallthrough")
    public static char[] readPassword(InputStream in, boolean isEchoOn)
            throws IOException {

        char[] consoleEntered = null;
        byte[] consoleBytes = null;

        try {
            // Only use Console if `in` is the initial System.in
            if (!isEchoOn &&
                    in == SharedSecrets.getJavaLangAccess().initialSystemIn() &&
                    ConsoleHolder.consoleIsAvailable()) {
                consoleEntered = ConsoleHolder.readPassword();
                // readPassword returns "" if you just press ENTER with the built-in Console,
                // to be compatible with old Password class, change to null
                if (consoleEntered == null || consoleEntered.length == 0) {
                    return null;
                }
                consoleBytes = ConsoleHolder.convertToBytes(consoleEntered);
                in = new ByteArrayInputStream(consoleBytes);
            }

            // Rest of the lines still necessary for KeyStoreLoginModule
            // and when there is no console.

            char[] lineBuffer;
            char[] buf;

            buf = lineBuffer = new char[128];

            int room = buf.length;
            int offset = 0;
            int c;

            boolean done = false;
            while (!done) {
                switch (c = in.read()) {
                  case -1:
                  case '\n':
                      done = true;
                      break;

                  case '\r':
                    int c2 = in.read();
                    if ((c2 != '\n') && (c2 != -1)) {
                        if (!(in instanceof PushbackInputStream)) {
                            in = new PushbackInputStream(in);
                        }
                        ((PushbackInputStream)in).unread(c2);
                    } else {
                        done = true;
                        break;
                    }
                    /* fall through */
                  default:
                    if (--room < 0) {
                        buf = new char[offset + 128];
                        room = buf.length - offset - 1;
                        System.arraycopy(lineBuffer, 0, buf, 0, offset);
                        Arrays.fill(lineBuffer, ' ');
                        lineBuffer = buf;
                    }
                    buf[offset++] = (char) c;
                    break;
                }
            }

            if (offset == 0) {
                return null;
            }

            char[] ret = new char[offset];
            System.arraycopy(buf, 0, ret, 0, offset);
            Arrays.fill(buf, ' ');

            return ret;
        } finally {
            if (consoleEntered != null) {
                Arrays.fill(consoleEntered, ' ');
            }
            if (consoleBytes != null) {
                Arrays.fill(consoleBytes, (byte)0);
            }
        }
    }

    // Everything about Console or JdkConsole is inside this class.
    private static class ConsoleHolder {

        // primary console; may be null
        private static final Console c1;
        // secondary console (when stdout is redirected); may be null
        private static final JdkConsoleImpl c2;
        // encoder for c1 or c2
        private static final CharsetEncoder enc;

        static {
            c1 = System.console();
            Charset charset;
            if (c1 != null) {
                c2 = null;
                charset = c1.charset();
            } else if (isStdinTTY()) {
                Charset stdinCharset =
                        Charset.forName(StaticProperty.stdinEncoding(), UTF_8.INSTANCE);
                Charset stdoutCharset =
                        Charset.forName(StaticProperty.stdoutEncoding(), UTF_8.INSTANCE);
                c2 = (JdkConsoleImpl) new JdkConsoleProviderImpl().console(true, stdinCharset, stdoutCharset);
                charset = stdinCharset;
            } else {
                c2 = null;
                charset = null;
            }
            enc = charset == null ? null : charset.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPLACE)
                    .onUnmappableCharacter(CodingErrorAction.REPLACE);
        }

        public static boolean consoleIsAvailable() {
            return c1 != null || c2 != null;
        }

        public static char[] readPassword() {
            assert consoleIsAvailable();
            if (c1 != null) {
                return c1.readPassword();
            } else {
                try {
                    return c2.readPasswordNoNewLine();
                } finally {
                    System.err.println();
                }
            }
        }

        private static boolean isStdinTTY() {
            return OperatingSystem.isWindows()
                    ? isWindowsStdinTTY() : isUnixStdinTTY();
        }

        @SuppressWarnings("restricted")
        private static boolean isUnixStdinTTY() {
            try {
                Linker linker = Linker.nativeLinker();
                SymbolLookup stdlib = linker.defaultLookup();
                MethodHandle isatty = linker.downcallHandle(
                        stdlib.find("isatty").get(),
                        FunctionDescriptor.of(JAVA_INT, JAVA_INT));
                return (int) isatty.invokeExact(0) != 0;
            } catch (Throwable t) {
                return false;
            }
        }

        @SuppressWarnings("restricted")
        private static boolean isWindowsStdinTTY() {
            try {
                Linker linker = Linker.nativeLinker();
                SymbolLookup lookup = SymbolLookup.libraryLookup("Kernel32", Arena.global());
                MethodHandle getStdHandle = linker.downcallHandle(
                        lookup.find("GetStdHandle").orElseThrow(),
                        FunctionDescriptor.of(JAVA_INT, JAVA_INT));
                MethodHandle getFileType = linker.downcallHandle(
                        lookup.find("GetFileType").orElseThrow(),
                        FunctionDescriptor.of(JAVA_INT, JAVA_INT));
                int hStdIn = (int)
                        getStdHandle.invoke(-10); // STD_INPUT_HANDLE
                if (hStdIn == -1) { // INVALID_HANDLE_VALUE
                    return false;
                }
                return (int) getFileType.invoke(hStdIn) == 2; // FILE_TYPE_CHAR;
            } catch (Throwable e) {
                return false;
            }
        }

        /**
         * Change a password read from Console.readPassword() into
         * its original bytes.
         *
         * @param pass a char[]
         * @return its byte[] format, similar to new String(pass).getBytes()
         */
        public static byte[] convertToBytes(char[] pass) {
            assert consoleIsAvailable();
            byte[] ba = new byte[(int) (enc.maxBytesPerChar() * pass.length)];
            ByteBuffer bb = ByteBuffer.wrap(ba);
            synchronized (enc) {
                enc.reset().encode(CharBuffer.wrap(pass), bb, true);
            }
            if (bb.position() < ba.length) {
                ba[bb.position()] = '\n';
            }
            return ba;
        }
    }
}
