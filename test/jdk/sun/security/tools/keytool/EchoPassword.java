/*
 * Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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

/*
 * @test
 * @bug 8354469
 * @summary keytool password prompt shows warning when cannot suppress echo
 * @library /java/awt/regtesthelpers
 * @build PassFailJFrame
 * @run main/manual/othervm EchoPassword
 */

import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.event.HyperlinkEvent;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.file.Path;

public class EchoPassword {

    static JLabel label;

    public static void main(String[] args) throws Exception {

        var ks = Path.of("8354469.ks").toAbsolutePath();

        final String keytool = String.format("\"%s/bin/keytool\" -keystore " + ks,
                System.getProperty("java.home").replace("\\", File.separator));

        final String gen = keytool + " -genkeypair -keyalg ec";
        final String firstCommand = gen + " -dname cn=a -alias first";
        final String secondCommand = gen + " -dname cn=b -alias second | sort";
        final String thirdCommand = "echo changeit| " + gen + " -dname cn=c -alias third";
        final String fourthCommand = keytool + " -exportcert -alias first | " + keytool + " -printcert -rfc";

        final String message = String.format("""
                <html>Perform the following steps and record the final result:
                <ol>
                <li>Open a terminal or Windows Command Prompt window.

                <li>Click <a href='First'>Copy First Command</a> to copy the following command into
                the system clipboard. Paste it into the terminal window and execute the command.
                <pre>
                %s
                </pre>
                When prompted, enter "changeit" and press Enter. When prompted again, enter
                "changeit" again and press Enter. Verify that both passwords are hidden
                and a key pair is generated successfully.

                <li>Click <a href='Second'>Copy Second Command</a> to copy the following command into
                the system clipboard. Paste it into the terminal window and execute the command.
                <pre>
                %s
                </pre>
                When prompted, enter "changeit" and press Enter. Verify that the password is hidden.
                and a key pair is generated successfully.

                <li>Click <a href='Third'>Copy Third Command</a> to copy the following command into
                the system clipboard. Paste it into the terminal window and execute the command.
                <pre>
                %s
                </pre>
                You will see a prompt but you don't need to enter anything. Verify that the password
                "changeit" is not shown in the command output and a key pair is generated successfully.

                <li>Click <a href='Fourth'>Copy Fourth Command</a> to copy the following command into
                the system clipboard. Paste it into the terminal window and execute the command.
                <pre>
                %s
                </pre>
                When prompted, enter "changeit" and press Enter. Verify that the password is hidden
                and a PEM style certificate is correctly shown.
                </ol>
                Press "pass" if the behavior matches expectations; otherwise, press "fail".
                """, firstCommand, secondCommand, thirdCommand, fourthCommand);

        PassFailJFrame.builder()
                .instructions(message)
                .addHyperlinkListener(e -> {
                    if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                                new StringSelection(switch (e.getDescription()) {
                                    case "First" -> firstCommand;
                                    case "Second" -> secondCommand;
                                    case "Third" -> thirdCommand;
                                    default -> fourthCommand;
                                }), null);
                        label.setText(e.getDescription() + " command copied");
                        if (e.getSource() instanceof JEditorPane ep) {
                            ep.getCaret().setVisible(false);
                        }
                    }
                })
                .columns(100)
                .splitUIBottom(() -> {
                    label = new JLabel("Status");
                    return label;
                })
                .build()
                .awaitAndCheck();
    }
}
