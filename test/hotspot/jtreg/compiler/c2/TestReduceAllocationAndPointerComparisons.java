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
 * @bug 8347718
 * @summary Check that Reduce Allocation Merges correctly handle "NE" pointer comparisons.
 * @requires vm.flagless & vm.compiler2.enabled & vm.opt.final.EliminateAllocations
 * @run main/othervm -XX:CompileCommand=compileonly,*TestReduceAllocationAndPointerComparisons*::*
 *                   -XX:CompileCommand=dontinline,*TestReduceAllocationAndPointerComparisons*::*
 *                   -XX:-TieredCompilation -Xcomp
 *                   compiler.c2.TestReduceAllocationAndPointerComparisons
 * @run main compiler.c2.TestReduceAllocationAndPointerComparisons
 */

package compiler.c2;

public class TestReduceAllocationAndPointerComparisons {
    public static void main(String[] args) {
        for (int i=0; i<50000; i++) {
            if (test(true) == false) {
                throw new RuntimeException("Unexpected result.");
            }
        }
    }

    public static boolean test(boolean b) {
        MyClass obj = new MyClass();

        for (int i = 0; i < 100_000; ++i) { }

        obj = b ? obj : new MyClass();
        obj = b ? obj : new MyClass();

        if (obj == null) {
            return false;
        }

        return b;
    }

    static class MyClass {
    }
}
