/*
 * Copyright (c) 2005, 2021, Oracle and/or its affiliates. All rights reserved.
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

#ifndef _GSSAPI_EXT_H_
#define _GSSAPI_EXT_H_

#if defined(__MACH__) && defined(__APPLE__)
#       include <TargetConditionals.h>
#       if TARGET_RT_MAC_CFM
#               error "Use KfM 4.0 SDK headers for CFM compilation."
#       endif
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// Condition was copied from
// Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/gssapi/gssapi.h
#if TARGET_OS_MAC && (defined(__ppc__) || defined(__ppc64__) || defined(__i386__) || defined(__x86_64__))
#    pragma pack(push,2)
#endif

/* GGF extensions */
typedef struct gss_buffer_set_desc_struct {
    size_t count;
    gss_buffer_desc *elements;
} gss_buffer_set_desc, *gss_buffer_set_t;

#define GSS_C_NO_BUFFER_SET ((gss_buffer_set_t) 0)

GSS_DLLIMP OM_uint32 gss_release_buffer_set
	(OM_uint32 * /*minor_status*/,
	 gss_buffer_set_t * /*buffer_set*/);

GSS_DLLIMP OM_uint32 gss_inquire_sec_context_by_oid
	(OM_uint32 * /*minor_status*/,
	 const gss_ctx_id_t /*context_handle*/,
	 const gss_OID /*desired_object*/,
	 gss_buffer_set_t * /*data_set*/
);

#if TARGET_OS_MAC && (defined(__ppc__) || defined(__ppc64__) || defined(__i386__) || defined(__x86_64__))
#    pragma pack(pop)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _GSSAPI_EXT_H_ */
