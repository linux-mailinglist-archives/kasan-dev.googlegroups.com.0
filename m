Return-Path: <kasan-dev+bncBAABB3GM4WJQMGQEETH2RYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 992FD5204F0
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 21:07:24 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id p7-20020a170906614700b006f87f866117sf1992965ejl.21
        for <lists+kasan-dev@lfdr.de>; Mon, 09 May 2022 12:07:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652123244; cv=pass;
        d=google.com; s=arc-20160816;
        b=wllRyqVSYy+MfdriXO6cXqRBWxfC2eUwqorcOC3BP95MVm1QnYS4wl/ynE4pxYEUx7
         Hp/nnTQK/DYxcrOcWX5HTEJjXn/yGcGBi9ZlEdzsnEHyX/RVl26e3givWRVtmf+Kqb7B
         MG4/U/uYMI72mzhNuIKtXwFfLlcLHQHYkkzvY/9aqXIbErpM19P2Og+/IHBJlRIAXufj
         tUexHlPeIkGE851K0TL6E5rCJjdnRTR8jT8GTY7Ey/nwT9NvEDdNrreRbtsODQm1Iufx
         YlGUnkTHqEn+r8I2GBbM2d9H4B0Qkg7elfnGStTZumq5lUp5r60Ex1VzEduOmSnVpQAN
         pN8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=sK5ls7ewnI5ZJIGdO6XEVmbJi3ps1HAEPpM2yYJSneo=;
        b=IMUiSfcDz2pTr+X6NXnx2V02W4HYlvPbkMvwgdGUaGrinNiA4O5uTrguFI3DSLUCge
         NujJrSQFrUonP4PfNsOUG75ZJoSdEBm+NnjENYlSCnl56IEnjTiRelbQplm76xbahA3D
         3Lx8K96Ww9lzHKUwxrVbV8FWbZrkvDUXxGHhw5Fh/n9yJN7SnrNZHSu98v4H+3dV2ZJR
         6OrHXIRPqJGyYDxeL1z917El+5TP6udAsVrIRmPSTx2PizokJd4CFeBINiVOoJjTKh3o
         lc1fGLDp/YbTfuzEft2VGtF7J2p5PiCUIInV3V18KxuYtsE/p8G19JIKqjaasl2xSG/I
         p/yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pHAhi9Ve;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sK5ls7ewnI5ZJIGdO6XEVmbJi3ps1HAEPpM2yYJSneo=;
        b=XNMwXwPp2Va9tlboJtNHDLpqGm/liX8y8nb77nDivXPUGOH4JvHcUyw2RjtvosJlcT
         fFDROgh60OH8l3W0gbJQfZlO359oPS5avkX4PYV+Fd9kU6H5Olt3lth++DUqeUmMOoUm
         P6mBUaSLFckNSYExq36cyBPj2ZLFjTJ6yosoY9Gr1QBiEasSIEvp1/UIb009ISBjxm8e
         r9TGYRhUwWSKug7zhZkDiQvu8svlAg1il1G8j8cSkapc0bJ+H9/e82BKeYLpgqNN+jaN
         wnz4/mAazeRXNsofaBl87xWtPb/pnfkcl5KcU4R2Ph3KF1GJhEVRR8D2ZD2BS6SW5BN+
         xWHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sK5ls7ewnI5ZJIGdO6XEVmbJi3ps1HAEPpM2yYJSneo=;
        b=kG1/hq311NZqkKVMlr08Wk7LcpTvTIa7b/FWgtKOjFlvRyxw+/pzRCwpgCw9sVyqVw
         7/vYTWGjKgAlIl5vVx/NrXPtmIVVsY6Ut+2/rs1Vf6FMS3OVOYPBkdQCprgtU1pVQqKe
         Flv76awWPt195srrq+pNxCoa7OKsT+ZWr9k2Q2JrZLhQWqd89k+1vlI7ge/j+kt0boiI
         S5xZASSfp1NKvAbsa8VyxmbdxF3kCgLnZMM6toMTXrUzym6i2o1pTJTP0fwbIGC8Bqba
         WkmUWNXcCMrs4QwUBdDYLX/8YOOubjB+10afLtc7rHFky7Wiz9N/tlX3SJ8/KJGrBh+a
         C7IA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Q6M3XTlHUWDnXFsffTwkZlzxnPbkSV5YZNt0x8o5jJUHdP1EJ
	vdAKSS4DLx/cNg1R47R67h8=
X-Google-Smtp-Source: ABdhPJyXJo8bSOMh8U+9mlYoCI6PoZu9y1TxSPC9ErX3u+KOMfRjaix7lBkUzuTPHXauQeatye7cLw==
X-Received: by 2002:a17:907:94c6:b0:6f5:287a:2bf2 with SMTP id dn6-20020a17090794c600b006f5287a2bf2mr15615635ejc.124.1652123244235;
        Mon, 09 May 2022 12:07:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:270b:b0:427:d070:5bfe with SMTP id
 y11-20020a056402270b00b00427d0705bfels535627edd.0.gmail; Mon, 09 May 2022
 12:07:23 -0700 (PDT)
X-Received: by 2002:aa7:d9d9:0:b0:425:fcc7:d132 with SMTP id v25-20020aa7d9d9000000b00425fcc7d132mr18612295eds.89.1652123243417;
        Mon, 09 May 2022 12:07:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652123243; cv=none;
        d=google.com; s=arc-20160816;
        b=Vm6/7Hgurdo2CI6i6Te2z21iLLB6AIq4VHklpaKV2uvfqwM5CmegTcF2W6h8zeqwo4
         NsbRuDtQtqAyCjMdfgRgRADJ3IQkCkaZTYCqFUofhjHf1ydgicqy+v5c+w7OoGqnG2/x
         Bw32GG7+L4vG/Kf7mhRtKohbnpsQK2HsqjNQmIOGUTCXTYaGtnUgNEwaf7Rt1NXfDqbw
         wIiYO3tlAbz602wu+yzwfsSrg5i6veiThHQTYmxoiLuR5yGjFDnjVN8yTLLcwD4WvHfk
         F8Pw0IcU18qlup/w/Lh3298fIjWEfC6H8C6A6VSPdq9MVDgthyuSFkySnwVl+ZeMQK4H
         o0rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=tB7yvQtIjl4xLNyNlj6OakMN3VM4GzJtE82SJQIVc3k=;
        b=bkfOxsQXrF07VF//trMA8odS2eTBaKH/gNxvHkLA4vPc6WxZnZqLCkuWpTMvgabSVW
         OA9zKWLL3erLyS6dZMUXIvO84DtPCcCJTVi/wh2GbtyqMowu5awN5t8ecZpJjKeU6i9G
         9texVEHrSD7Oqiudi2W5jhvtJa5JhMy1gvqJj2ObkvvN22miRmqz14OnnldES22RR3Cf
         dN73I9GIqJ7r+HqScwHJAk0Oq6cjPFpjzf9CmYR+W+nZhaoKpPU6mb3TK+S29S7itnk1
         D1Xm24fnC9yYGHDAPNjA4d0rUEqmV7q+kA+7XoQyYvbSb6as0T1nXXQw4QFFwtlY8Yc5
         AxaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pHAhi9Ve;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id gv43-20020a1709072beb00b006e8421b806dsi837847ejc.1.2022.05.09.12.07.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 09 May 2022 12:07:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 1/3] kasan: update documentation
Date: Mon,  9 May 2022 21:07:17 +0200
Message-Id: <5bd58ebebf066593ce0e1d265d60278b5f5a1874.1652123204.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=pHAhi9Ve;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

From: Andrey Konovalov <andreyknvl@google.com>

Do assorted clean-ups and improvements to KASAN documentation, including:

- Describe each mode in a dedicated paragraph.
- Split out a Support section that describes in details which compilers,
  architectures and memory types each mode requires/supports.
- Capitalize the first letter in the names of each KASAN mode.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 143 ++++++++++++++++++------------
 1 file changed, 87 insertions(+), 56 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 7614a1fc30fa..aca219ed1198 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -4,39 +4,76 @@ The Kernel Address Sanitizer (KASAN)
 Overview
 --------
 
-KernelAddressSANitizer (KASAN) is a dynamic memory safety error detector
-designed to find out-of-bound and use-after-free bugs. KASAN has three modes:
+Kernel Address Sanitizer (KASAN) is a dynamic memory safety error detector
+designed to find out-of-bounds and use-after-free bugs.
 
-1. generic KASAN (similar to userspace ASan),
-2. software tag-based KASAN (similar to userspace HWASan),
-3. hardware tag-based KASAN (based on hardware memory tagging).
+KASAN has three modes:
 
-Generic KASAN is mainly used for debugging due to a large memory overhead.
-Software tag-based KASAN can be used for dogfood testing as it has a lower
-memory overhead that allows using it with real workloads. Hardware tag-based
-KASAN comes with low memory and performance overheads and, therefore, can be
-used in production. Either as an in-field memory bug detector or as a security
-mitigation.
+1. Generic KASAN
+2. Software Tag-Based KASAN
+3. Hardware Tag-Based KASAN
 
-Software KASAN modes (#1 and #2) use compile-time instrumentation to insert
-validity checks before every memory access and, therefore, require a compiler
-version that supports that.
+Generic KASAN, enabled with CONFIG_KASAN_GENERIC, is the mode intended for
+debugging, similar to userspace ASan. This mode is supported on many CPU
+architectures, but it has significant performance and memory overheads.
 
-Generic KASAN is supported in GCC and Clang. With GCC, it requires version
-8.3.0 or later. Any supported Clang version is compatible, but detection of
-out-of-bounds accesses for global variables is only supported since Clang 11.
+Software Tag-Based KASAN or SW_TAGS KASAN, enabled with CONFIG_KASAN_SW_TAGS,
+can be used for both debugging and dogfood testing, similar to userspace HWASan.
+This mode is only supported for arm64, but its moderate memory overhead allows
+using it for testing on memory-restricted devices with real workloads.
 
-Software tag-based KASAN mode is only supported in Clang.
+Hardware Tag-Based KASAN or HW_TAGS KASAN, enabled with CONFIG_KASAN_HW_TAGS,
+is the mode intended to be used as an in-field memory bug detector or as a
+security mitigation. This mode only works on arm64 CPUs that support MTE
+(Memory Tagging Extension), but it has low memory and performance overheads and
+thus can be used in production.
 
-The hardware KASAN mode (#3) relies on hardware to perform the checks but
-still requires a compiler version that supports memory tagging instructions.
-This mode is supported in GCC 10+ and Clang 12+.
+For details about the memory and performance impact of each KASAN mode, see the
+descriptions of the corresponding Kconfig options.
 
-Both software KASAN modes work with SLUB and SLAB memory allocators,
-while the hardware tag-based KASAN currently only supports SLUB.
+The Generic and the Software Tag-Based modes are commonly referred to as the
+software modes. The Software Tag-Based and the Hardware Tag-Based modes are
+referred to as the tag-based modes.
 
-Currently, generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390,
-and riscv architectures, and tag-based KASAN modes are supported only for arm64.
+Support
+-------
+
+Architectures
+~~~~~~~~~~~~~
+
+Generic KASAN is supported on x86_64, arm, arm64, powerpc, riscv, s390, and
+xtensa, and the tag-based KASAN modes are supported only on arm64.
+
+Compilers
+~~~~~~~~~
+
+Software KASAN modes use compile-time instrumentation to insert validity checks
+before every memory access and thus require a compiler version that provides
+support for that. The Hardware Tag-Based mode relies on hardware to perform
+these checks but still requires a compiler version that supports the memory
+tagging instructions.
+
+Generic KASAN requires GCC version 8.3.0 or later
+or any Clang version supported by the kernel.
+
+Software Tag-Based KASAN requires GCC 11+
+or any Clang version supported by the kernel.
+
+Hardware Tag-Based KASAN requires GCC 10+ or Clang 12+.
+
+Memory types
+~~~~~~~~~~~~
+
+Generic KASAN supports finding bugs in all of slab, page_alloc, vmap, vmalloc,
+stack, and global memory.
+
+Software Tag-Based KASAN supports slab, page_alloc, vmalloc, and stack memory.
+
+Hardware Tag-Based KASAN supports slab, page_alloc, and non-executable vmalloc
+memory.
+
+For slab, both software KASAN modes support SLUB and SLAB allocators, while
+Hardware Tag-Based KASAN only supports SLUB.
 
 Usage
 -----
@@ -45,13 +82,13 @@ To enable KASAN, configure the kernel with::
 
 	  CONFIG_KASAN=y
 
-and choose between ``CONFIG_KASAN_GENERIC`` (to enable generic KASAN),
-``CONFIG_KASAN_SW_TAGS`` (to enable software tag-based KASAN), and
-``CONFIG_KASAN_HW_TAGS`` (to enable hardware tag-based KASAN).
+and choose between ``CONFIG_KASAN_GENERIC`` (to enable Generic KASAN),
+``CONFIG_KASAN_SW_TAGS`` (to enable Software Tag-Based KASAN), and
+``CONFIG_KASAN_HW_TAGS`` (to enable Hardware Tag-Based KASAN).
 
-For software modes, also choose between ``CONFIG_KASAN_OUTLINE`` and
+For the software modes, also choose between ``CONFIG_KASAN_OUTLINE`` and
 ``CONFIG_KASAN_INLINE``. Outline and inline are compiler instrumentation types.
-The former produces a smaller binary while the latter is 1.1-2 times faster.
+The former produces a smaller binary while the latter is up to 2 times faster.
 
 To include alloc and free stack traces of affected slab objects into reports,
 enable ``CONFIG_STACKTRACE``. To include alloc and free stack traces of affected
@@ -146,7 +183,7 @@ is either 8 or 16 aligned bytes depending on KASAN mode. Each number in the
 memory state section of the report shows the state of one of the memory
 granules that surround the accessed address.
 
-For generic KASAN, the size of each memory granule is 8. The state of each
+For Generic KASAN, the size of each memory granule is 8. The state of each
 granule is encoded in one shadow byte. Those 8 bytes can be accessible,
 partially accessible, freed, or be a part of a redzone. KASAN uses the following
 encoding for each shadow byte: 00 means that all 8 bytes of the corresponding
@@ -181,14 +218,14 @@ By default, KASAN prints a bug report only for the first invalid memory access.
 With ``kasan_multi_shot``, KASAN prints a report on every invalid access. This
 effectively disables ``panic_on_warn`` for KASAN reports.
 
-Alternatively, independent of ``panic_on_warn`` the ``kasan.fault=`` boot
+Alternatively, independent of ``panic_on_warn``, the ``kasan.fault=`` boot
 parameter can be used to control panic and reporting behaviour:
 
 - ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
   report or also panic the kernel (default: ``report``). The panic happens even
   if ``kasan_multi_shot`` is enabled.
 
-Hardware tag-based KASAN mode (see the section about various modes below) is
+Hardware Tag-Based KASAN mode (see the section about various modes below) is
 intended for use in production as a security mitigation. Therefore, it supports
 additional boot parameters that allow disabling KASAN or controlling features:
 
@@ -250,49 +287,46 @@ outline-instrumented kernel.
 Generic KASAN is the only mode that delays the reuse of freed objects via
 quarantine (see mm/kasan/quarantine.c for implementation).
 
-Software tag-based KASAN
+Software Tag-Based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
 
-Software tag-based KASAN uses a software memory tagging approach to checking
+Software Tag-Based KASAN uses a software memory tagging approach to checking
 access validity. It is currently only implemented for the arm64 architecture.
 
-Software tag-based KASAN uses the Top Byte Ignore (TBI) feature of arm64 CPUs
+Software Tag-Based KASAN uses the Top Byte Ignore (TBI) feature of arm64 CPUs
 to store a pointer tag in the top byte of kernel pointers. It uses shadow memory
 to store memory tags associated with each 16-byte memory cell (therefore, it
 dedicates 1/16th of the kernel memory for shadow memory).
 
-On each memory allocation, software tag-based KASAN generates a random tag, tags
+On each memory allocation, Software Tag-Based KASAN generates a random tag, tags
 the allocated memory with this tag, and embeds the same tag into the returned
 pointer.
 
-Software tag-based KASAN uses compile-time instrumentation to insert checks
+Software Tag-Based KASAN uses compile-time instrumentation to insert checks
 before each memory access. These checks make sure that the tag of the memory
 that is being accessed is equal to the tag of the pointer that is used to access
-this memory. In case of a tag mismatch, software tag-based KASAN prints a bug
+this memory. In case of a tag mismatch, Software Tag-Based KASAN prints a bug
 report.
 
-Software tag-based KASAN also has two instrumentation modes (outline, which
+Software Tag-Based KASAN also has two instrumentation modes (outline, which
 emits callbacks to check memory accesses; and inline, which performs the shadow
 memory checks inline). With outline instrumentation mode, a bug report is
 printed from the function that performs the access check. With inline
 instrumentation, a ``brk`` instruction is emitted by the compiler, and a
 dedicated ``brk`` handler is used to print bug reports.
 
-Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
+Software Tag-Based KASAN uses 0xFF as a match-all pointer tag (accesses through
 pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
 reserved to tag freed memory regions.
 
-Software tag-based KASAN currently only supports tagging of slab, page_alloc,
-and vmalloc memory.
-
-Hardware tag-based KASAN
+Hardware Tag-Based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
 
-Hardware tag-based KASAN is similar to the software mode in concept but uses
+Hardware Tag-Based KASAN is similar to the software mode in concept but uses
 hardware memory tagging support instead of compiler instrumentation and
 shadow memory.
 
-Hardware tag-based KASAN is currently only implemented for arm64 architecture
+Hardware Tag-Based KASAN is currently only implemented for arm64 architecture
 and based on both arm64 Memory Tagging Extension (MTE) introduced in ARMv8.5
 Instruction Set Architecture and Top Byte Ignore (TBI).
 
@@ -302,21 +336,18 @@ access, hardware makes sure that the tag of the memory that is being accessed is
 equal to the tag of the pointer that is used to access this memory. In case of a
 tag mismatch, a fault is generated, and a report is printed.
 
-Hardware tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
+Hardware Tag-Based KASAN uses 0xFF as a match-all pointer tag (accesses through
 pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
 reserved to tag freed memory regions.
 
-Hardware tag-based KASAN currently only supports tagging of slab, page_alloc,
-and VM_ALLOC-based vmalloc memory.
-
-If the hardware does not support MTE (pre ARMv8.5), hardware tag-based KASAN
+If the hardware does not support MTE (pre ARMv8.5), Hardware Tag-Based KASAN
 will not be enabled. In this case, all KASAN boot parameters are ignored.
 
 Note that enabling CONFIG_KASAN_HW_TAGS always results in in-kernel TBI being
 enabled. Even when ``kasan.mode=off`` is provided or when the hardware does not
 support MTE (but supports TBI).
 
-Hardware tag-based KASAN only reports the first found bug. After that, MTE tag
+Hardware Tag-Based KASAN only reports the first found bug. After that, MTE tag
 checking gets disabled.
 
 Shadow memory
@@ -414,15 +445,15 @@ generic ``noinstr`` one.
 Note that disabling compiler instrumentation (either on a per-file or a
 per-function basis) makes KASAN ignore the accesses that happen directly in
 that code for software KASAN modes. It does not help when the accesses happen
-indirectly (through calls to instrumented functions) or with the hardware
-tag-based mode that does not use compiler instrumentation.
+indirectly (through calls to instrumented functions) or with Hardware
+Tag-Based KASAN, which does not use compiler instrumentation.
 
 For software KASAN modes, to disable KASAN reports in a part of the kernel code
 for the current task, annotate this part of the code with a
 ``kasan_disable_current()``/``kasan_enable_current()`` section. This also
 disables the reports for indirect accesses that happen through function calls.
 
-For tag-based KASAN modes (include the hardware one), to disable access
+For tag-based KASAN modes (include the Hardware one), to disable access
 checking, use ``kasan_reset_tag()`` or ``page_kasan_tag_reset()``. Note that
 temporarily disabling access checking via ``page_kasan_tag_reset()`` requires
 saving and restoring the per-page KASAN tag via
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5bd58ebebf066593ce0e1d265d60278b5f5a1874.1652123204.git.andreyknvl%40google.com.
