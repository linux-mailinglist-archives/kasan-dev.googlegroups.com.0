Return-Path: <kasan-dev+bncBDK3TPOVRULBBYP723ZAKGQEB35Q6SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B85116F47D
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2020 01:46:27 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id w17sf696531plq.16
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2020 16:46:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582677985; cv=pass;
        d=google.com; s=arc-20160816;
        b=oQhY/M44MTj6LH8ce9QvslPd2bxAChCEWc8Kvcbe3s/6aRUhiVdKfepazVTtRdk9rq
         gE/SCwoNHHlxhHzhkXK7dHdU+SRAyqTtP6ohXCnnG62ywNOfp2qADeysmj+U2YdthZr4
         09JkMCtzU6dae3+64uooKDY1qMehxD8vbZImdPqb8jbU/YO5qsolu1uXltTXLWFyjlF+
         nS5lynDZVJ2ax9NXJafUhWJ9who0CX7XCSCWKrqHjQ075lg5xv092Uq5/3dY8MGDZt8f
         vTr15zXOpqA9go11MXbgEdSOytQSc2HS+wZSJeYO1/HkEwMqpxEGKEcv0NJ2GcRl4lGs
         C0/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=bfGOXb40PNVf85Tdq9BNhrfTce0Dpe0Kg6KWfkmjF9Y=;
        b=a+5ffX1hfciLMmVE3OKlRWHTe5rvZIjKzorfIb5aFZemgvmzPThKdRzhxjcG3Oyid8
         gb1bmOvtnhIzCRAxjZGsro6qPd4IzgkHOEWTFzm9jYib8VJjVSTwpynl8DKp20CWV8Wz
         9wEUBT4S1WMYa0wV1CBLVd+jYgEEL6rl62EXnkNwsSm2pFto77kK0KHYucXsDbjVStrB
         PMPOKIQJhYl5mwMOudKRmUfD5K19p5Q3lplfyOr5p2myTQwg9nXg8nL9vQZFppvQ43cd
         pDqv3tILz+bCigUqfCfatikbxoeRdSrFrk6nx4+mWaz7UwkhwhqhrFx1/Fb1MVl9f66K
         vhoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r8iqvzjB;
       spf=pass (google.com: domain of 34l9vxgwkca8igxhwpaudchdvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=34L9VXgwKCa8igXhWPaUdchdVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=bfGOXb40PNVf85Tdq9BNhrfTce0Dpe0Kg6KWfkmjF9Y=;
        b=gnYXGF+dhLtSmysPnWmVmwtgPcuAZxUlllAiNIOtyB1nCgr3TSu5YnaovMy3555P6a
         AwJLW/SbhZfrZUMPN5o6OOYjh3j/rrxdYRBqdXz7DFLKrqYtfVvoJJj3eRxzNW/7N39A
         5b96RK+95vDFgYjib68F3wnv6kfJ4T0rFhMUkz8JcDM/ZGvgciEfA/9k7DrOTg/b1Gym
         St9wF6HUQR+Wz/g7fK+hHN2riNJI4r7FxdSkZnFCYuBPP3drjoJxVXrZTaTU7/wPMbTf
         QT/6ZsunkkGci43fiJd0nzg2yfasneAzIdb4VTLmsGvGY8EAFyhHDWqBP4jZ0Q4+//xn
         U/bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bfGOXb40PNVf85Tdq9BNhrfTce0Dpe0Kg6KWfkmjF9Y=;
        b=D43++2ZiK18CYSB75Zl3MEJSS/7RvnErlRst8C2vfYcwitCDpa4/KSDuvbuMKv5VQY
         GPV0sXpeXUQQae8FUgzbXlSmMO+7IG4+JDFPaN3tFmd1pnbKyPp/Lt6McPH3vrPIGSZS
         oj+aLZC8wHw2TXbI9xlj4Su7T7GNLAz8CfQGg5gC7e5NFHTX1Iew9o+z8PeRIL4gPAY/
         KQqTsUSLsNXESYOmh96jDuFN2Qcm03S80U4q/XZIA6KLYsR4NUybAVUIqijofrdA2Mb9
         Lc5f6UnnwQPwl7iOTY/W/TAc8Fl4moW7XUWd6eTJprOEoXFCPjweWQjs//CCQIofFbyo
         6VeQ==
X-Gm-Message-State: APjAAAVhbzlmMguuX1CSzg8F4h/wWLlHuaM2Yl9Ytf37IrFnoZxG360C
	rq2gVc+9g+mhiH+FMXuBWTg=
X-Google-Smtp-Source: APXvYqwWO4wQ8EoI04MXTzYfehlIaHlB3URAuM4cHKtTRQRn2Fl06crl9DsQ8/qGo9MGBF7Pq+cr0Q==
X-Received: by 2002:a17:902:ac8b:: with SMTP id h11mr1202250plr.131.1582677985586;
        Tue, 25 Feb 2020 16:46:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d70b:: with SMTP id w11ls377288ply.11.gmail; Tue, 25
 Feb 2020 16:46:25 -0800 (PST)
X-Received: by 2002:a17:90a:e996:: with SMTP id v22mr2023798pjy.53.1582677985179;
        Tue, 25 Feb 2020 16:46:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582677985; cv=none;
        d=google.com; s=arc-20160816;
        b=yCu71GI8YLJcKU48UbPudhWcGDFarovd23OvUaJv7XsVZiK/64EAw6goz6+Zl7M4Nz
         Td2MScD4oxrd3wZll22pOS8gJFAyaVRTL8HyawFRE6Mod5oVz4M231WvxBFN3N5hQC7F
         AESKwsZ2D7FRRla1T5mubjGazgQNTvkNxzvc80RM73FGI3H94xcvRVda2+9cOGmRZs/F
         ajvuwYC6ey8df9gtZXuHKEQd8TVRSlGI0nOBl8ep+qGBnvY8dpWjTXfUrmQBhggqkPPr
         6vZV/6cKOhvQiH4x6p99DZFKuO8Y5zwv54nbUbsq9LiRHifqJiel2K1IUoEWDaxHqw9Q
         UiOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=qg/mLm47H3J3LUrDOT9vShpF52qrmnDuVDLkcH3D2w8=;
        b=nCBRN6BKdsznpiQEikBOTv4DgcapVHU7bsih+VS0rughOKttoAydbTbMrsdyywOHNi
         yt1d/fWHgdCoyXYJX43eavBzWIn60IOj32vHQZpDTnJw4/M1l/1oi+yaUAvL36SwwiZk
         y5uFSXyNT9kD+Z5Rxob3W5Po4ZgTj/gcAIR2pJ4LGJoibk8yHAatA/4HIaK+c6cA2Llp
         Dv/L+zQXiRqJI0GYk8PmOcXY2eELu1F+bUWry1ZkbbG/dZZK6FCdLwbgqjhLN0BSmxjm
         oqxMY8Cgz7Jc2BPGHf4clINY2aThBdU5dcNQOMH6Cy7X9k+reQKmnXtNkFn39RjG30H1
         ZRTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r8iqvzjB;
       spf=pass (google.com: domain of 34l9vxgwkca8igxhwpaudchdvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=34L9VXgwKCa8igXhWPaUdchdVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x549.google.com (mail-pg1-x549.google.com. [2607:f8b0:4864:20::549])
        by gmr-mx.google.com with ESMTPS id y13si47021plp.0.2020.02.25.16.46.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Feb 2020 16:46:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 34l9vxgwkca8igxhwpaudchdvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) client-ip=2607:f8b0:4864:20::549;
Received: by mail-pg1-x549.google.com with SMTP id l17so580739pgh.21
        for <kasan-dev@googlegroups.com>; Tue, 25 Feb 2020 16:46:25 -0800 (PST)
X-Received: by 2002:a63:770d:: with SMTP id s13mr1108426pgc.7.1582677984725;
 Tue, 25 Feb 2020 16:46:24 -0800 (PST)
Date: Tue, 25 Feb 2020 16:46:08 -0800
Message-Id: <20200226004608.8128-1-trishalfonso@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH] UML: add support for KASAN under x86_64
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
To: jdike@addtoit.com, richard@nod.at, anton.ivanov@cambridgegreys.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, brendanhiggins@google.com, 
	davidgow@google.com, johannes@sipsolutions.net
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-um@lists.infradead.org, Patricia Alfonso <trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=r8iqvzjB;       spf=pass
 (google.com: domain of 34l9vxgwkca8igxhwpaudchdvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=34L9VXgwKCa8igXhWPaUdchdVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

Make KASAN run on User Mode Linux on x86_64.

Depends on Constructor support in UML - "[RFC PATCH] um:
implement CONFIG_CONSTRUCTORS for modules"
(https://patchwork.ozlabs.org/patch/1234551/) by Johannes Berg.

The location of the KASAN shadow memory, starting at
KASAN_SHADOW_OFFSET, can be configured using the
KASAN_SHADOW_OFFSET option. UML uses roughly 18TB of address
space, and KASAN requires 1/8th of this. The default location of
this offset is 0x7fff8000 as suggested by Dmitry Vyukov. There is
usually enough free space at this location; however, it is a config
option so that it can be easily changed if needed.

The UML-specific KASAN initializer uses mmap to map
the roughly 2.25TB of shadow memory to the location defined by
KASAN_SHADOW_OFFSET. kasan_init() utilizes constructors to initialize
KASAN before main().

Disable stack instrumentation on UML via KASAN_STACK config option to
avoid false positive KASAN reports.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
---
 arch/um/Kconfig                  | 13 +++++++++++++
 arch/um/Makefile                 |  6 ++++++
 arch/um/include/asm/common.lds.S |  1 +
 arch/um/include/asm/kasan.h      | 32 ++++++++++++++++++++++++++++++++
 arch/um/kernel/dyn.lds.S         |  5 ++++-
 arch/um/kernel/mem.c             | 18 ++++++++++++++++++
 arch/um/os-Linux/mem.c           | 22 ++++++++++++++++++++++
 arch/um/os-Linux/user_syms.c     |  4 ++--
 arch/x86/um/Makefile             |  3 ++-
 arch/x86/um/vdso/Makefile        |  3 +++
 lib/Kconfig.kasan                |  2 +-
 11 files changed, 104 insertions(+), 5 deletions(-)
 create mode 100644 arch/um/include/asm/kasan.h

diff --git a/arch/um/Kconfig b/arch/um/Kconfig
index 0917f8443c28..fb2ad1fb05fd 100644
--- a/arch/um/Kconfig
+++ b/arch/um/Kconfig
@@ -8,6 +8,7 @@ config UML
 	select ARCH_HAS_KCOV
 	select ARCH_NO_PREEMPT
 	select HAVE_ARCH_AUDITSYSCALL
+	select HAVE_ARCH_KASAN if X86_64
 	select HAVE_ARCH_SECCOMP_FILTER
 	select HAVE_ASM_MODVERSIONS
 	select HAVE_UID16
@@ -200,6 +201,18 @@ config UML_TIME_TRAVEL_SUPPORT
 
 	  It is safe to say Y, but you probably don't need this.
 
+config KASAN_SHADOW_OFFSET
+	hex
+	depends on KASAN
+	default 0x7fff8000
+	help
+	  This is the offset at which the ~2.25TB of shadow memory is
+	  mapped and used by KASAN for memory debugging. This can be any
+	  address that has at least KASAN_SHADOW_SIZE(total address space divided
+	  by 8) amount of space so that the KASAN shadow memory does not conflict
+	  with anything. The default is 0x7fff8000, as it fits into immediate of
+	  most instructions.
+
 endmenu
 
 source "arch/um/drivers/Kconfig"
diff --git a/arch/um/Makefile b/arch/um/Makefile
index d2daa206872d..28fe7a9a1858 100644
--- a/arch/um/Makefile
+++ b/arch/um/Makefile
@@ -75,6 +75,12 @@ USER_CFLAGS = $(patsubst $(KERNEL_DEFINES),,$(patsubst -I%,,$(KBUILD_CFLAGS))) \
 		-D_FILE_OFFSET_BITS=64 -idirafter $(srctree)/include \
 		-idirafter $(objtree)/include -D__KERNEL__ -D__UM_HOST__
 
+# Kernel config options are not included in USER_CFLAGS, but the option for KASAN
+# should be included if the KASAN config option was set.
+ifdef CONFIG_KASAN
+	USER_CFLAGS+=-DCONFIG_KASAN=y
+endif
+
 #This will adjust *FLAGS accordingly to the platform.
 include $(ARCH_DIR)/Makefile-os-$(OS)
 
diff --git a/arch/um/include/asm/common.lds.S b/arch/um/include/asm/common.lds.S
index eca6c452a41b..731f8c8422a2 100644
--- a/arch/um/include/asm/common.lds.S
+++ b/arch/um/include/asm/common.lds.S
@@ -83,6 +83,7 @@
   }
   .init_array : {
 	__init_array_start = .;
+	*(.kasan_init)
 	*(.init_array)
 	__init_array_end = .;
   }
diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
new file mode 100644
index 000000000000..2b81e7bcd4af
--- /dev/null
+++ b/arch/um/include/asm/kasan.h
@@ -0,0 +1,32 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __ASM_UM_KASAN_H
+#define __ASM_UM_KASAN_H
+
+#include <linux/init.h>
+#include <linux/const.h>
+
+#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+
+/* used in kasan_mem_to_shadow to divide by 8 */
+#define KASAN_SHADOW_SCALE_SHIFT 3
+
+#ifdef CONFIG_X86_64
+#define KASAN_HOST_USER_SPACE_END_ADDR 0x00007fffffffffffUL
+/* KASAN_SHADOW_SIZE is the size of total address space divided by 8 */
+#define KASAN_SHADOW_SIZE ((KASAN_HOST_USER_SPACE_END_ADDR + 1) >> \
+			KASAN_SHADOW_SCALE_SHIFT)
+#else
+#error "KASAN_SHADOW_SIZE is not defined for this sub-architecture"
+#endif /* CONFIG_X86_64 */
+
+#define KASAN_SHADOW_START (KASAN_SHADOW_OFFSET)
+#define KASAN_SHADOW_END (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
+
+#ifdef CONFIG_KASAN
+void kasan_init(void);
+void kasan_map_memory(void *start, unsigned long len);
+#else
+static inline void kasan_init(void) { }
+#endif /* CONFIG_KASAN */
+
+#endif /* __ASM_UM_KASAN_H */
diff --git a/arch/um/kernel/dyn.lds.S b/arch/um/kernel/dyn.lds.S
index f5001481010c..d91bdb2c3143 100644
--- a/arch/um/kernel/dyn.lds.S
+++ b/arch/um/kernel/dyn.lds.S
@@ -103,7 +103,10 @@ SECTIONS
      be empty, which isn't pretty.  */
   . = ALIGN(32 / 8);
   .preinit_array     : { *(.preinit_array) }
-  .init_array     : { *(.init_array) }
+  .init_array     : {
+    *(.kasan_init)
+    *(.init_array)
+  }
   .fini_array     : { *(.fini_array) }
   .data           : {
     INIT_TASK_DATA(KERNEL_STACK_SIZE)
diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
index 30885d0b94ac..7b0d028aa079 100644
--- a/arch/um/kernel/mem.c
+++ b/arch/um/kernel/mem.c
@@ -18,6 +18,24 @@
 #include <kern_util.h>
 #include <mem_user.h>
 #include <os.h>
+#include <linux/sched/task.h>
+
+#ifdef CONFIG_KASAN
+void kasan_init(void)
+{
+	/*
+	 * kasan_map_memory will map all of the required address space and
+	 * the host machine will allocate physical memory as necessary.
+	 */
+	kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
+	init_task.kasan_depth = 0;
+	os_info("KernelAddressSanitizer initialized\n");
+}
+
+static void (*kasan_init_ptr)(void)
+__section(.kasan_init) __used
+= kasan_init;
+#endif
 
 /* allocated in paging_init, zeroed in mem_init, and unchanged thereafter */
 unsigned long *empty_zero_page = NULL;
diff --git a/arch/um/os-Linux/mem.c b/arch/um/os-Linux/mem.c
index 3c1b77474d2d..8530b2e08604 100644
--- a/arch/um/os-Linux/mem.c
+++ b/arch/um/os-Linux/mem.c
@@ -17,6 +17,28 @@
 #include <init.h>
 #include <os.h>
 
+/*
+ * kasan_map_memory - maps memory from @start with a size of @len.
+ * The allocated memory is filled with zeroes upon success.
+ * @start: the start address of the memory to be mapped
+ * @len: the length of the memory to be mapped
+ *
+ * This function is used to map shadow memory for KASAN in uml
+ */
+void kasan_map_memory(void *start, size_t len)
+{
+	if (mmap(start,
+		 len,
+		 PROT_READ|PROT_WRITE,
+		 MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE,
+		 -1,
+		 0) == MAP_FAILED) {
+		os_info("Couldn't allocate shadow memory: %s\n.",
+			strerror(errno));
+		exit(1);
+	}
+}
+
 /* Set by make_tempfile() during early boot. */
 static char *tempdir = NULL;
 
diff --git a/arch/um/os-Linux/user_syms.c b/arch/um/os-Linux/user_syms.c
index 715594fe5719..cb667c9225ab 100644
--- a/arch/um/os-Linux/user_syms.c
+++ b/arch/um/os-Linux/user_syms.c
@@ -27,10 +27,10 @@ EXPORT_SYMBOL(strstr);
 #ifndef __x86_64__
 extern void *memcpy(void *, const void *, size_t);
 EXPORT_SYMBOL(memcpy);
-#endif
-
 EXPORT_SYMBOL(memmove);
 EXPORT_SYMBOL(memset);
+#endif
+
 EXPORT_SYMBOL(printf);
 
 /* Here, instead, I can provide a fake prototype. Yes, someone cares: genksyms.
diff --git a/arch/x86/um/Makefile b/arch/x86/um/Makefile
index 33c51c064c77..7dbd76c546fe 100644
--- a/arch/x86/um/Makefile
+++ b/arch/x86/um/Makefile
@@ -26,7 +26,8 @@ else
 
 obj-y += syscalls_64.o vdso/
 
-subarch-y = ../lib/csum-partial_64.o ../lib/memcpy_64.o ../entry/thunk_64.o
+subarch-y = ../lib/csum-partial_64.o ../lib/memcpy_64.o ../entry/thunk_64.o \
+	../lib/memmove_64.o ../lib/memset_64.o
 
 endif
 
diff --git a/arch/x86/um/vdso/Makefile b/arch/x86/um/vdso/Makefile
index 0caddd6acb22..450efa0fb694 100644
--- a/arch/x86/um/vdso/Makefile
+++ b/arch/x86/um/vdso/Makefile
@@ -3,6 +3,9 @@
 # Building vDSO images for x86.
 #
 
+# do not instrument on vdso because KASAN is not compatible with user mode
+KASAN_SANITIZE			:= n
+
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
 KCOV_INSTRUMENT                := n
 
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 81f5464ea9e1..5b54f3c9a741 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -125,7 +125,7 @@ config KASAN_STACK_ENABLE
 
 config KASAN_STACK
 	int
-	default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
+	default 1 if (KASAN_STACK_ENABLE || CC_IS_GCC) && !UML
 	default 0
 
 config KASAN_S390_4_LEVEL_PAGING
-- 
2.25.0.265.gbab2e86ba0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200226004608.8128-1-trishalfonso%40google.com.
