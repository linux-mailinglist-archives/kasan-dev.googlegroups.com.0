Return-Path: <kasan-dev+bncBDK3TPOVRULBBA6AQ7ZAKGQECSHKJHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc37.google.com (mail-yw1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id B94A71585D1
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 23:58:12 +0100 (CET)
Received: by mail-yw1-xc37.google.com with SMTP id l12sf7359596ywk.6
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 14:58:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581375491; cv=pass;
        d=google.com; s=arc-20160816;
        b=deVwyffoUQFPiBuKSvhC+pefpciXZQ/Vht7O3nzVDWy/7QHxlyhNr7lBhzyhi9oZeX
         EotUNfe7zJSp3/9kApd8KAWC0qaHSicdkQ6R36S0D75Z5RwYEBDzYEVyrDAga9vtadyz
         qTdByd/aW7poD4MfSvrnG0otnxe8baoALAeaOIJgB245RMi9zgbucXchSiHD+5rBcfwb
         E6zqpTA5K5SG2ENh7aOuOGcKopCrSMEh2ugGgCQtAWeq4W3XkXCESSoCV7Jjlqa12dE3
         uQ8Oi76oLFYJ1ap8eE4S4QYIFhiMqxR7QHOXnfN0X4ln7VAVcwuYPTzNRve4LUAEb97h
         6Xsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=VDq26oaU6058bv2kw+9ijRGRF4cBvDPulEYA9n90LQs=;
        b=roJku0DzLgwAgbh1O15e4j0oXnPVC3b6zq84CWxqouJYBnH70STb4yMn+VyDf0TmwY
         FPB4Vy5r+LODVN9Ozy423GUKemoLQOpBPqrCg3xcTDIousgAFcV++DcZiFK9LNTCwYQX
         megwLVFtX9aVmHRKhDxU5iE0IAsqlM+Io3G7KPHFGtafGL+JMp2yy3PyMceHdJ/zmU2b
         UGBgdCi9nRwop33YFKtb3z3oFVC24SmC72zMnZSkfEVjg46qzPNAQX3gghW7RDQ7hCSO
         nh1j4P/okXeM8X1ibkWwgnfKPsO5SCPmlzt1qjFSfCybcnWdnOOuPNQH3cFO76FmeWTu
         b4Ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GFdrTt3S;
       spf=pass (google.com: domain of 3aubbxgwkcce0ypzohsmvuzvnvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3AuBBXgwKCcE0ypzohsmvuzvnvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=VDq26oaU6058bv2kw+9ijRGRF4cBvDPulEYA9n90LQs=;
        b=bR4ssal3dRJpEGcbYTr/yCgfs27cdVACj9S7IzeczntrcAmoZQFgPK6bUAwpw0WIXi
         68AYRcfGkoBRtShIWclhxsS6d8pomONHsz/NfnZLPKdopSytL8KZiWLUEEaeCWmPw45L
         fjroYWXYgiAhYQOWZmbxVURPpQme0d550aSH0vjRQI2XQtQ0NWfywvUX5HldDZLwszUN
         L8Ypw3WJ0qKN4S0rulvNx/8VEfN1KQn1VdzC+ndtXXjL8YgqHDSg4XuphsqLIOeHaYE+
         4NCPnjJVB6JPR3x0VFLNneKK8IgXHhHt56iSXjYwSsz9Ky1C6EDeQIGuheyJgvpNK13D
         73qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VDq26oaU6058bv2kw+9ijRGRF4cBvDPulEYA9n90LQs=;
        b=Q0nqiWTGkvnv5k7fXBaefEbjTomRX7/njq1XniSBHokBAg8sAchyHPoy6RITTHQGhm
         P7QZskxGU1kjeZlqno/4rXQk+tqdsmDq/CUgFF3XS+3vfdT3vDgXDHtiADkNlx3y/b7g
         kk4psCVEZxpke4UcvZjNRWlYOCef5LkWJWrg2JIfCUeYR1k71XOA1jqUraX+HoP4QKjt
         6G7JgTXPNh/jxiGtYcTL/12ibBt+GbYJ/tdUcrVcwb6EWCtZyLkIOGe2ZT8uKhXNurY7
         1SFIUvImKbgPJ4xls4adi5w0z/A8Us/uOgIa/YczbIVuNw5AhZANX9tyWAkTMj1uLJBO
         GNpw==
X-Gm-Message-State: APjAAAWy0kBD6N2C/YNoen1qmv2zN0n52VVBo6bSLkR11kqhq84pVQwx
	aRAH2t+TdBrdN3yBYDk0GAo=
X-Google-Smtp-Source: APXvYqxJ+Ysqzgrl57v0omll3xk2B+cPj0ifO1w0HhGKvbjPHwatGzkEejklEU9l7iJ5Q0X8pu+VeQ==
X-Received: by 2002:a81:bb54:: with SMTP id a20mr3301228ywl.408.1581375491448;
        Mon, 10 Feb 2020 14:58:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2f88:: with SMTP id v130ls666357ybv.2.gmail; Mon, 10 Feb
 2020 14:58:11 -0800 (PST)
X-Received: by 2002:a25:ab65:: with SMTP id u92mr3621936ybi.472.1581375491059;
        Mon, 10 Feb 2020 14:58:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581375491; cv=none;
        d=google.com; s=arc-20160816;
        b=X6tDFhgRbdPigF9fDOPMpdthvdv1X+6m3u/HbKJdIxv5gW/8kZhMw/pCSKeL1DN/Bz
         TAjE9s3rqwX9xBvWJq5lCsgE/y4CjsfDOvN4OGO/b/QyvUfrGYMRCW72IAJ1xMBvG65Z
         vJRGGnD9i/VZe0aBhhA/Fc6gvIPzhSyPXki5RUhZXp4eOA5ElhaV0VKtppgNjbBqwVjI
         KGtgwJIps3uwKTeRxqEDAc05Of9/puZEzRspRrGPwRgf0Lptp0SknIr0ICRqQr/hjslC
         zIEF3cLt1iX4OVBH3SRlkLkVVNv0nP+gWf+OQjIggf6LcYcMmejau8M5ujTEt5EeL2JO
         Sqdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=e3IohNnZH1pK34OxxjwQrgjk1+u95jywj4N942Qaffg=;
        b=hnKvFKyOOco2aDqTQpHN6ZMCpAvoonahNP7ZAwR+W/wWVgHuMnmuM9tks2c2MW3vo6
         qr8ZHgGIJ0mSAoK6msO15IE5sTiIfXHSmgVKS2sf6lMDlY2aB5ZqkuxvOJt9xT5pf1cD
         v6D+GIvYsavN4YFSU/5qXiv22Qo9Ly2kzcPr7YsPuVGZcQlNnVJKfcQdDMspy/trqe0A
         dG2Q3Cc7dNMJoepipvTpjkb1nikLa27Wh2p/7YyjgqY3XKvYM5ytpbKIY4Dfsjlad1HU
         rwi4zhHR6ycnGchBIzUwvYNxjpPTCdpDNjAAukQG3lUIlN/6LAeEVlOvjppP1hnFX1hw
         3dog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GFdrTt3S;
       spf=pass (google.com: domain of 3aubbxgwkcce0ypzohsmvuzvnvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3AuBBXgwKCcE0ypzohsmvuzvnvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x649.google.com (mail-pl1-x649.google.com. [2607:f8b0:4864:20::649])
        by gmr-mx.google.com with ESMTPS id l1si27146ybt.2.2020.02.10.14.58.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 14:58:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 3aubbxgwkcce0ypzohsmvuzvnvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) client-ip=2607:f8b0:4864:20::649;
Received: by mail-pl1-x649.google.com with SMTP id c19so3681045plz.19
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 14:58:11 -0800 (PST)
X-Received: by 2002:a63:26c4:: with SMTP id m187mr3932433pgm.410.1581375490395;
 Mon, 10 Feb 2020 14:58:10 -0800 (PST)
Date: Mon, 10 Feb 2020 14:58:06 -0800
Message-Id: <20200210225806.249297-1-trishalfonso@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [RFC PATCH v2] UML: add support for KASAN under x86_64
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
To: jdike@addtoit.com, richard@nod.at, anton.ivanov@cambridgegreys.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, davidgow@google.com, 
	brendanhiggins@google.com, johannes@sipsolutions.net
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-um@lists.infradead.org, Patricia Alfonso <trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GFdrTt3S;       spf=pass
 (google.com: domain of 3aubbxgwkcce0ypzohsmvuzvnvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3AuBBXgwKCcE0ypzohsmvuzvnvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--trishalfonso.bounces.google.com;
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

Depends on Constructor support in UML and is based off of
"[RFC PATCH] um: implement CONFIG_CONSTRUCTORS for modules"
(https://patchwork.ozlabs.org/patch/1234551/) and "[DEMO] um:
demonstrate super early constructors"
(https://patchwork.ozlabs.org/patch/1234553/) by
Johannes.

The location of the KASAN shadow memory, starting at
KASAN_SHADOW_OFFSET, can be configured using the
KASAN_SHADOW_OFFSET option. UML uses roughly 18TB of address
space, and KASAN requires 1/8th of this. The default location of
this offset is 0x100000000000. There is usually enough free space at
this location; however, it is a config option so that it can be
easily changed if needed.

The UML-specific KASAN initializer uses mmap to map
the roughly 2.25TB of shadow memory to the location defined by
KASAN_SHADOW_OFFSET.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
---

Changes since v1:
 - KASAN has been initialized much earlier.
 - With the help of Johannes's RFC patch to implement constructors in
   UML and Demo showing how kasan_init could take advantage of these
   super early constructors, most of the "KASAN_SANITIZE := n" have
   been removed.
 - Removed extraneous code
 - Fixed typos

 arch/um/Kconfig              | 10 ++++++++++
 arch/um/Makefile             |  6 ++++++
 arch/um/include/asm/dma.h    |  1 +
 arch/um/include/asm/kasan.h  | 30 ++++++++++++++++++++++++++++++
 arch/um/kernel/Makefile      | 22 ++++++++++++++++++++++
 arch/um/kernel/mem.c         | 19 +++++++++----------
 arch/um/os-Linux/mem.c       | 19 +++++++++++++++++++
 arch/um/os-Linux/user_syms.c |  4 ++--
 arch/x86/um/Makefile         |  3 ++-
 arch/x86/um/vdso/Makefile    |  3 +++
 10 files changed, 104 insertions(+), 13 deletions(-)
 create mode 100644 arch/um/include/asm/kasan.h

diff --git a/arch/um/Kconfig b/arch/um/Kconfig
index 0917f8443c28..2b76dc273731 100644
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
@@ -200,6 +201,15 @@ config UML_TIME_TRAVEL_SUPPORT
 
 	  It is safe to say Y, but you probably don't need this.
 
+config KASAN_SHADOW_OFFSET
+	hex
+	depends on KASAN
+	default 0x100000000000
+	help
+	  This is the offset at which the ~2.25TB of shadow memory is
+	  initialized and used by KASAN for memory debugging. The default
+	  is 0x100000000000.
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
 
diff --git a/arch/um/include/asm/dma.h b/arch/um/include/asm/dma.h
index fdc53642c718..8aafd60d62bb 100644
--- a/arch/um/include/asm/dma.h
+++ b/arch/um/include/asm/dma.h
@@ -5,6 +5,7 @@
 #include <asm/io.h>
 
 extern unsigned long uml_physmem;
+extern unsigned long long physmem_size;
 
 #define MAX_DMA_ADDRESS (uml_physmem)
 
diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
new file mode 100644
index 000000000000..ba08061068cf
--- /dev/null
+++ b/arch/um/include/asm/kasan.h
@@ -0,0 +1,30 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __ASM_UM_KASAN_H
+#define __ASM_UM_KASAN_H
+
+#include <linux/init.h>
+#include <linux/const.h>
+
+#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+#ifdef CONFIG_X86_64
+#define KASAN_SHADOW_SIZE 0x100000000000UL
+#else
+#error "KASAN_SHADOW_SIZE is not defined for this sub-architecture"
+#endif /* CONFIG_X86_64 */
+
+// used in kasan_mem_to_shadow to divide by 8
+#define KASAN_SHADOW_SCALE_SHIFT 3
+
+#define KASAN_SHADOW_START (KASAN_SHADOW_OFFSET)
+#define KASAN_SHADOW_END (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
+
+#ifdef CONFIG_KASAN
+void kasan_init(void);
+#else
+static inline void kasan_init(void) { }
+#endif /* CONFIG_KASAN */
+
+void kasan_map_memory(void *start, unsigned long len);
+void kasan_unpoison_shadow(const void *address, size_t size);
+
+#endif /* __ASM_UM_KASAN_H */
diff --git a/arch/um/kernel/Makefile b/arch/um/kernel/Makefile
index 5aa882011e04..875e1827588b 100644
--- a/arch/um/kernel/Makefile
+++ b/arch/um/kernel/Makefile
@@ -8,6 +8,28 @@
 # kernel.
 KCOV_INSTRUMENT                := n
 
+# The way UMl deals with the stack causes seemingly false positive KASAN
+# reports such as:
+# BUG: KASAN: stack-out-of-bounds in show_stack+0x15e/0x1fb
+# Read of size 8 at addr 000000006184bbb0 by task swapper/1
+# ==================================================================
+# BUG: KASAN: stack-out-of-bounds in dump_trace+0x141/0x1c5
+# Read of size 8 at addr 0000000071057eb8 by task swapper/1
+# ==================================================================
+# BUG: KASAN: stack-out-of-bounds in get_wchan+0xd7/0x138
+# Read of size 8 at addr 0000000070e8fc80 by task systemd/1
+#
+# With these files removed from instrumentation, those reports are
+# eliminated, but KASAN still repeatedly reports a bug on syscall_stub_data:
+# ==================================================================
+# BUG: KASAN: stack-out-of-bounds in syscall_stub_data+0x299/0x2bf
+# Read of size 128 at addr 0000000071457c50 by task swapper/1
+
+KASAN_SANITIZE_stacktrace.o := n
+KASAN_SANITIZE_sysrq.o := n
+KASAN_SANITIZE_process.o := n
+
+
 CPPFLAGS_vmlinux.lds := -DSTART=$(LDS_START)		\
                         -DELF_ARCH=$(LDS_ELF_ARCH)	\
                         -DELF_FORMAT=$(LDS_ELF_FORMAT)	\
diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
index 32fc941c80f7..7b7b8a0ee724 100644
--- a/arch/um/kernel/mem.c
+++ b/arch/um/kernel/mem.c
@@ -18,21 +18,20 @@
 #include <kern_util.h>
 #include <mem_user.h>
 #include <os.h>
+#include <linux/sched/task.h>
 
-extern int printf(const char *msg, ...);
-static void early_print(void)
+#ifdef CONFIG_KASAN
+void kasan_init(void)
 {
-	printf("I'm super early, before constructors\n");
+	kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
+	init_task.kasan_depth = 0;
+	os_info("KernelAddressSanitizer initialized\n");
 }
 
-static void __attribute__((constructor)) constructor_test(void)
-{
-	printf("yes, you can see it\n");
-}
-
-static void (*early_print_ptr)(void)
+static void (*kasan_init_ptr)(void)
 __attribute__((section(".kasan_init"), used))
- = early_print;
+= kasan_init;
+#endif
 
 /* allocated in paging_init, zeroed in mem_init, and unchanged thereafter */
 unsigned long *empty_zero_page = NULL;
diff --git a/arch/um/os-Linux/mem.c b/arch/um/os-Linux/mem.c
index 3c1b77474d2d..da7039721d35 100644
--- a/arch/um/os-Linux/mem.c
+++ b/arch/um/os-Linux/mem.c
@@ -17,6 +17,25 @@
 #include <init.h>
 #include <os.h>
 
+/**
+ * kasan_map_memory() - maps memory from @start with a size of @len.
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
+		 0) == MAP_FAILED)
+		os_info("Couldn't allocate shadow memory %s", strerror(errno));
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
 
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200210225806.249297-1-trishalfonso%40google.com.
