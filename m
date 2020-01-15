Return-Path: <kasan-dev+bncBDK3TPOVRULBBR5T7XYAKGQEKXNFVVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2204F13CC16
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 19:28:25 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id s23sf10787748pgg.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 10:28:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579112903; cv=pass;
        d=google.com; s=arc-20160816;
        b=GRdmj4d5g66BzmbvqpCWtbDgXeLAs2l7McNBeMAcNQCuZRad3zGGTry87XE3gOXZws
         aknZPe0b+5xH8k8SsfiQ2s4G5RtXkFp6OSnL/31TaX3D+100Mf+XQ+V8SJLkmQe4Q2Lq
         XtU4QoRGdks+AZUx7SAFE2Qabrz47pYRQegKNyUdUCj6BYOgwl0HXpzjAyduW/BENro/
         UW3MRb0/aitnrZgBv8t3JWXuUCdHTFLM2gRSOQUNEoyQSGQhKQMfPm+DBFjf7vIsJnge
         CPLsw1GhmawFyJ1HTCJNI0lL7kR9IpqYrRNSg4MxaPeqI6zZGUF5UFfR3AZ/ZwSVKBoy
         /FQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=APct/ktBlBA6GypagsuhltP2v2doH21+u0Ihu4GAJ44=;
        b=BE32q//XM3irj7yz3r9RDq4GyTLqznFT0UOHfrvxrsJOb2fz67lwUiUfCImB47PkNg
         Ey9dkqaSpBSZYD3wN/FBIXB+UtJl3cmdTqhPOMQmfmow9sBPxgDruuCft0N3P5eawDSf
         ZRHxbt3YTFiHx/qsJyCSY/tOmhAUoTHd38sILmaRoe9NtjvbcqhU9mdWDpdTsP4LdftX
         2JWL2xTIOM0C6myB3XutFwRMs+Fd8Ny8zhMGUckHdT6rCslJZ8+20pSn2BmSaenrkwtH
         u+QrUISFwQhAF1mtwNaI0tAwjhZ9DItr6oLc6iSZXi1lCjXV0jxgdb6u4wc/vQW2cVPa
         QuRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q1t2R4u2;
       spf=pass (google.com: domain of 3xlkfxgwkce0igxhwpaudchdvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3xlkfXgwKCe0igXhWPaUdchdVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=APct/ktBlBA6GypagsuhltP2v2doH21+u0Ihu4GAJ44=;
        b=bXp8NUKhBQHokbjLo8mO4NcUluLfUQl/fU8D2ycpx1bGdHcy2CkbTztrUwkW9yrX/m
         RCVcIrB6LniHdVqHhDbZaZIQCESjMb13m90FTluMDciCCFRZ3fB6Dog0sabxd/F75ZwX
         5rw3F/w0D6mKnQP2YWTyenE0tqy3gRbYboZi7OTYZJj4jykrmDh4q58GbByF2VghWJrR
         4abQkkiujBida0N99GuG3glXPc+nVOoyiSdyCPf7dg1NIUeQWnQJFvT74nntCDE8qZ+W
         EmYpx9gR0a3LNhGhVcscW2Rt8XdmcbJThZFh47yjEL2SXmP0TMzyo3zVE5Ajwa+4yBjr
         OsGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=APct/ktBlBA6GypagsuhltP2v2doH21+u0Ihu4GAJ44=;
        b=PJkzn4xbGeeeMsX9t8I0z+3uwrorSVqPWKLKhEUIqDJ8HWjMArNWkz3nIk9cGVHx8j
         M2sPfhJeYjnT7s4tkkU++1zhGesrziJhFuH/uVvxW+FSp86oigCHCo5dAsC5VAorEhVo
         RfmY8wlu9LxXUHFQESXeBR3YVOJqD1ROJ5GDwneVwpcmzAxo6QZMVgTA1VbGPxloEEPF
         kR9GH5f3/w7MGfAYGmQ7l43vEM9r/bTW77DfZbT7bhnZhHcYQz73ZD9UU8LnpMpv6lit
         eWqyOUMphz1MLhE9o+A7QwnP3D9QQjlWYr5mxqbnTaXtKJAXNcrfm9dQ35YyHnLDDW6c
         8hfA==
X-Gm-Message-State: APjAAAUEXrgkKbdnCJgcFtsVMJHVqKgNBcQOfg/oj/fDQPBC+ZQLuO9P
	9jMwagmqQ7bRDtEQmfxoSJk=
X-Google-Smtp-Source: APXvYqzZ3jDxG7EoLPhidDFE9wWgD6oNnmZIOyz0FR2i5xdBRY0Nrwyn99Lec+bZ1GF7rHMu/3Rhtg==
X-Received: by 2002:a65:4d46:: with SMTP id j6mr35493112pgt.63.1579112903702;
        Wed, 15 Jan 2020 10:28:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b601:: with SMTP id b1ls1463931pls.3.gmail; Wed, 15
 Jan 2020 10:28:23 -0800 (PST)
X-Received: by 2002:a17:90a:e646:: with SMTP id ep6mr1493325pjb.58.1579112903319;
        Wed, 15 Jan 2020 10:28:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579112903; cv=none;
        d=google.com; s=arc-20160816;
        b=xq9QlIN29kUYYxWACtFH1tEje79fkeukAWQg0mZ0q6CsUJdiaqsVIKQoohdwu7yOXf
         +NatiqTPl/qTBCx/thxWsyQQ5Pe9fH8oXUVzoEpDo6ctpQjSEduHshjyO4cdicIjYGrw
         eyzb4IeuIC96aH24D5WxEYlZdbXJyYFVrfKtTW7qR7dfbmitHOPZLsBh+QJjA/C7EIaR
         DCjXDAQzG7C7lsDoxbIDplMRqIaX3o0lLhVFPDkhTjyn34wwmWw0P1uKQaXyzzMKyvgW
         RVSq7rLc/HCAO8ZbLM8CiKPMIQOLN6jVrDmEQyOt8yU+H3XfRO6AlgB9VrJCDFk4mVwZ
         lr1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=9RQh/5QKLq1tjl9ikRbjGdu2IL7r2jcXxm8Y8M/x+EI=;
        b=nhcvmRLELgPLHmkEKp/mg87Sd3CxzSpqK85Kcu7PnxR6yeXhEIfjHAh6dDQH77l3gC
         wWPHbddNorDxsgj7y19k9dLL1LAgEFE/zX7HvZ8diVrb2PONiClibLHaePENc2D0cJoV
         Qv7XSa+xHpUEujFdRFhxV1/ivZg2iAMuz8Z4BGI7H9s+pCkKTgBseZFEAu2pI0kRSC4Y
         LBX0vRQ4wJoZfRDXRkSGe0ADipA12Uvbyf7vzA8sH9ODPrwx2FPOu9mWz++uQ31sfL9X
         4RpKrUud2wg0gyKZWATaCjpdXJeYKGtzl0+gjJChjN8UY9Flh1+deTVKr/nhgFTDFKXg
         WuUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q1t2R4u2;
       spf=pass (google.com: domain of 3xlkfxgwkce0igxhwpaudchdvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3xlkfXgwKCe0igXhWPaUdchdVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x44a.google.com (mail-pf1-x44a.google.com. [2607:f8b0:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id d12si250824pjv.0.2020.01.15.10.28.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 10:28:23 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xlkfxgwkce0igxhwpaudchdvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) client-ip=2607:f8b0:4864:20::44a;
Received: by mail-pf1-x44a.google.com with SMTP id 8so11417445pfb.22
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 10:28:23 -0800 (PST)
X-Received: by 2002:a63:941:: with SMTP id 62mr35749169pgj.203.1579112902953;
 Wed, 15 Jan 2020 10:28:22 -0800 (PST)
Date: Wed, 15 Jan 2020 10:28:16 -0800
Message-Id: <20200115182816.33892-1-trishalfonso@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.rc1.283.g88dfdc4193-goog
Subject: [RFC PATCH] UML: add support for KASAN under x86_64
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
To: jdike@addtoit.com, richard@nod.at, anton.ivanov@cambridgegreys.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, davidgow@google.com, 
	brendanhiggins@google.com
Cc: linux-um@lists.infradead.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Patricia Alfonso <trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=q1t2R4u2;       spf=pass
 (google.com: domain of 3xlkfxgwkce0igxhwpaudchdvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3xlkfXgwKCe0igXhWPaUdchdVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--trishalfonso.bounces.google.com;
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

The location of the KASAN shadow memory, starting at
KASAN_SHADOW_OFFSET, can be configured using the
KASAN_SHADOW_OFFSET option. UML uses roughly 18TB of address
space, and KASAN requires 1/8th of this. For this reason, the default
location is 0x100000000000. There is usually enough free space at
this location; however, it is a config option so that it can be
easily changed if needed.

Functions that are used before KASAN is initialized are excluded from
instrumentation. The UML-specific KASAN initializer uses mmap to map
the roughly 2.25TB of shadow memory to the location defined by
KASAN_SHADOW_OFFSET and ensures that the address space used by the
kernel text and the vmalloc region is not poisoned at
initialization.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
---
 arch/um/Kconfig                | 10 ++++++++++
 arch/um/include/asm/dma.h      |  1 +
 arch/um/include/asm/kasan.h    | 32 ++++++++++++++++++++++++++++++++
 arch/um/kernel/Makefile        |  4 ++++
 arch/um/kernel/kasan_init_um.c | 20 ++++++++++++++++++++
 arch/um/kernel/skas/Makefile   |  6 ++++++
 arch/um/kernel/um_arch.c       |  3 +++
 arch/um/os-Linux/mem.c         | 18 ++++++++++++++++++
 arch/um/os-Linux/user_syms.c   |  4 ++--
 arch/x86/um/Makefile           |  3 ++-
 arch/x86/um/vdso/Makefile      |  3 +++
 kernel/Makefile                |  6 ++++++
 lib/Makefile                   | 10 ++++++++++
 13 files changed, 117 insertions(+), 3 deletions(-)
 create mode 100644 arch/um/include/asm/kasan.h
 create mode 100644 arch/um/kernel/kasan_init_um.c

diff --git a/arch/um/Kconfig b/arch/um/Kconfig
index 6f0edd0c0220..99c68863e7e9 100644
--- a/arch/um/Kconfig
+++ b/arch/um/Kconfig
@@ -8,6 +8,7 @@ config UML
 	select ARCH_HAS_KCOV
 	select ARCH_NO_PREEMPT
 	select HAVE_ARCH_AUDITSYSCALL
+	select HAVE_ARCH_KASAN
 	select HAVE_ARCH_SECCOMP_FILTER
 	select HAVE_ASM_MODVERSIONS
 	select HAVE_UID16
@@ -198,6 +199,15 @@ config UML_TIME_TRAVEL_SUPPORT
 
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
index 000000000000..ca4c43a35d41
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
+#ifdef CONFIG_X86_64
+#define KASAN_SHADOW_SIZE 0x100000000000UL
+#else
+#error "KASAN_SHADOW_SIZE is not defined in this sub-architecture"
+#endif
+
+// used in kasan_mem_to_shadow to divide by 8
+#define KASAN_SHADOW_SCALE_SHIFT 3
+
+#define KASAN_SHADOW_START (KASAN_SHADOW_OFFSET)
+#define KASAN_SHADOW_END (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
+
+#ifdef CONFIG_KASAN
+void kasan_init(void);
+void kasan_map_shadow(void);
+#else
+static inline void kasan_early_init(void) { }
+static inline void kasan_init(void) { }
+#endif /* CONFIG_KASAN */
+
+void kasan_map_memory(void *start, unsigned long len);
+void kasan_unpoison_shadow(const void *address, size_t size);
+
+#endif /* __ASM_UM_KASAN_H */
diff --git a/arch/um/kernel/Makefile b/arch/um/kernel/Makefile
index 5aa882011e04..f783a7dd863c 100644
--- a/arch/um/kernel/Makefile
+++ b/arch/um/kernel/Makefile
@@ -8,6 +8,9 @@
 # kernel.
 KCOV_INSTRUMENT                := n
 
+# Do not instrument on main.o
+KASAN_SANITIZE	:= n
+
 CPPFLAGS_vmlinux.lds := -DSTART=$(LDS_START)		\
                         -DELF_ARCH=$(LDS_ELF_ARCH)	\
                         -DELF_FORMAT=$(LDS_ELF_FORMAT)	\
@@ -24,6 +27,7 @@ obj-$(CONFIG_GPROF)	+= gprof_syms.o
 obj-$(CONFIG_GCOV)	+= gmon_syms.o
 obj-$(CONFIG_EARLY_PRINTK) += early_printk.o
 obj-$(CONFIG_STACKTRACE) += stacktrace.o
+obj-$(CONFIG_KASAN)	+= kasan_init_um.o
 
 USER_OBJS := config.o
 
diff --git a/arch/um/kernel/kasan_init_um.c b/arch/um/kernel/kasan_init_um.c
new file mode 100644
index 000000000000..2e9a85216fb5
--- /dev/null
+++ b/arch/um/kernel/kasan_init_um.c
@@ -0,0 +1,20 @@
+// SPDX-License-Identifier: GPL-2.0
+#include <asm/kasan.h>
+#include <linux/sched.h>
+#include <linux/sched/task.h>
+#include <asm/dma.h>
+#include <as-layout.h>
+
+void kasan_init(void)
+{
+	kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
+
+	// unpoison the kernel text which is form uml_physmem -> uml_reserved
+	kasan_unpoison_shadow((void *)uml_physmem, physmem_size);
+
+	// unpoison the vmalloc region, which is start_vm -> end_vm
+	kasan_unpoison_shadow((void *)start_vm, (end_vm - start_vm + 1));
+
+	init_task.kasan_depth = 0;
+	pr_info("KernelAddressSanitizer initialized\n");
+}
diff --git a/arch/um/kernel/skas/Makefile b/arch/um/kernel/skas/Makefile
index f3d494a4fd9b..d68f447274e5 100644
--- a/arch/um/kernel/skas/Makefile
+++ b/arch/um/kernel/skas/Makefile
@@ -5,6 +5,12 @@
 
 obj-y := clone.o mmu.o process.o syscall.o uaccess.o
 
+ifdef CONFIG_UML
+# Do not instrument until after start_uml() because KASAN is not
+# initialized yet
+KASAN_SANITIZE	:= n
+endif
+
 # clone.o is in the stub, so it can't be built with profiling
 # GCC hardened also auto-enables -fpic, but we need %ebx so it can't work ->
 # disable it
diff --git a/arch/um/kernel/um_arch.c b/arch/um/kernel/um_arch.c
index 0f40eccbd759..73cd159d28e8 100644
--- a/arch/um/kernel/um_arch.c
+++ b/arch/um/kernel/um_arch.c
@@ -14,6 +14,7 @@
 #include <linux/sched/task.h>
 #include <linux/kmsg_dump.h>
 
+#include <asm/kasan.h>
 #include <asm/pgtable.h>
 #include <asm/processor.h>
 #include <asm/sections.h>
@@ -227,6 +228,8 @@ static struct notifier_block panic_exit_notifier = {
 
 void uml_finishsetup(void)
 {
+	kasan_init();
+
 	atomic_notifier_chain_register(&panic_notifier_list,
 				       &panic_exit_notifier);
 
diff --git a/arch/um/os-Linux/mem.c b/arch/um/os-Linux/mem.c
index 3c1b77474d2d..ef282bacc58e 100644
--- a/arch/um/os-Linux/mem.c
+++ b/arch/um/os-Linux/mem.c
@@ -17,6 +17,24 @@
 #include <init.h>
 #include <os.h>
 
+/**
+ * kasan_map_memory() - maps memory from @start with a size of @len
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
 
diff --git a/kernel/Makefile b/kernel/Makefile
index f2cc0d118a0b..4fbb72cb253f 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -32,6 +32,12 @@ KCOV_INSTRUMENT_kcov.o := n
 KASAN_SANITIZE_kcov.o := n
 CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
 
+ifdef CONFIG_UML
+# Do not istrument kasan on panic because it can be called before KASAN
+# is initialized
+KASAN_SANITIZE_panic.o := n
+endif
+
 # cond_syscall is currently not LTO compatible
 CFLAGS_sys_ni.o = $(DISABLE_LTO)
 
diff --git a/lib/Makefile b/lib/Makefile
index 93217d44237f..e28dc5b06ae2 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -17,6 +17,16 @@ KCOV_INSTRUMENT_list_debug.o := n
 KCOV_INSTRUMENT_debugobjects.o := n
 KCOV_INSTRUMENT_dynamic_debug.o := n
 
+# Don't sanatize vsprintf or string functions in UM because they are used
+# before KASAN is initialized from cmdline parsing cmdline and kstrtox are
+# also called during uml initialization before KASAN is instrumented
+ifdef CONFIG_UML
+KASAN_SANITIZE_vsprintf.o := n
+KASAN_SANITIZE_string.o := n
+KASAN_SANITIZE_cmdline.o := n
+KASAN_SANITIZE_kstrtox.o := n
+endif
+
 # Early boot use of cmdline, don't instrument it
 ifdef CONFIG_AMD_MEM_ENCRYPT
 KASAN_SANITIZE_string.o := n
-- 
2.25.0.rc1.283.g88dfdc4193-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200115182816.33892-1-trishalfonso%40google.com.
