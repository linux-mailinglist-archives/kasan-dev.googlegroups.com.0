Return-Path: <kasan-dev+bncBAABBS4B2HWAKGQEWE5USWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id E38ABC4799
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2019 08:16:44 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id b2sf9246712otl.23
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 23:16:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569997003; cv=pass;
        d=google.com; s=arc-20160816;
        b=TtgxWSFXDpTQFaLOigJiokTsK0MuUHRNBn9RBGblFNkPKVPbyTxKg5HWLLv8QQMoSj
         7HuKAcDGCuoUE3SOHXIyEUZpHmRgvp7anOJqrP4Q1t22LFddAN9qDuabJQMHCAYAQair
         utrhG8koJ2WyFdC7+YhUH5kSl7C/odVTGGdxhGAbgZT8PLRKQRXU/ZF5PkT75r3kx6Gr
         rERcdFLkz/T4dERG3gFrabmlzHG1f28c3TDP8jdLG2DEW73ohB1zh3fIhrgjS752Pu3C
         DvW3IWzjspCXKP3FoOy+CfMFUyw3qdgjRSsMA9aJIWYYEmJha2y9plkUn8xrwkfWMtOl
         Wrjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Q83ZfKbqP27CtlWSI/P4bt10kAn85e9OysPWuznc16U=;
        b=ouQMvIDyy7TRhHRYeO751MvxhXanFZMetpITK/qCW3J6Yp+XrjAPpFKxAscNZPrqu5
         H34daXXjDRsqNb/NSzupZSh2KKr3Mq/Ha3A/7UGCNOp/BUy907gRaP2pp0Ayd5YLbusK
         MCPoX3jueoo87spoV6aj0rxnDodn+NprDVWksvFT+/405KYBC2hpPGBqtHo4XmpOMvUJ
         FoNu3/GjyHRnDyPOeUGbtiD4ogQ13vAUhCvCkAD8AixeSDXgWyeJqZ68GpJSR8mdC5U2
         rgpvll7AVqOBSb1jUJPD9nBTpPUV/hZWM/TEBsH+wggu7GYZeLMtl+mVmGqvmQwNwEg4
         K8+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q83ZfKbqP27CtlWSI/P4bt10kAn85e9OysPWuznc16U=;
        b=CnJh35lCMeBUIv7iNdo+bqqZAP4zta0pYPcYz+8F5wTKR+dIScJdMRczcgQ6LbSTvT
         soMkU5rL+W4are/Bzq4Nn5Zw5RLilvbqRJ+eF+7tDKgeCdw8q1rEj80oTxb2xoLbtqhD
         hk+jqh9Nnjy10vIBB2yjSpiF18u6phZ9iifhmmofq7w6/49Ga+QWkk3XR1fYCMnACzDu
         adrPD3Q+3tUcct2xv6cN7sh7V+nEVQAmCgJP1yniO6YWImBhp2y9ZfdlZyKTYk1/A60B
         C8K2lcLgcXw+zmo6tCphyettYV4AVHQiJegNuQQD88dlAezsaklmTQaMtHwqBJlzbnHG
         Ip/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q83ZfKbqP27CtlWSI/P4bt10kAn85e9OysPWuznc16U=;
        b=SVBA4nl3IBEPJ5AsALQPY/GK35zMmLl//WJOuimOAlOzvxMmvG0mTg9JJyEpHiQNwX
         3PMNEEGNBG8bbJmriqrkpyG8+pH6rOyqZ5kMc7pusDHfQX3VX8l7CpQImOrv7spEzZfM
         DfIOy9cdyzkfKY51DwgTmKbUAJuuuFMw7EDDaDemhBmC8NHrT07zumbopWI4v+2i32R1
         KFk8LKTM0BeBhXvirRzja+V05aG1qbumrL3suIr89IIDwwcC1VWUghAW2Sh6CyFIlcDn
         aRMbdnEwLdNVcawqJS9Q3affhvrL8vFLqp6l8j6bwOoTNVhgeX+NCPiE0xh4ykuoCmcz
         OTSQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWLWMKSvLF8Lzguy7pTfpLuLch22jE7pmpxLYIk+tOeBpEzpUA/
	T2ww4x3yrGSZ2XD6NYzTYMY=
X-Google-Smtp-Source: APXvYqyvVM8GH5CagUMH7q8nl/8/B8KWf31FWMLR6A/jE70+O8N2/EeUi4KW2uCpCT2j37Iy6fn3yA==
X-Received: by 2002:aca:bf0b:: with SMTP id p11mr1566363oif.142.1569997003337;
        Tue, 01 Oct 2019 23:16:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6d91:: with SMTP id x17ls241739otp.1.gmail; Tue, 01 Oct
 2019 23:16:42 -0700 (PDT)
X-Received: by 2002:a9d:7851:: with SMTP id c17mr1405147otm.55.1569997002883;
        Tue, 01 Oct 2019 23:16:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569997002; cv=none;
        d=google.com; s=arc-20160816;
        b=fZWGlYETzKWWR3QWkzgs/Ou3p1bA+oL+06K56G0Z2zi+Jez0mtfpVSPzC2a8aIrPFp
         GdJ0tZgnmXbvjK0XBhR0MdkmvoQSBh9TF+lIbFtf6T72uxZ4CmW/8FyaHYedCT/lC9dG
         jFjGsVemBAnkU6sI3h6OTqOYxTDbW+GgoDvPuX19BrL2Hh8v94waWbfglKmmtyR46VZF
         5eWGVEeyUu5+ImLeR375EeTmooPwh2EVHsZ0M/hVWjuyHTwbx0iQJh3lto2AmLUO07YT
         35v30aqUicO2KzDmolse3aUx1w2UazwpGnbiCIaWgxKQBZ1mSryeWEvjajHV2F01UVCP
         tOLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=+j4nfGwknDYDBcYzxvdghR4zZosYxux2mb5yWzP7zi4=;
        b=ktfIVC86xiLlnZIAWcnIbu3NEr10CN5xrw3IReEzjF49Kf5T5Ts3NpGi3rLJihulk3
         mpTiqqUw8K9ZopUptvv+KcypZgqNFpiHHbJxggtjNWR+Z4D2byti5qUkXZI3KSCQtTWB
         IsLNDyG+b6QJDzyt5yIpNYg6Ek8RUcX2rP9qoUyBshxBUdyT9SN+CLQnINGMCauoN0NH
         MYk8lR+jTy4Djn+8KtgPyhtzitT/lQ8VfXq0Z+knjcZDYxU9P9AEJRdJmY1YbgV+U79P
         Xv8n7wrZaMRfNMmzh/QKZAFDy/zFfoOp1aPNLYFPc1cq1SqnfqoUxPleARjqmUg+wmJH
         7PsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id c6si739060oto.5.2019.10.01.23.16.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Oct 2019 23:16:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x9260tqa065631;
	Wed, 2 Oct 2019 14:00:55 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from atcsqa06.andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Wed, 2 Oct 2019
 14:16:21 +0800
From: Nick Hu <nickhu@andestech.com>
To: <alankao@andestech.com>, <paul.walmsley@sifive.com>, <palmer@sifive.com>,
        <aou@eecs.berkeley.edu>, <aryabinin@virtuozzo.com>,
        <glider@google.com>, <dvyukov@google.com>, <alexios.zavras@intel.com>,
        <allison@lohutok.net>, <Anup.Patel@wdc.com>, <tglx@linutronix.de>,
        <gregkh@linuxfoundation.org>, <atish.patra@wdc.com>,
        <kstewart@linuxfoundation.org>, <linux-riscv@lists.infradead.org>,
        <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
        <linux-mm@kvack.org>
CC: Nick Hu <nickhu@andestech.com>
Subject: [PATCH v2 2/2] riscv: Add KASAN support
Date: Wed, 2 Oct 2019 14:16:05 +0800
Message-ID: <8d86d53e904bece0623cb8969cdc70f782fa2bae.1569995450.git.nickhu@andestech.com>
X-Mailer: git-send-email 2.17.0
In-Reply-To: <cover.1569995450.git.nickhu@andestech.com>
References: <cover.1569995450.git.nickhu@andestech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x9260tqa065631
X-Original-Sender: nickhu@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as
 permitted sender) smtp.mailfrom=nickhu@andestech.com
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

This patch ports the feature Kernel Address SANitizer (KASAN).

Note: The start address of shadow memory is at the beginning of kernel
space, which is 2^64 - (2^39 / 2) in SV39. The size of the kernel space is
2^38 bytes so the size of shadow memory should be 2^38 / 8. Thus, the
shadow memory would not overlap with the fixmap area.

There are currently two limitations in this port,

1. RV64 only: KASAN need large address space for extra shadow memory
region.

2. KASAN can't debug the modules since the modules are allocated in VMALLOC
area. We mapped the shadow memory, which corresponding to VMALLOC area, to
the kasan_early_shadow_page because we don't have enough physical space for
all the shadow memory corresponding to VMALLOC area.

Signed-off-by: Nick Hu <nickhu@andestech.com>
---
 arch/riscv/Kconfig                  |   1 +
 arch/riscv/include/asm/kasan.h      |  27 ++++++++
 arch/riscv/include/asm/pgtable-64.h |   5 ++
 arch/riscv/include/asm/string.h     |   9 +++
 arch/riscv/kernel/head.S            |   3 +
 arch/riscv/kernel/riscv_ksyms.c     |   2 +
 arch/riscv/kernel/setup.c           |   5 ++
 arch/riscv/kernel/vmlinux.lds.S     |   1 +
 arch/riscv/lib/memcpy.S             |   5 +-
 arch/riscv/lib/memset.S             |   5 +-
 arch/riscv/mm/Makefile              |   6 ++
 arch/riscv/mm/kasan_init.c          | 104 ++++++++++++++++++++++++++++
 12 files changed, 169 insertions(+), 4 deletions(-)
 create mode 100644 arch/riscv/include/asm/kasan.h
 create mode 100644 arch/riscv/mm/kasan_init.c

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 8eebbc8860bb..ca2fc8ba8550 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -61,6 +61,7 @@ config RISCV
 	select SPARSEMEM_STATIC if 32BIT
 	select ARCH_WANT_DEFAULT_TOPDOWN_MMAP_LAYOUT if MMU
 	select HAVE_ARCH_MMAP_RND_BITS
+	select HAVE_ARCH_KASAN if MMU && 64BIT
 
 config ARCH_MMAP_RND_BITS_MIN
 	default 18 if 64BIT
diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
new file mode 100644
index 000000000000..eb9b1a2f641c
--- /dev/null
+++ b/arch/riscv/include/asm/kasan.h
@@ -0,0 +1,27 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/* Copyright (C) 2019 Andes Technology Corporation */
+
+#ifndef __ASM_KASAN_H
+#define __ASM_KASAN_H
+
+#ifndef __ASSEMBLY__
+
+#ifdef CONFIG_KASAN
+
+#include <asm/pgtable.h>
+
+#define KASAN_SHADOW_SCALE_SHIFT	3
+
+#define KASAN_SHADOW_SIZE	(UL(1) << (38 - KASAN_SHADOW_SCALE_SHIFT))
+#define KASAN_SHADOW_START	0xffffffc000000000 // 2^64 - 2^38
+#define KASAN_SHADOW_END	(KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
+
+#define KASAN_SHADOW_OFFSET	(KASAN_SHADOW_END - (1ULL << \
+					(64 - KASAN_SHADOW_SCALE_SHIFT)))
+
+void kasan_init(void);
+asmlinkage void kasan_early_init(void);
+
+#endif
+#endif
+#endif /* __ASM_KASAN_H */
diff --git a/arch/riscv/include/asm/pgtable-64.h b/arch/riscv/include/asm/pgtable-64.h
index 7df8daa66cc8..777a1dddb3df 100644
--- a/arch/riscv/include/asm/pgtable-64.h
+++ b/arch/riscv/include/asm/pgtable-64.h
@@ -59,6 +59,11 @@ static inline unsigned long pud_page_vaddr(pud_t pud)
 	return (unsigned long)pfn_to_virt(pud_val(pud) >> _PAGE_PFN_SHIFT);
 }
 
+static inline struct page *pud_page(pud_t pud)
+{
+	return pfn_to_page(pud_val(pud) >> _PAGE_PFN_SHIFT);
+}
+
 #define pmd_index(addr) (((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
 
 static inline pmd_t *pmd_offset(pud_t *pud, unsigned long addr)
diff --git a/arch/riscv/include/asm/string.h b/arch/riscv/include/asm/string.h
index 1b5d44585962..a4451f768826 100644
--- a/arch/riscv/include/asm/string.h
+++ b/arch/riscv/include/asm/string.h
@@ -11,8 +11,17 @@
 
 #define __HAVE_ARCH_MEMSET
 extern asmlinkage void *memset(void *, int, size_t);
+extern asmlinkage void *__memset(void *, int, size_t);
 
 #define __HAVE_ARCH_MEMCPY
 extern asmlinkage void *memcpy(void *, const void *, size_t);
+extern asmlinkage void *__memcpy(void *, const void *, size_t);
 
+// For those files which don't want to check by kasan.
+#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
+
+#define memcpy(dst, src, len) __memcpy(dst, src, len)
+#define memset(s, c, n) __memset(s, c, n)
+
+#endif
 #endif /* _ASM_RISCV_STRING_H */
diff --git a/arch/riscv/kernel/head.S b/arch/riscv/kernel/head.S
index 72f89b7590dd..95eca23cd811 100644
--- a/arch/riscv/kernel/head.S
+++ b/arch/riscv/kernel/head.S
@@ -102,6 +102,9 @@ clear_bss_done:
 	sw zero, TASK_TI_CPU(tp)
 	la sp, init_thread_union + THREAD_SIZE
 
+#ifdef CONFIG_KASAN
+	call kasan_early_init
+#endif
 	/* Start the kernel */
 	call parse_dtb
 	tail start_kernel
diff --git a/arch/riscv/kernel/riscv_ksyms.c b/arch/riscv/kernel/riscv_ksyms.c
index 4800cf703186..376bba7f65ce 100644
--- a/arch/riscv/kernel/riscv_ksyms.c
+++ b/arch/riscv/kernel/riscv_ksyms.c
@@ -14,3 +14,5 @@ EXPORT_SYMBOL(__asm_copy_to_user);
 EXPORT_SYMBOL(__asm_copy_from_user);
 EXPORT_SYMBOL(memset);
 EXPORT_SYMBOL(memcpy);
+EXPORT_SYMBOL(__memset);
+EXPORT_SYMBOL(__memcpy);
diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
index a990a6cb184f..41f7eae9bc4d 100644
--- a/arch/riscv/kernel/setup.c
+++ b/arch/riscv/kernel/setup.c
@@ -23,6 +23,7 @@
 #include <asm/smp.h>
 #include <asm/tlbflush.h>
 #include <asm/thread_info.h>
+#include <asm/kasan.h>
 
 #ifdef CONFIG_DUMMY_CONSOLE
 struct screen_info screen_info = {
@@ -70,6 +71,10 @@ void __init setup_arch(char **cmdline_p)
 	swiotlb_init(1);
 #endif
 
+#ifdef CONFIG_KASAN
+	kasan_init();
+#endif
+
 #ifdef CONFIG_SMP
 	setup_smp();
 #endif
diff --git a/arch/riscv/kernel/vmlinux.lds.S b/arch/riscv/kernel/vmlinux.lds.S
index 23cd1a9e52a1..97009803ba9f 100644
--- a/arch/riscv/kernel/vmlinux.lds.S
+++ b/arch/riscv/kernel/vmlinux.lds.S
@@ -46,6 +46,7 @@ SECTIONS
 		KPROBES_TEXT
 		ENTRY_TEXT
 		IRQENTRY_TEXT
+		SOFTIRQENTRY_TEXT
 		*(.fixup)
 		_etext = .;
 	}
diff --git a/arch/riscv/lib/memcpy.S b/arch/riscv/lib/memcpy.S
index b4c477846e91..51ab716253fa 100644
--- a/arch/riscv/lib/memcpy.S
+++ b/arch/riscv/lib/memcpy.S
@@ -7,7 +7,8 @@
 #include <asm/asm.h>
 
 /* void *memcpy(void *, const void *, size_t) */
-ENTRY(memcpy)
+ENTRY(__memcpy)
+WEAK(memcpy)
 	move t6, a0  /* Preserve return value */
 
 	/* Defer to byte-oriented copy for small sizes */
@@ -104,4 +105,4 @@ ENTRY(memcpy)
 	bltu a1, a3, 5b
 6:
 	ret
-END(memcpy)
+END(__memcpy)
diff --git a/arch/riscv/lib/memset.S b/arch/riscv/lib/memset.S
index 5a7386b47175..34c5360c6705 100644
--- a/arch/riscv/lib/memset.S
+++ b/arch/riscv/lib/memset.S
@@ -8,7 +8,8 @@
 #include <asm/asm.h>
 
 /* void *memset(void *, int, size_t) */
-ENTRY(memset)
+ENTRY(__memset)
+WEAK(memset)
 	move t0, a0  /* Preserve return value */
 
 	/* Defer to byte-oriented fill for small sizes */
@@ -109,4 +110,4 @@ ENTRY(memset)
 	bltu t0, a3, 5b
 6:
 	ret
-END(memset)
+END(__memset)
diff --git a/arch/riscv/mm/Makefile b/arch/riscv/mm/Makefile
index 9d9a17335686..b8a8ca71f86e 100644
--- a/arch/riscv/mm/Makefile
+++ b/arch/riscv/mm/Makefile
@@ -17,3 +17,9 @@ ifeq ($(CONFIG_MMU),y)
 obj-$(CONFIG_SMP) += tlbflush.o
 endif
 obj-$(CONFIG_HUGETLB_PAGE) += hugetlbpage.o
+obj-$(CONFIG_KASAN)   += kasan_init.o
+
+ifdef CONFIG_KASAN
+KASAN_SANITIZE_kasan_init.o := n
+KASAN_SANITIZE_init.o := n
+endif
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
new file mode 100644
index 000000000000..c3152768cdbe
--- /dev/null
+++ b/arch/riscv/mm/kasan_init.c
@@ -0,0 +1,104 @@
+// SPDX-License-Identifier: GPL-2.0
+// Copyright (C) 2019 Andes Technology Corporation
+
+#include <linux/pfn.h>
+#include <linux/init_task.h>
+#include <linux/kasan.h>
+#include <linux/kernel.h>
+#include <linux/memblock.h>
+#include <asm/tlbflush.h>
+#include <asm/pgtable.h>
+#include <asm/fixmap.h>
+
+extern pgd_t early_pg_dir[PTRS_PER_PGD];
+asmlinkage void __init kasan_early_init(void)
+{
+	uintptr_t i;
+	pgd_t *pgd = early_pg_dir + pgd_index(KASAN_SHADOW_START);
+
+	for (i = 0; i < PTRS_PER_PTE; ++i)
+		set_pte(kasan_early_shadow_pte + i,
+			mk_pte(virt_to_page(kasan_early_shadow_page),
+			PAGE_KERNEL));
+
+	for (i = 0; i < PTRS_PER_PMD; ++i)
+		set_pmd(kasan_early_shadow_pmd + i,
+		 pfn_pmd(PFN_DOWN(__pa((uintptr_t)kasan_early_shadow_pte)),
+			__pgprot(_PAGE_TABLE)));
+
+	for (i = KASAN_SHADOW_START; i < KASAN_SHADOW_END;
+	     i += PGDIR_SIZE, ++pgd)
+		set_pgd(pgd,
+		 pfn_pgd(PFN_DOWN(__pa(((uintptr_t)kasan_early_shadow_pmd))),
+			__pgprot(_PAGE_TABLE)));
+
+	// init for swapper_pg_dir
+	pgd = pgd_offset_k(KASAN_SHADOW_START);
+
+	for (i = KASAN_SHADOW_START; i < KASAN_SHADOW_END;
+	     i += PGDIR_SIZE, ++pgd)
+		set_pgd(pgd,
+		 pfn_pgd(PFN_DOWN(__pa(((uintptr_t)kasan_early_shadow_pmd))),
+			__pgprot(_PAGE_TABLE)));
+
+	flush_tlb_all();
+}
+
+static void __init populate(void *start, void *end)
+{
+	unsigned long i;
+	unsigned long vaddr = (unsigned long)start & PAGE_MASK;
+	unsigned long vend = PAGE_ALIGN((unsigned long)end);
+	unsigned long n_pages = (vend - vaddr) / PAGE_SIZE;
+	unsigned long n_pmds =
+		(n_pages % PTRS_PER_PTE) ? n_pages / PTRS_PER_PTE + 1 :
+						n_pages / PTRS_PER_PTE;
+	pgd_t *pgd = pgd_offset_k(vaddr);
+	pmd_t *pmd = memblock_alloc(n_pmds * sizeof(pmd_t), PAGE_SIZE);
+	pte_t *pte = memblock_alloc(n_pages * sizeof(pte_t), PAGE_SIZE);
+
+	for (i = 0; i < n_pages; i++) {
+		phys_addr_t phys = memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
+
+		set_pte(pte + i, pfn_pte(PHYS_PFN(phys), PAGE_KERNEL));
+	}
+
+	for (i = 0; i < n_pages; ++pmd, i += PTRS_PER_PTE)
+		set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa((uintptr_t)(pte + i))),
+				__pgprot(_PAGE_TABLE)));
+
+	for (i = vaddr; i < vend; i += PGDIR_SIZE, ++pgd)
+		set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(((uintptr_t)pmd))),
+				__pgprot(_PAGE_TABLE)));
+
+	flush_tlb_all();
+	memset(start, 0, end - start);
+}
+
+void __init kasan_init(void)
+{
+	struct memblock_region *reg;
+	unsigned long i;
+
+	kasan_populate_early_shadow((void *)KASAN_SHADOW_START,
+			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
+
+	for_each_memblock(memory, reg) {
+		void *start = (void *)__va(reg->base);
+		void *end = (void *)__va(reg->base + reg->size);
+
+		if (start >= end)
+			break;
+
+		populate(kasan_mem_to_shadow(start),
+			 kasan_mem_to_shadow(end));
+	};
+
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		set_pte(&kasan_early_shadow_pte[i],
+			mk_pte(virt_to_page(kasan_early_shadow_page),
+			__pgprot(_PAGE_PRESENT | _PAGE_READ | _PAGE_ACCESSED)));
+
+	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+	init_task.kasan_depth = 0;
+}
-- 
2.17.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8d86d53e904bece0623cb8969cdc70f782fa2bae.1569995450.git.nickhu%40andestech.com.
