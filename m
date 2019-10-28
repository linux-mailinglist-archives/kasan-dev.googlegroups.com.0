Return-Path: <kasan-dev+bncBAABBA5L3HWQKGQEGUM3CGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 32C42E6AE2
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 03:42:13 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d13sf1584756qtn.10
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Oct 2019 19:42:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572230532; cv=pass;
        d=google.com; s=arc-20160816;
        b=T3TCh9+1P+51dkGC6Suk0jY+3I/792hoOBqFSfTLL95rEYAymIhyAemrW6DTjHIvrV
         6umFNyUHmSp0R23g2rEJhqAqIOcqXY+ExJK6fFu8YZryXzAabF9eUQYDfX0Y3pnvvurb
         3NGejtdsknxuzoxivVo/RSncBQYXH79700/xFUrKNXok9ENbV2eNt62lEQwjTWhnf4Sm
         UEeWXZ1Tdu3kPx2P9m6o3CnTX5z+SF2dp1QthZ7ldXUGogWDQf8YcrmtVOOQFZA1tqPn
         XPnwwAOhlX0QfOZSBrRFOmDonSXEbcx17slmVhdpKi2n6ohnlzBRfjAr8qq0tMpMzXDs
         vCPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zGf7OmopIvh5IQfMsygPLRNJQ1xk9H9wc/mojEwuoLQ=;
        b=WrUvs83R5MZ9IqDv4ddbrWpnfGBB963ZjIIwmeCox+qeH7dDCKGjefL1XtP8lqO5Ik
         gCl/Mn8IH7EbGXbEguC/b33kkTMHfFRnjj2ru4nxFDWHwiAGlfLWleEoO0p3KZcxrqgq
         JbUsqWZCXXKdY/BaOmu81IPAbqoJlMaTr98dOphXoNWujF4z3XO7Jw+pdZt7JA08sy68
         X0CO26FeVqkxllod2Zd8lKysnCwIMdG1WbtxofhtTcBHszaLLwTPmaMR/PxfPnsHXJom
         uURaI01tRhJa1E7xIvcXD6J8D01+qLYLgfx+N3KJ0kH85tS7SqKzMMRxYKij5qh7Pli+
         Rjxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zGf7OmopIvh5IQfMsygPLRNJQ1xk9H9wc/mojEwuoLQ=;
        b=BtwUrZVj9YZc0zXaXer4wEdUGjuk0r66kGKeD3bxi3U49K3+l6UiteCY2CFJ6PfqzD
         oOwlp6hJ+5CA31rcsd+E1QSaH9pJS56T0S3BUIE3a6QOVxX5jScOZ0TCPXTVyhWlupZj
         C9M6Iz53LkxmRDdDano5Bj4r3t+pjQW4eCx6Yyo8mkAM5C8rRgdmoaZEdsTrtuUMNIso
         WYESOP7qpavqgmxFLucyY5un8+jKbZecn93oAwod29Ohvt0AzEWU3ygy6kEUdxTs2yeS
         86Ev7i9ZVtUyoVqx+0+qek5p/IHg9gYOqcf6rV8IdvyOrzyFenNso9Zv2912cbkqLbgj
         FtCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zGf7OmopIvh5IQfMsygPLRNJQ1xk9H9wc/mojEwuoLQ=;
        b=ATk4ywly0SjAhzfbJNOeTgwFtxmuCx2uelcLa6XNf6vEO172DYduYd6HnkMp79Ar3z
         zAhVILpS0xmxAwOWZ40paM88wInsyYTi9aODTTvbuY3MkTDmrsfBSmq744AoRaZqkPr8
         JP1Vej9UcsfztKq7hkxvc3jHYSg1gWCK3I/+OiJQb7eJ90xBSo6hzagpP+VMCAH16bQC
         Shc6iLJ3Siv7WgXzHajDrphOyQCR6UNnDlmjEgi/Q6WfMUziqJZv+8aDRgX2XUzPYmKf
         9UjJAeVIvN61exvtZcFyyk/gKWiGEcLBrqF/a0y4CdzKyavbzoEIQOcXTrm//BNJ+Etq
         jsbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUL6TWRbR/rvrTxN8QPLkbBdg/+UwsHi9XoE0+1+AuGV5V2a/LB
	JxxJAkdD3XbAS0OHhgo2r/I=
X-Google-Smtp-Source: APXvYqzcNyByTkbdEcnSV/x6OXucuP4DdIGWdxZmN0u9veDgdXBGvT7vrgpqvpfZ3M/tsNAcYsLykQ==
X-Received: by 2002:a05:620a:142a:: with SMTP id k10mr8873747qkj.268.1572230531809;
        Sun, 27 Oct 2019 19:42:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4454:: with SMTP id r81ls4127503qka.5.gmail; Sun, 27 Oct
 2019 19:42:11 -0700 (PDT)
X-Received: by 2002:a37:84a:: with SMTP id 71mr3917592qki.423.1572230531268;
        Sun, 27 Oct 2019 19:42:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572230531; cv=none;
        d=google.com; s=arc-20160816;
        b=btDOnbby2wjKV9C2N9hHBB0/yDLMFJ3/VLZL+1eLYXH3TIK07UvV0ADofQX4uHLMSR
         k4dtzog2U1cGVpG8tCPa4EBb8wxlVFx7EvcAJAnJfQvy1dvy0+UH5pXOCxDTknU++t3j
         EedkbrX1Rtw95Gmyamg1ieh2QjelmQwQJWVNT0mi6/Z58TICF1AzwhHtb5i/4khvdVTz
         lXd0z2QwIJmdUv56J1EBQzy8Muvc8C7g4JCBYPmcZuo9FuTGC9PcqkX/jLNNFNud400t
         nwz3Skj592B1pH0mqleg36N4gCT2CqI7uLqaQofICDm85RNGFVaBPmC8TtLy8Qm4y2jR
         hu5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=4PeSSlmP9xN0JRXGwnRyDBjIe3jz/G+fNhht3E/SGQo=;
        b=T4Lu4aMYjoRFPq0TKTjodMEayoi6/ZdcZTyC7jRvZuShi3cG3pzcwpCFMlAXXG2NdE
         Pv/5EPUqqlBjCB2TD6I3ncU20HmB4s1nSNwi2t7WagNL3Ui7ttht4ayV+hYQaSlPw9o7
         6F0dNnitUfFTM2oFzNOKgL+obWebcnvbAPG04CgZ6zKrHSCSOePf79R+KuAopEJxeXG0
         shwDcg2Rm+7TeZ5ogqWkt7GXdhtt8VsepYqHQ8deCV6BIgvQfqyZ4QFyh8cWk73apZYS
         niIGFxFAPtNOla7lmcHNASJoiplYou5L1wyazM5BiLfTcs4OZR7D6LG8Hl/0UXXgH9hf
         wjcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id t187si480689qkd.0.2019.10.27.19.42.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Oct 2019 19:42:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x9S2OOBs087256;
	Mon, 28 Oct 2019 10:24:24 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from atcsqa06.andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Mon, 28 Oct 2019
 10:41:53 +0800
From: Nick Hu <nickhu@andestech.com>
To: <aryabinin@virtuozzo.com>, <glider@google.com>, <dvyukov@google.com>,
        <corbet@lwn.net>, <paul.walmsley@sifive.com>, <palmer@sifive.com>,
        <aou@eecs.berkeley.edu>, <tglx@linutronix.de>,
        <gregkh@linuxfoundation.org>, <alankao@andestech.com>,
        <Anup.Patel@wdc.com>, <atish.patra@wdc.com>,
        <kasan-dev@googlegroups.com>, <linux-doc@vger.kernel.org>,
        <linux-kernel@vger.kernel.org>, <linux-riscv@lists.infradead.org>,
        <linux-mm@kvack.org>, <green.hu@gmail.com>
CC: Nick Hu <nickhu@andestech.com>
Subject: [PATCH v4 2/3] riscv: Add KASAN support
Date: Mon, 28 Oct 2019 10:41:00 +0800
Message-ID: <20191028024101.26655-3-nickhu@andestech.com>
X-Mailer: git-send-email 2.17.0
In-Reply-To: <20191028024101.26655-1-nickhu@andestech.com>
References: <20191028024101.26655-1-nickhu@andestech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x9S2OOBs087256
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
Reported-by: Greentime Hu <green.hu@gmail.com>
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
index 000000000000..eee6e6588b12
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
+#define KASAN_SHADOW_START	0xffffffc000000000 /* 2^64 - 2^38 */
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
index 1b5d44585962..924af13f8555 100644
--- a/arch/riscv/include/asm/string.h
+++ b/arch/riscv/include/asm/string.h
@@ -11,8 +11,17 @@
 
 #define __HAVE_ARCH_MEMSET
 extern asmlinkage void *memset(void *, int, size_t);
+extern asmlinkage void *__memset(void *, int, size_t);
 
 #define __HAVE_ARCH_MEMCPY
 extern asmlinkage void *memcpy(void *, const void *, size_t);
+extern asmlinkage void *__memcpy(void *, const void *, size_t);
 
+/* For those files which don't want to check by kasan. */
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
index 000000000000..f0cc86040587
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
+	/* init for swapper_pg_dir */
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
+	for (i = 0; i < n_pmds; ++pgd, i += PTRS_PER_PMD)
+		set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(((uintptr_t)(pmd + i)))),
+				__pgprot(_PAGE_TABLE)));
+
+	for (i = 0; i < n_pages; ++pmd, i += PTRS_PER_PTE)
+		set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa((uintptr_t)(pte + i))),
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191028024101.26655-3-nickhu%40andestech.com.
