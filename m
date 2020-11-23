Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5VN6D6QKGQE4KPUVCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id D68052C1552
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:26 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id g72sf148658wme.6
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162166; cv=pass;
        d=google.com; s=arc-20160816;
        b=siMfkO+ebDGGWtEgmvC0M8Ez4Ci/Sq4SoB6G8auzkItmGqYS/C0R2RHFySx7m/0GaR
         uhMDHKqCnAksiwF3eVDZQR6IEztedQakVO6Oj5/52haxwjTYrGpp4BerNKgRZy58Ordk
         v0UdymYaSP+E3+ZSFppWGvblZxTSyF2PAXsfNB3DOFDqam320nx4s/WRuD5xsmRbwufA
         Jn4cPLSek/bZ3sTG6rCHnVfA2uOB882viqnicoQqmmOBiZs2r2Yu3zpprDa8TUGVqtZq
         hsSghZz0ntc7oj9qWGqTGQtiswqF9Xm5hLr5cSUr8S7cXpNgLKX4ac5FoNs/xbbtJab7
         Udow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=zWqyXIq2fYyGar61qq2JnB8ZB/1EJH2MuabgRT3mA6A=;
        b=OCsGMN1IuZnHGcayt87aUe5LA4tHnV6WvBnGAmYvHioDJBw1NL/3OxcxFtxEXimBUP
         nUqjtxceNIvtQD/F2nTMDjh39/SUHLsr5tS+NBYlvUtKnO/hsPE17UyqByoIZITN85tw
         bZ7K2tbF3/W4732a1o6eHGVmbGnkK2BYbv0HfVtUk02q4FRb33FwBL/bDFABYT2MedBD
         apYRwiCXkNDThEtyrLWgvG2pisKY/djgLZoEpsPVji5tmlBDhT8BpQEzKSVDP0wCFAq0
         tvAoxLr+6LCKeq7ONX1sEnpqeeIeXtnA3zMFesgGfwfSxAx3oKG6RJD6YpGxH/bty7/V
         +Bvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hROpr06A;
       spf=pass (google.com: domain of 39ra8xwokcrgyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=39Ra8XwoKCRgyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zWqyXIq2fYyGar61qq2JnB8ZB/1EJH2MuabgRT3mA6A=;
        b=tG5a1djiVZEJOdH1IE24IgeX32xfZwLda85GXU0UXTAjZbJQDf+/eCx7KfylQavjWY
         U/ucYFTo94Ib64T34ttVYD8B00IKO51veDZ3kVowXUSWVate9uundy9E0TNMg7LU0bcX
         qjWOftGNbTMWl0ooJY2gX5c8SjVFA2mOBjscLYBSuuugIgZ9hmvlUdkwmjxlnZ0gY8t1
         dj9HoR8Ihpz4ir4dL1Hv/oTppYMRwMRKSZIrqU7nRGNIB/VorlI5XrIoRDYnvKdJmKRZ
         swSQb9ya/c/aZ+edhfNa16KaQvK2O+1fe3qcFCFokLQraDPGO9Jr3u8jCvDXOhlDkn8P
         vmHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zWqyXIq2fYyGar61qq2JnB8ZB/1EJH2MuabgRT3mA6A=;
        b=EYViC9OiViTr8xmzPSC0GzObUZlsW/Q2Ypo+XIsFgL9buqp7/vb3hIr74jQf8HKdRj
         PimWChIM2Mf/zeBp6GC83wfcsJvY7/T0v3feV5d2sBgW1vnw6j+6QjkDu7DxnMNGlFgi
         kZVKS5jo2x+w/Tqoca7nxcEYQoyAgkFq4VhW6XOj53Yi+iOHNIBkt1ObgsJ/aFg4/JNs
         r8O0ER/UpRP57rc9assU7CohjVg/wQzvuyn/iFMxtTbziKg2CSiN1Nf5jHhTnpZjNV8W
         gY9P6ZvZB6mU62rNh4QO8RQ7Zcuw6PrqDUCC9Vt20xGLHTwJDeC2aSQJJWUqrXsXlxLp
         w56g==
X-Gm-Message-State: AOAM532V9WrhsiYQvBxWVamIajKDyLExqXF1/hctOvlh9uBwaI+CA0+z
	EmoErfm5giomNeyR/vVd46k=
X-Google-Smtp-Source: ABdhPJw51Z6kzH1d2qFUu00/2JKSfFGaTpX8VzIJ0lPF51Ez7hAPrkkNP4UnIkenNfWpU+5bHKri3w==
X-Received: by 2002:a1c:e442:: with SMTP id b63mr649862wmh.10.1606162166630;
        Mon, 23 Nov 2020 12:09:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:414c:: with SMTP id h12ls162584wmm.2.gmail; Mon, 23
 Nov 2020 12:09:25 -0800 (PST)
X-Received: by 2002:a1c:c6:: with SMTP id 189mr638194wma.36.1606162165887;
        Mon, 23 Nov 2020 12:09:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162165; cv=none;
        d=google.com; s=arc-20160816;
        b=PMU3fm0Tbvz24RMPeOh5C7VFGSLWFxOvnzGppgMAKnXu+cImbFH2o0N5NGGfmp/wmi
         gWUs/JemDG1F9xEBaD8X99gXn2IcaxqwJOeDDIjWKSTJVAbhae81NSd1PTvLwDgd2DPl
         vFaSD0mx+8asMUBulvdRlqoEYCwypyzxMse8hg7SW0wXr2UYs3rwvJDTexKfyLMU/6qq
         EamGcMeQmCFYrEZs56WVQtqw1rC4R8eRug9H8i95568jYrfQLkuxxRtwNiENRCiXegg+
         PhnlESGpW0f0BUPKW32SshtxMi8o48TElPmEinfwQ7jwLJrSFxJysWFlaXiCjk3Puylz
         0wig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=8e63GTlhB9QbGsFBUU3MJ45Yhzqtwy6A04ZDFy/2ryA=;
        b=vax1rdhf75GOl7bQYuRjpaId9reIbK7v3To/fbLs9OizKkqxy6E2YfIxMygxykZNYD
         piuJedFli1ezHJtpciGydImSLZ87xMiF9ugjS0XkgQn6LuNhcjTqOlH/YmIvU8wa8o/5
         RUvHFxy38ox0OPXkxQ5a3utpVC6PXRSbRFO/d1V2/AmRPmtUXVaDIMeGB9VnlU7r/o2R
         xGeyg013X7hJnHu6yK/Cx9+53hYfCRwNKi2oiPkHkqIpVb3nRxNdSziCglExPpt/nMxd
         bpYVWj9f0oqawGFLPozB2LJVBlsaETYXIW8khz2+lCFJYaeXmyPlq8M9ZwiM9tKRDMMi
         6VNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hROpr06A;
       spf=pass (google.com: domain of 39ra8xwokcrgyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=39Ra8XwoKCRgyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id w65si9904wmg.1.2020.11.23.12.09.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 39ra8xwokcrgyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id o19so156535wme.2
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:25 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:618c:: with SMTP id
 j12mr1465350wru.182.1606162165477; Mon, 23 Nov 2020 12:09:25 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:49 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <c31bf759b4411b2d98cdd801eb928e241584fd1f.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 25/42] arm64: mte: Add in-kernel MTE helpers
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hROpr06A;       spf=pass
 (google.com: domain of 39ra8xwokcrgyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=39Ra8XwoKCRgyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

Provide helper functions to manipulate allocation and pointer tags for
kernel addresses.

Low-level helper functions (mte_assign_*, written in assembly) operate
tag values from the [0x0, 0xF] range. High-level helper functions
(mte_get/set_*) use the [0xF0, 0xFF] range to preserve compatibility
with normal kernel pointers that have 0xFF in their top byte.

MTE_GRANULE_SIZE and related definitions are moved to mte-def.h header
that doesn't have any dependencies and is safe to include into any
low-level header.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I1b5230254f90dc21a913447cb17f07fea7944ece
---
 arch/arm64/include/asm/esr.h       |  1 +
 arch/arm64/include/asm/mte-def.h   | 15 ++++++++
 arch/arm64/include/asm/mte-kasan.h | 56 ++++++++++++++++++++++++++++++
 arch/arm64/include/asm/mte.h       | 20 +++++++----
 arch/arm64/kernel/mte.c            | 48 +++++++++++++++++++++++++
 arch/arm64/lib/mte.S               | 16 +++++++++
 6 files changed, 150 insertions(+), 6 deletions(-)
 create mode 100644 arch/arm64/include/asm/mte-def.h
 create mode 100644 arch/arm64/include/asm/mte-kasan.h

diff --git a/arch/arm64/include/asm/esr.h b/arch/arm64/include/asm/esr.h
index 22c81f1edda2..971c20ddfed4 100644
--- a/arch/arm64/include/asm/esr.h
+++ b/arch/arm64/include/asm/esr.h
@@ -105,6 +105,7 @@
 #define ESR_ELx_FSC		(0x3F)
 #define ESR_ELx_FSC_TYPE	(0x3C)
 #define ESR_ELx_FSC_EXTABT	(0x10)
+#define ESR_ELx_FSC_MTE		(0x11)
 #define ESR_ELx_FSC_SERROR	(0x11)
 #define ESR_ELx_FSC_ACCESS	(0x08)
 #define ESR_ELx_FSC_FAULT	(0x04)
diff --git a/arch/arm64/include/asm/mte-def.h b/arch/arm64/include/asm/mte-def.h
new file mode 100644
index 000000000000..8401ac5840c7
--- /dev/null
+++ b/arch/arm64/include/asm/mte-def.h
@@ -0,0 +1,15 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Copyright (C) 2020 ARM Ltd.
+ */
+#ifndef __ASM_MTE_DEF_H
+#define __ASM_MTE_DEF_H
+
+#define MTE_GRANULE_SIZE	UL(16)
+#define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
+#define MTE_TAG_SHIFT		56
+#define MTE_TAG_SIZE		4
+#define MTE_TAG_MASK		GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
+#define MTE_TAG_MAX		(MTE_TAG_MASK >> MTE_TAG_SHIFT)
+
+#endif /* __ASM_MTE_DEF_H  */
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
new file mode 100644
index 000000000000..3a70fb1807fd
--- /dev/null
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -0,0 +1,56 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Copyright (C) 2020 ARM Ltd.
+ */
+#ifndef __ASM_MTE_KASAN_H
+#define __ASM_MTE_KASAN_H
+
+#include <asm/mte-def.h>
+
+#ifndef __ASSEMBLY__
+
+#include <linux/types.h>
+
+/*
+ * The functions below are meant to be used only for the
+ * KASAN_HW_TAGS interface defined in asm/memory.h.
+ */
+#ifdef CONFIG_ARM64_MTE
+
+static inline u8 mte_get_ptr_tag(void *ptr)
+{
+	/* Note: The format of KASAN tags is 0xF<x> */
+	u8 tag = 0xF0 | (u8)(((u64)(ptr)) >> MTE_TAG_SHIFT);
+
+	return tag;
+}
+
+u8 mte_get_mem_tag(void *addr);
+u8 mte_get_random_tag(void);
+void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
+
+#else /* CONFIG_ARM64_MTE */
+
+static inline u8 mte_get_ptr_tag(void *ptr)
+{
+	return 0xFF;
+}
+
+static inline u8 mte_get_mem_tag(void *addr)
+{
+	return 0xFF;
+}
+static inline u8 mte_get_random_tag(void)
+{
+	return 0xFF;
+}
+static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
+{
+	return addr;
+}
+
+#endif /* CONFIG_ARM64_MTE */
+
+#endif /* __ASSEMBLY__ */
+
+#endif /* __ASM_MTE_KASAN_H  */
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 1c99fcadb58c..cf1cd181dcb2 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -5,14 +5,16 @@
 #ifndef __ASM_MTE_H
 #define __ASM_MTE_H
 
-#define MTE_GRANULE_SIZE	UL(16)
-#define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
-#define MTE_TAG_SHIFT		56
-#define MTE_TAG_SIZE		4
+#include <asm/compiler.h>
+#include <asm/mte-def.h>
+
+#define __MTE_PREAMBLE		ARM64_ASM_PREAMBLE ".arch_extension memtag\n"
 
 #ifndef __ASSEMBLY__
 
+#include <linux/bitfield.h>
 #include <linux/page-flags.h>
+#include <linux/types.h>
 
 #include <asm/pgtable-types.h>
 
@@ -45,7 +47,9 @@ long get_mte_ctrl(struct task_struct *task);
 int mte_ptrace_copy_tags(struct task_struct *child, long request,
 			 unsigned long addr, unsigned long data);
 
-#else
+void mte_assign_mem_tag_range(void *addr, size_t size);
+
+#else /* CONFIG_ARM64_MTE */
 
 /* unused if !CONFIG_ARM64_MTE, silence the compiler */
 #define PG_mte_tagged	0
@@ -80,7 +84,11 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
 	return -EIO;
 }
 
-#endif
+static inline void mte_assign_mem_tag_range(void *addr, size_t size)
+{
+}
+
+#endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
 #endif /* __ASM_MTE_H  */
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 52a0638ed967..8f99c65837fd 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -13,10 +13,13 @@
 #include <linux/swap.h>
 #include <linux/swapops.h>
 #include <linux/thread_info.h>
+#include <linux/types.h>
 #include <linux/uio.h>
 
+#include <asm/barrier.h>
 #include <asm/cpufeature.h>
 #include <asm/mte.h>
+#include <asm/mte-kasan.h>
 #include <asm/ptrace.h>
 #include <asm/sysreg.h>
 
@@ -72,6 +75,51 @@ int memcmp_pages(struct page *page1, struct page *page2)
 	return ret;
 }
 
+u8 mte_get_mem_tag(void *addr)
+{
+	if (!system_supports_mte())
+		return 0xFF;
+
+	asm(__MTE_PREAMBLE "ldg %0, [%0]"
+	    : "+r" (addr));
+
+	return mte_get_ptr_tag(addr);
+}
+
+u8 mte_get_random_tag(void)
+{
+	void *addr;
+
+	if (!system_supports_mte())
+		return 0xFF;
+
+	asm(__MTE_PREAMBLE "irg %0, %0"
+	    : "+r" (addr));
+
+	return mte_get_ptr_tag(addr);
+}
+
+void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
+{
+	void *ptr = addr;
+
+	if ((!system_supports_mte()) || (size == 0))
+		return addr;
+
+	/* Make sure that size is MTE granule aligned. */
+	WARN_ON(size & (MTE_GRANULE_SIZE - 1));
+
+	/* Make sure that the address is MTE granule aligned. */
+	WARN_ON((u64)addr & (MTE_GRANULE_SIZE - 1));
+
+	tag = 0xF0 | tag;
+	ptr = (void *)__tag_set(ptr, tag);
+
+	mte_assign_mem_tag_range(ptr, size);
+
+	return ptr;
+}
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
index cceed41bba15..e63890292bc1 100644
--- a/arch/arm64/lib/mte.S
+++ b/arch/arm64/lib/mte.S
@@ -149,3 +149,19 @@ SYM_FUNC_START(mte_restore_page_tags)
 
 	ret
 SYM_FUNC_END(mte_restore_page_tags)
+
+/*
+ * Assign allocation tags for a region of memory based on the pointer tag
+ *   x0 - source pointer
+ *   x1 - size
+ *
+ * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
+ * size must be non-zero and MTE_GRANULE_SIZE aligned.
+ */
+SYM_FUNC_START(mte_assign_mem_tag_range)
+1:	stg	x0, [x0]
+	add	x0, x0, #MTE_GRANULE_SIZE
+	subs	x1, x1, #MTE_GRANULE_SIZE
+	b.gt	1b
+	ret
+SYM_FUNC_END(mte_assign_mem_tag_range)
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c31bf759b4411b2d98cdd801eb928e241584fd1f.1606161801.git.andreyknvl%40google.com.
