Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVNO5T6AKGQEPRTZ6FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id B39F429F4DD
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:13 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id e3sf1678995wrn.19
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999573; cv=pass;
        d=google.com; s=arc-20160816;
        b=YabKBUnQKQhrjhacE4ZCTGnL0uqzbjaE6HZtO22qyblD9hhzDhAOoa8w301BcFAcue
         ZzLR0WQLSsy7zcquKT+yRAf4M3KPTAEKdOyHXe7GN/852GMmicyNz/m9n/yYOPeJjq17
         UmyLad8MeOJIrg4G9nBfRARta3kR6v1YXSr0WlTnOxRHB5qTJZ1zElakjs+Utfet75C/
         q5TG/5Eys3Y5pDg4tjvJnZKGsgKD+54naPvbfTv1s3mCi6vLya06lW+1d2S6cdqnuGUE
         LrxMO+EXil5v6014+8vI7mNtp1NqWBhP2A/IZjRKYAGp1uIWC7syjCsA2N/r1O4yxCTm
         qlrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=T5cgZbdJzAw4L+mJXvFsNChudAh4hhMj8+aNZSW8/qw=;
        b=nV0Iqj+fcBhcODUNMbw2S5gntRwHkMFJ5L96nGBDBT9EMJdR7vtdD3/j9e76WnezqY
         9EVL1a9l4+u8IgO+ce+dY2k3fGgjOFO2Ik2SYeMEsvV/nSbkqF9dHY0P2d2YPqTR+7Yt
         YuZRuZ7SU58zEeVNhfvY050GQcokMseWSD/sgGN3up67ww3vY1LGdK+6JSfb8UfnNvRX
         tXmlkPC5EHEZFEow/WFMTY6VxkSqzjlPK0KQ7VbScT4/WPNzDXo9hTypdN7e7I3vI+Dl
         2c6AMRy6ipZK+7zkhh9/D7NIiJtzz+IQBDkUjimHh6yS2QfQodtHak+XIExHNuDZZCRc
         Ss/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TbXAhZtX;
       spf=pass (google.com: domain of 3uxebxwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3UxebXwoKCfASfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=T5cgZbdJzAw4L+mJXvFsNChudAh4hhMj8+aNZSW8/qw=;
        b=mChdaq7abYPCufubFNpRo8D3A0rrEonQLMcC+Zx9XawOnY71rVplilX0fw/hgn4ipq
         bFXjo7pZm1U4h/5Yn+J0qNlIMxo+wGBb4Xk/XlCzFqtJR+cDOwdq+i41syV/CKGr7CYH
         umDv6SlcI5GsUOBIL+GPclIJ024+Wu46k2+TUizyI6wq9bjLMs8EXMkbBM9/hOepkvRA
         cBFhYLXSMKCGlu+4yxAlRJaOhcD5JeYQF5hT5CDKWEGgq75lWAwBqUWsx8KtcdijmK0n
         sWtknl1+uCrHaf0siQAyhRI+qV1Mfm1k2GhoZx8NKBgh7IMZ87sMyovfhUDKYp3dd3Xo
         Hb4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T5cgZbdJzAw4L+mJXvFsNChudAh4hhMj8+aNZSW8/qw=;
        b=K2iWM66FaZ1qCZf2Ccs15OyyUhts9B6oUpeR+y6Z4UOXf3bsMsL+mzY2PPA+XobQiJ
         vyxyZ8DMT39SFdndB1aMen8uCtCdHiDe6m5Pqv1Es/HJZU1dZdislrkwoHP9chHFWxN5
         jJY2Js/CDCraTBEEfqX8guINsh7aGpXDVcuEghWab3f3FW/pX7sPIHg94Y4SqjVi2FC0
         lfzg1t/wVG6Y6Gb4EF0bMWeqo684Qq6BIPsyw18/SB+5Bukr6udVXBPV3SZNMam2rm72
         jVWVPH6HobILzMc/ojJlyddKfgb0bPxxLe4A1LSAzuBMqP92Sx3fESK50HXrKe9aziEr
         zyKw==
X-Gm-Message-State: AOAM530JeGzVc00tIEnBmG+oRbILpigdbgeDEjPvyH/0JEJh4A4wz6Bl
	ojLJUC6OLcg7+5QMC1ZFzGc=
X-Google-Smtp-Source: ABdhPJzzcEHftf2yeQBg0effMJ6XfuB84xJkSNFQq8ntwKoVmYhOhUUo2qkA9Xr3fLiBwBdZL8re1A==
X-Received: by 2002:a1c:7707:: with SMTP id t7mr485610wmi.54.1603999573415;
        Thu, 29 Oct 2020 12:26:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cf0f:: with SMTP id l15ls96974wmg.0.experimental-gmail;
 Thu, 29 Oct 2020 12:26:12 -0700 (PDT)
X-Received: by 2002:a1c:bdc4:: with SMTP id n187mr404200wmf.185.1603999572265;
        Thu, 29 Oct 2020 12:26:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999572; cv=none;
        d=google.com; s=arc-20160816;
        b=txbXK1jHOdBNREpagzM962ey2GCjIS9kp2l2V4dtUn/QCluWdLun1g2tXE3fnPkrYW
         XLLsF714kYTVlMwuQokk5kLO29tWzovOz0kd4YRdiawnM+7ysViRGY3rxVK59LGHhwHH
         S46xZYojmEl9/0sA+5NnBQfUF1NNrsEknTRC0W5f0CDGfDQ32AKskdwDhhef7QzDhZM8
         TPe4ZxMwGaXUwQnM1LZx+GLxajFsv18Xpvn/ayCSFNqC2Biy72wM/yKUCFuf3wgA5kUG
         4WucE/CSgZ5nWJ2b46wjxIu9+GSKvMALwVu1FvUr9yrB/+aCZVXEUpan8VwBjAXVYs/H
         ByzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=iKiZmQLw/RkryeoFhlFWSKbY6lm99BwbnzE2uZJZe40=;
        b=LFdDcEV2cw0Pf1t9QHSVc8JQpm6R4hk4uroWttNWITxbRkZgQfLED6omnpJvy2Hho0
         wRmTHea2nHrnN38JoFXMe1eEih43B69kgGLr4xj0eeDHr0r133wqTnOY/jsTlBnn5cUd
         Kiizl0zgKjkHQYIRbkn5bC/2DVHdyqMwnJz7yFo9RgSGgmrtWoONVXv5YIZb3wKmQzdP
         Bn/WItyde7oqSylAhMuW8pEJuMulreQ2Yb+Rf8A7gGHFDfQiRyvXpBl01XSdziCS65Tr
         JRRg6DPvzt+JSaAfq+g+7g3a4JYy8LQR8xFMQIKhk2ETOWZ3FWKaeV/2boSbEI+CN+Vs
         MZHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TbXAhZtX;
       spf=pass (google.com: domain of 3uxebxwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3UxebXwoKCfASfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id n19si84092wmk.1.2020.10.29.12.26.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uxebxwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id s12so973251wmj.0
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:12 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c309:: with SMTP id
 k9mr381643wmj.125.1603999571854; Thu, 29 Oct 2020 12:26:11 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:23 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <22f5b596f86d0dd7a9ae8963f07cd21d7b6041c4.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 02/40] arm64: mte: Add in-kernel MTE helpers
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TbXAhZtX;       spf=pass
 (google.com: domain of 3uxebxwokcfasfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3UxebXwoKCfASfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
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
index 03ca6d8b8670..ede1ea65428c 100644
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/22f5b596f86d0dd7a9ae8963f07cd21d7b6041c4.1603999489.git.andreyknvl%40google.com.
