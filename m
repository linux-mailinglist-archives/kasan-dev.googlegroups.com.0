Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3ELXT6QKGQECAPMFGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B5602B281B
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:17 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id i3sf4871441lja.15
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305837; cv=pass;
        d=google.com; s=arc-20160816;
        b=O6tJGoTMjrs89tza2tEnxCWdJj4DA510muQqNoUdaCgv7TFmOjQoYMfAguLRn4NSH6
         vOL4o5OVzOXGW5HzcEROYQzpXQS6wuVz3sT/DO4MeGPAwNzeISnOWPuiXUt0qRBtBuzM
         Nq2C8FY1HJweWFwbtmv8c8/JKDkN7dste1b/Z4Nlbj7Pv2Zp404mhwvhHeH51YWlKBGW
         YTVSB1fgDu7QS14Y+wsFDfEeJ1s7IzkpL3Dn5psqhD9INWC8qQME/XZA6wkKnahY+DL0
         lauX71K4TQpQzyYwhRHhGQx7E8HI722pBRj7eippKqLuprlGPG69xiXacPH0Kwrt64PD
         verA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=iboPx2pW4KmUU85fWPpS3wecmEI/JB/N2nE4YBtT3sI=;
        b=rKKE/OXlphAZubTk5nddzPl6GSMYY9eEo7dAjZISWH/y/kJ9G8qezUbtNURVfB07w5
         9dEaOS6MKIah/IFrHkVb2KtfZoYEQv/FEesQRkQUCFI/Ng6Re9iuiWZAR7eZa37vN+EF
         EtmoV3uVk6ASZVAU/OgXbahQmD/G0x8H1zRS80a2H3jK4RE91CkAiJzy9rg+5whx+RJi
         TIesild+Ayc/m3+z4Dlu1stU4OO+sFE/R7l3Nrew1ZgaDREVgebp9CAKLN1Kbs3r5Koa
         2E+r1CbdEGYwb6JmitSRnj8UqopXLqxvX+MdAmVKcUoEy+Hx+h+Vf/n3aoqCOjM7l3/D
         OIsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i6B5Haa+;
       spf=pass (google.com: domain of 36wwvxwokcbywjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=36wWvXwoKCbYWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=iboPx2pW4KmUU85fWPpS3wecmEI/JB/N2nE4YBtT3sI=;
        b=e0hncq5Ic2S/XfPtkgNWR/JCmQEqioP6EHslc49woldFEzev18q5qh60fCEMXqmwpm
         O38Ka9U5OhPvPNqv1i+TGGU+0BAWiTUN7tf+e6vzClvjCAY2gSJnXUhaqUOfopbD633f
         d5qy0f3Z6NSkbdQNfmHz01hLq5cV1TSrN+fpaAkYw+KaEua3Bulh0j27I6tAOFjHuQtL
         ixX8j+4Tc2OBkWgIMhqnBMFNJUhgwwaUbNQKFvd5sYOKwJpIPIfTjy/+4tRaqMhyj8Q0
         8mAONCrU22IBMPk5CGFs7PfjkO+IhcYCJmS582haqEwFrmn5nGbtlmL8D3y3ESIyYKT+
         3Ctw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iboPx2pW4KmUU85fWPpS3wecmEI/JB/N2nE4YBtT3sI=;
        b=rcYcgBvsIiptMbd//y8HJBsAQYWB87YK1TWjCEpT+4D3Kl+TixZ15w7S1VVpBxWrs3
         3JnzgeANWLzuafiwnLpxWJilZ0iaARxdym34b/N0QBH11ydr+hM1TcZ6Nl+hEuH2744J
         B3GlT9rvbUt+3MBtOPoQMYv/nrKWG6jQS5fjMLdJ8JIk3Fyc1IiJKKRmdCpZ/XUWem8d
         KQwcR0Ov7M4L+tQQTY1ieblQ61DpP1HK4blyDeLoRZuOJRngKCvYfjOghjc/M6RzLgZx
         frvNj+2ETpU6UifsxE4EktJCbR6m7d5bvShXl/L9pXWUf9KQKif7wRMzL3GJ7cdRfAPA
         aLQA==
X-Gm-Message-State: AOAM530ibVwGBP8RBNGxbVeZ09zb0AQnu1sdW3w0q2b3xKooqvVNZmjK
	tPlhzqIdsEqd0aeInXpW4r8=
X-Google-Smtp-Source: ABdhPJzecZG89vrHxhSRbFOmUvB/64oipOCTNe3Uus4H665lt1RuPM+PRYuP12oO0V9rNiMMbX3JsQ==
X-Received: by 2002:a19:e20c:: with SMTP id z12mr1802006lfg.450.1605305837113;
        Fri, 13 Nov 2020 14:17:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:480e:: with SMTP id v14ls4569223lfa.2.gmail; Fri, 13 Nov
 2020 14:17:16 -0800 (PST)
X-Received: by 2002:ac2:51a9:: with SMTP id f9mr57051lfk.429.1605305836219;
        Fri, 13 Nov 2020 14:17:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305836; cv=none;
        d=google.com; s=arc-20160816;
        b=z2cTiTj1QkJ4/eJTiPP66OkagzMItbKV2gLfH8Z/fKnLxdAsTnc311KeldSvNJ+e5T
         O0dGi8TfXfHuCrsv3zM56JnbGgVZNk1wQJpYAJALuZMaci3HTUDNbsBlat77020FNAY/
         Lh7tP74klrY4WydqnqbpP8HPPEtMEjRZgbDrytgpR+lICKIfoSsNnVw+jSLZ8EqaNCkE
         LUw6uvonMsJK5aTOM3TRVVMhLaU/k3+CcWAcIq1JSODk7NCus2Zpp/diEn4eiWU0wUK8
         yexmLTgj8UyXKuJAhPpuToPiC4qawwBRQn6GrRAlG3SWrBXHVed4sxv4dsKIY1nscQ9d
         sCkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=qSHoF8V+EFQagRk1pc/+G+fEj1DpiqE8G3KQ67JvFaY=;
        b=Go7Pjq/XwvBKO+d2nNA1tSc99+BQ35XfC3kHXPfoRwMorSk8sYLa30cxRbA864bvjS
         owTyxnytne0WBaQa9W6P+Y5lj/z5/x1HaqyC1QrBBz+wIgkeJEYansoF57iTOzyBqG7J
         QmxyCIoJRFv3KrbgSwxeF5ptZhxU2LtahW9XwnnF/HIpGgUftOI5v+jAJdUvmIwMOdu+
         FhBVQ7aVwtu+mhntm278xnkOU4jpvkNx0so94kxUfyQeEfMJiON+YH4/xd68ENeV5ZU5
         +gTNvLQ1YURBz3VsvGddov6WDRVDB3U70vupOAasn9Zmi9zxa0aa/QIHfXMTHTInwAr1
         zflA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i6B5Haa+;
       spf=pass (google.com: domain of 36wwvxwokcbywjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=36wWvXwoKCbYWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 26si365839lfr.13.2020.11.13.14.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:16 -0800 (PST)
Received-SPF: pass (google.com: domain of 36wwvxwokcbywjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id d8so4669102wrr.10
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:16 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:bcc1:: with SMTP id
 m184mr4399399wmf.132.1605305835550; Fri, 13 Nov 2020 14:17:15 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:53 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <6003966741503e98ca237ba056cf35cf0c7045a0.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 25/42] arm64: mte: Add in-kernel MTE helpers
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
 header.i=@google.com header.s=20161025 header.b=i6B5Haa+;       spf=pass
 (google.com: domain of 36wwvxwokcbywjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=36wWvXwoKCbYWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6003966741503e98ca237ba056cf35cf0c7045a0.1605305705.git.andreyknvl%40google.com.
