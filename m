Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLHORT6QKGQEMUEY2OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 243C82A713A
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:13 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id d5sf1304ljg.12
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532012; cv=pass;
        d=google.com; s=arc-20160816;
        b=jnP3df+4hnx0GnbomUBF+TmEjGiKcTPDYR/9qAlwSGWWip5JNqdaQKA6z/wRvKvtKI
         Nmrfohu4QVtt/x+3Km7zgMg+MP3Nr7OxinMgpvXlhuj0rCbAeTYgQN1CxEibKAFTmvTv
         U58IgWVX1xLU51IMFOJ3snWnD9Mpo9cAnCth5fwcAfx+TEzZeFBbHuYJysHQ6grmFRKU
         e3Y17iptGSDn6rjbrffYcTf+6tHCUu84eYSgyGeN/7a8GpfCvlUTCRIFDgTbOmHC+OIn
         8Lb679b8xiYtvUknJh26jTkiFAaNpsgVZ4HUj1yGLCpmBRIKDtpSy+7NPAF3XjJH16vw
         bOIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=pm5IRhF5BWPcqDjGJNOlBiAaPJIAKcVMJtc6ZnuONBE=;
        b=wgVtN4NnbrBY0GJNHiVZpM7JyPEnQfEy849NDqlw674pL+L0VbrV/i4/d7Rrj1r9/U
         cOWSBbeJmHIZxlvK62aKA5sruIr16D+nBej1p8cueNOUfUolIfFWYQcMTXZmGMkELRLy
         q3FKVITUj8TXTs31YHnXLpwrc/mWqAyYUBvMS0e5CHgp38QIeaeXR+6PfxrmW3FVVUBx
         onyQKd8OjCXE56kw9BztLH+O7LyKTduK81HH2HSKD0hFNC2FZR5Tn6lOmXOK0pA6goNj
         wc/14rMNEErcTRv83FnOYkY8MVurogOrzDnGomw1O+u2LjXWZyq0a6Y+WwqCmOEl4u8T
         rzPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YiLZqyii;
       spf=pass (google.com: domain of 3kzejxwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3KzejXwoKCSoGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pm5IRhF5BWPcqDjGJNOlBiAaPJIAKcVMJtc6ZnuONBE=;
        b=gI1ZeHdAUq4MMcHYLqhtUjYV5rDyGudXER4hLsssfsWEeG5YAkBEutvjnccjj6snfI
         8xbqRqe7Z4GfLguWBPclmwlAQI/hr1FnQAZouVd46qwqisEByzhbMFOMBBFQ3nl6mEdd
         pNouj8KyPWZa1qM4XjHZm188uEWdaT5toL4XuiNWgZRJbNTxj+nvqFc2sXGWIruXjcjW
         P9moWmuYtPRoXQBNDPF7JXaio8Cy+hokHxlBghBScQmNuaHBgRhSiRM8ZR/weqdbiugS
         BOEDuMFAraTKSBCtK9WPZp4WnxlwvW+vajAUrB0z4OlQmDb1q639KAoed645HcTYO7jX
         aDKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pm5IRhF5BWPcqDjGJNOlBiAaPJIAKcVMJtc6ZnuONBE=;
        b=RIFZlizDNZrc7JQV+5M9y82iAT5ZkCefPu+W9qOLoFByc4zyMzi717HXtl0FOUMKrL
         SBowIVyNaJUiLm6nIkRk6zPxJF3H3I4xzPnc5MyWKuzYPXIL+wxCYroklLqSxKNr46Bl
         HLeG48K5516XjQCqXOKCNWeLvrpBH8Dsdy21vcKHF/nyE9JaB5/rYflWkTX83eBcBNqn
         /F5F4VJWu15dCwqRyRCksj7VVPkdVYtXW9BOzCMwmf5HlSAY4rHM4C5hI7QUCayMmY0z
         uXPjEQp0dgnEpwZO4WXF7xOvFhk10ekCW21JecRFbYdXpA3dQ1AwVtNLFNiNgwvUe4IM
         GqXw==
X-Gm-Message-State: AOAM530rauevU0f7gdR2i8jEokfYAar3jbtEH0gOPRbw0SHLE+d7pGG0
	wJACsKOjmASEweMZhETulyk=
X-Google-Smtp-Source: ABdhPJxn9G4nzF1EOO0GCpq7Taavn0eNAQce082S10F1xqNDYkq+iWOHkidUJRM/BsHuP2V+mHLGIg==
X-Received: by 2002:a19:42d3:: with SMTP id p202mr20312lfa.85.1604532012694;
        Wed, 04 Nov 2020 15:20:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:91d8:: with SMTP id u24ls106516ljg.7.gmail; Wed, 04 Nov
 2020 15:20:11 -0800 (PST)
X-Received: by 2002:a2e:7211:: with SMTP id n17mr114076ljc.452.1604532011791;
        Wed, 04 Nov 2020 15:20:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532011; cv=none;
        d=google.com; s=arc-20160816;
        b=jVvX/d/aAu+vn8s7O+/WdNDX7UGry6YojzGtfzVpGse0Q7ti1eQXlwtH6tYi2/tEKR
         3UjZAPPdvTZ5V1xkOJ+DDuofthCnk+qA1Pa6d70iEgu9LNLJMWT5CZlMj5ErfXt3b2Fs
         sf7EzdmTmXETa+cO7BUMgvWj8UcsjDHDj+a1sKAwor797yfH0Gl4zgm8cOj84VA+KC8N
         Q/rrpZTOy5O+4BwG2mM7Dbh0MZYok0mTcKvZNPNpcShVVyFVltg9bTvymk7aNtS4T7PB
         X/d7y9SPSW7N8j3P3p/SpoO6x24h6fiacZLiym2my13Z01X2gjwb+k/LRjge56KOaxIo
         Hrcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=iKiZmQLw/RkryeoFhlFWSKbY6lm99BwbnzE2uZJZe40=;
        b=Fq3a+NPU4HPSbq5NgprDojojOPQzF/xE4Ty7Y9oe6brOMdYiBCkky5kHPVT2P6ewWK
         kANzCaSsTuXR04RItT8zErUYCqUPbIyG8KDVwaTllLjgP2ZPwVuC3NtVEr5DdlZ3vc5A
         TlrUZ1YgkvHUU2uirNPlH+gIU2kfF3nsZ3HoN2xZLHxKHv9g8C+HWkfOi6K17AyFmhsO
         H8TRHBoY00q2D0uya0l5zWjT/1H/o8mIYh4GsK2bqMg/jS9xXzp/d4tF6/pLidQrqE/N
         SaL5Kd+op/NlIwBJjjO18nT74jHRMkd2EHuteEnlxfhiyMwiJnaYGT/0dOYUFFqKPtfy
         OONA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YiLZqyii;
       spf=pass (google.com: domain of 3kzejxwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3KzejXwoKCSoGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id v24si116687lfo.5.2020.11.04.15.20.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kzejxwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id r16so30989wrw.22
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:11 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cbc8:: with SMTP id
 n8mr87026wmi.124.1604532011132; Wed, 04 Nov 2020 15:20:11 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:42 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <08de7ce49ec38f9dd279f60de78c67e6c8be3316.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 27/43] arm64: mte: Add in-kernel MTE helpers
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YiLZqyii;       spf=pass
 (google.com: domain of 3kzejxwokcsogtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3KzejXwoKCSoGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/08de7ce49ec38f9dd279f60de78c67e6c8be3316.1604531793.git.andreyknvl%40google.com.
