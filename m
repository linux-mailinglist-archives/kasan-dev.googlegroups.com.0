Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPFAVT6QKGQEYMGEWTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A05F2AE2D1
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:14 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id s201sf177261pfs.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046333; cv=pass;
        d=google.com; s=arc-20160816;
        b=ToCjnD1cjWTQUoCEcDn0ahdWNrVaDU0EbTMcZEzaG7hUX6hd9a/6dKtSM9iPy4GKsd
         c/EAk21zkvadVeeeSCnxs9x+X25FeqIDeDHrJUrzys0KXPAhIvWnbF4cxi13fsssZOKL
         OoClp4uUwyRGgGPw2gN2DkuiUe/PQn+YDyAXoxyQgyr9gGtjfFfveCp24kBPffF7vof1
         kmvodCNQVsLQaZHqW+JkWKSQj1s35/BJa1D7QyiuB6MldBSbAcsMli3/5bk0qA57PnlB
         SOXx7IrheboRnH//Z8h7p+pz8vaD5Qlb0b0SNACWn7DS9VhK409FFTdCZduaUtpcprsO
         6C+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=WB/A5aNHNTXQqYCds3qOkbJ93q/z3/2+aB6ktZoGh1w=;
        b=uTQKezKg58C/D0kbBXzq9esDByMhm15Y+Mx/WB5kg4XmpkqfirIbrVBY4OQdCBpi0O
         mnyFVE3cLUwvRazJNIxCRK/SbE/DDWPqA8TI/5MNaFTNz96s5xr+CHzL4CJp4mGc21GY
         ZiGOtPZqqg5lDh4WF5ymO3H6St8vg5timDUDVoHNtA7mUpTAOzAtjhnNPI1FFAQ2jJHu
         9b6U/Ae+cDsgqASt/hmHH+UQ6T+28t5KE+kdlyREDP+fEeT4u7sPYJv3BZFKhP4G/zsP
         av5xwXemdjGw0pBo1HZNNtHDBqZv0ZEI3MtA+tOtne/Z34aLHv8rb14dSDZAaPHXwomq
         Jrgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Oc77bBiQ;
       spf=pass (google.com: domain of 3oxcrxwokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3OxCrXwoKCQwmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WB/A5aNHNTXQqYCds3qOkbJ93q/z3/2+aB6ktZoGh1w=;
        b=PKXq2ZzF5E9EcJ71qGfsx42CILWA7QRP3LaxQIgUDuN5xwsEjn4ImQLXGHqEvZhuUh
         CbkOTryNdPNQh/A3J/EZuPJX9NDJaGCeq3wyW6CMnrB6REvK60zcGRb9sveCDezq4Aj2
         4sZTHjypKmtzGoPe3cPENB4RdiPR5DonwKh8FRdVsMuB+7zJ6pLEh83IMXfsmPc6NyI0
         +hSkX8SR5Fe5SGGsQatjKF90TF9GnWIhXz62m/Xw3dcuml92/Cjl7hT4Z6+CKseY31eE
         rsPKq4aHMBjNFUF8aBGE11doNYBBx5LONPdhEHHaPDx0woD2jZMOqQTtt0k0zPPEUY6H
         byuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WB/A5aNHNTXQqYCds3qOkbJ93q/z3/2+aB6ktZoGh1w=;
        b=T58SDpmiKYH877/AJ29QCCwjNL7Bre050MrLuawK2rYxz56CUMuEc0ND2t0youOfMj
         ngMh5GQJh1DNb3YOjIa4bN/e2hC9WMeUyCcReVhHfONXbwGMZaSgPQ4KF5JljuxGtE/C
         SECMTvVNbbrv2MyvH+lmNvzuAaxUJ60wCDNmw71KuBQoOz7g6WTJDAatgH/AzB97tdAk
         jPaSpw4koS/FIz9zINn8pioAYHHjP/Ky5BYfWmyznwTCXoPlipbXfmwtythxfCXe416b
         fCTbc5o2PQk2OACL1N57QHAkTQLsBM0D+gmRNCe6tJwCWUkZP+Y1+G2t/nHUda0sCpf3
         Cnzg==
X-Gm-Message-State: AOAM5323XOZi+Zn6+xlXjfgGx2oYAm5GfyJE+SrWyu69lrQWvpHCPtC9
	VvIbG+AE4eC+u0OZoL6/KuU=
X-Google-Smtp-Source: ABdhPJwwqCMEwPXmNv0gZjh3UhzQ5FL76nkZetGC2H8irFmB/hh8Uv4Y+sFM3pRp02onqIij8+b2EQ==
X-Received: by 2002:a62:2582:0:b029:18b:37c0:766b with SMTP id l124-20020a6225820000b029018b37c0766bmr20377944pfl.74.1605046332923;
        Tue, 10 Nov 2020 14:12:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:451d:: with SMTP id s29ls4646704pga.5.gmail; Tue, 10 Nov
 2020 14:12:12 -0800 (PST)
X-Received: by 2002:a62:254:0:b029:18b:fcea:8b7c with SMTP id 81-20020a6202540000b029018bfcea8b7cmr11483062pfc.69.1605046332368;
        Tue, 10 Nov 2020 14:12:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046332; cv=none;
        d=google.com; s=arc-20160816;
        b=CYzzl8+Y88ss1uvp/eTV52n7gm0fkqnNyzZH11/eWBuSZWdlLEOilJOOyLT8MC4sY5
         R9+X2szCpsmHfzfqYu4yYAu8+AfEhRr9YV78RFIiIzH0Nk7GRVGle33AbjpprHBaL84x
         swb6WZlvcqcu/EwjcflSnOpkhZYzi6DDcADYy9QdWfDo1roX17KrH/oYqcC3T3eP97p5
         TqNMoZ/E1izAyAOSlEhGUJvmkoTQb6H6utP17KFwPwuuXiNWPWqO96KRz0PCBf3Blcgu
         rIRL0xMHqC0c1qvEfhxem7RLQGx0Mq3Gbhs0De76Y1HpRd8BIWwp65NHPknOun9PzjF4
         9J6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=qrqIDIkALGo0nLxlkgPOhzfz//pXQgHs/W32Rad/lkk=;
        b=oE6oz6ewnBZMXxvK/cDBmQYi2HusN58knUumKdPe9iPLPXApaoRHf8CXL6vji1fBL8
         9V3RxukpMz1SW3CH8V8av4fCm61j3BJbmQQvcrvFpE8mcGIUfeabF4TcLA4gbn5H357C
         w5OTBCpdzYHPz2n1BRElj/sHKzPdxDwW+dTyHcMeC9/FMSzdujNQfk1mEKwCGoi9UQvB
         Z7O/XEgp6Jcc56F5F5HT8RupSn9JvT0oFEXX2DceOmRqAqnuIZ1OKbX2jxw4iCLT1V+s
         jAZiiyAzLp/6rBOSfwuvMPC7a5wtQ3rj7uNqACE0tGcZpWw0mwLS/cbtjcwhsup37hjA
         WOOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Oc77bBiQ;
       spf=pass (google.com: domain of 3oxcrxwokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3OxCrXwoKCQwmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id l192si4473pfd.6.2020.11.10.14.12.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3oxcrxwokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id d41so34923qvc.23
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:12 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:eacc:: with SMTP id
 y12mr21985881qvp.31.1605046331463; Tue, 10 Nov 2020 14:12:11 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:24 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <85a6021bdc296365c1c5bb3f6be5b1f80763a2b3.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 27/44] arm64: mte: Add in-kernel MTE helpers
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
 header.i=@google.com header.s=20161025 header.b=Oc77bBiQ;       spf=pass
 (google.com: domain of 3oxcrxwokcqwmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3OxCrXwoKCQwmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/85a6021bdc296365c1c5bb3f6be5b1f80763a2b3.1605046192.git.andreyknvl%40google.com.
