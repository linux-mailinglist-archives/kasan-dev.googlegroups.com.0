Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXG6QT5QKGQE4QQILIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id EE6BA26AF61
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:17 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id 6sf2015338oix.6
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204637; cv=pass;
        d=google.com; s=arc-20160816;
        b=NJRvPLsrO/mpL1dwx0VV5rzMHkEvIqvlw8J0JNHAVXihGY7cm7aeR2sr8h2u7gt/l4
         jP/WWr4vPc043eISHSjMGpWiRfszflGAdmySiA3c1k6kyrVgyirNaQ3jWtCnMOKCQQrA
         f8Rw/jTkGc8fNFK+igoQIiEOv7OHGtInwt8Pj3sHZ0BDaQqq+zksBETTfTpcwArRGh52
         u5Cxm8VVL72sI/bT5FTOuJif4YEPPsb2GuVgoASgEXw2qsiDBAiV1YOTS9LgYRH59lzo
         YtzBXIFvbwgy/W82MEZXmQnB8n8M98Bqa+zdfGugDS1cukNBnjTPyzVEFDWoYC4ol+za
         4/RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=2Md7r5PBN4PWa4xXcDSb2ysImNpUS4SarmMekKSW9wc=;
        b=ZZ9VOI1eoYBocFTwj4S/GmZ6Z0Xvvxh5ZNKQEgibZCTFAQrXX5Olo48JR+eqNKd2rh
         4Z/2KIRuy10jZ7ohTEtvOgqveoSoehpxatTsoA+dySBWCQ6EcGKhROhJ/OnRHSO2bmee
         M7x7sDGS/dAowH4SkvY1XO2/LAQENR9r1QjYcASqb6ExBqk3NY78SEAOYOUqQJWGSPUl
         vdXM7xKPp9q46CUikurzUIECzAGaqGcg07aBR3TUpumNQnan0odmMd5ZAC8ub/3n92sG
         tqHmFO6LqycIBULYVs7FHXHN6xns4WbE6m0TDGjWk98UbSQ8x47jFrrSGLUQtk+/bXsW
         B0zg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qdt0h6m8;
       spf=pass (google.com: domain of 3wy9hxwokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Wy9hXwoKCUAcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2Md7r5PBN4PWa4xXcDSb2ysImNpUS4SarmMekKSW9wc=;
        b=BEJ/zf5e3ovqorYWR56Jn5BjpQ77RZiXmZsq6ET0sD7ZKsyTeJyJdZKQTIDzi5mWMh
         l+MtIZY05NxQzMBihQbMRdgUYI6Qn5EeQRvMtYvcQMR+p3ZGPm8jxb6gUcRtswODT8Q7
         klQkVv0jeZXbLsXTEiCKUhTxE6RhqgTPio0lonFkrOozXRJDtICcBUBjcEW+Sf+NtlmI
         UptbZ7ptfRKZgWQ2YuilP9Y1rEPkeqMPCY6D5cBGxAoRT+nYmLLmQNvkA3dlWMyddGfJ
         Jt3GscFqKVGfI2a4O3z7K53iYW5nxyqoe2kET+IdKMxKuJQpUURjiLW55J8/N7h3mjMu
         RTcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2Md7r5PBN4PWa4xXcDSb2ysImNpUS4SarmMekKSW9wc=;
        b=NlsSX0wYC+wNS56duyGXZ8zUrh1kDt+teF7bn1WqYQCev54VbrzGOHt7Quw0lL+yq+
         R0ZUftwGVvmBc4+cZ/tn/GITVqalIwED9n55906h0ELfKIpGiheQPndchAek3hoJfyO2
         Wupob151bxX7S4tStsSlyFu0w0JITQ7hKUsUuK2H+2XUiGeemFzD1/gkKpLBhmApSfJU
         TmQ3qccsR5bTfWl+REKaEpCp/gG+JcaZE5+9JEFlDs5G+2dV7rNgV5q2B9V1I8bfIKYb
         zF7aK4ey6h2fXEQ7w3fMXuZzsH8S7vOvmy7o8v6djV5zqb8zwcJCEge5UdJ9C2rOEl7x
         RyNg==
X-Gm-Message-State: AOAM532v0ZcbvQbZE+4BfY1t02zMP0mUSpyeTIXpNNwA754CVII9KnzB
	3ZYVRA1BZ7O7NeBPTmi998M=
X-Google-Smtp-Source: ABdhPJwYfn8v0ZlcrWH49c/y0WfRLoC9frz69ai2UWJbaR2C5eYNxKlb19DKuasqYmr1Rmts0Q0U2g==
X-Received: by 2002:aca:da8b:: with SMTP id r133mr944946oig.163.1600204636876;
        Tue, 15 Sep 2020 14:17:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:49c9:: with SMTP id w192ls79171oia.5.gmail; Tue, 15 Sep
 2020 14:17:16 -0700 (PDT)
X-Received: by 2002:aca:1b01:: with SMTP id b1mr994823oib.137.1600204636516;
        Tue, 15 Sep 2020 14:17:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204636; cv=none;
        d=google.com; s=arc-20160816;
        b=yQD9Jc+Mx36+QKQCr1Wq5NoE7etpoyItsUgGY9659MjowDGoe/oKxO9nDJZqDPkJHt
         aq7vy7KkpOqhJCN7dS1glegmWFH8p4TGTnqTZaRRV/56dW3BombeWvKKt9iOE2/2Hsf6
         yZ8j1BUnSaq9VZtElza+dXDBw5Sdkdarnf2enWva5SivLZcCcWwDBcu85u34AMUjVvtR
         mJUTdXYJBClSz6JyZnkBy1QsvfgSX2o9QeqTinD6sP1venN2Mgl/jDi8othVLGAlKWD7
         H+sucdZDr6ccckRZ1aNkDC0S8ap8KNL43MVI/hM8835pe7V6tfN3YX21QnLixnfPfZKY
         ecrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=EjJhT+aBWvSW5tBYtrKg3j1ds+SSoe7l1pzkwlzhcIA=;
        b=AwR3DOvy5QGZO+RKeP/C0CSKHmdMsIQOffTDB26tA7WNnOaz/eWMC+WDZGo4cFEnXw
         fBAWZamLtlSLtsaxa9PZWl3lPDHNvGrHWsuFgXUBcknUQIP8SWZJyPkSWia/66iCvbzh
         jEJi4naPNw9LXJuoAiU5AiMLhTXZIDkbZAkGIGogP209j4eeSsA4QcMW+QCh0x8cjwOg
         F4KMEj6PjO/M/RTYB8qgPpBkAqBE78ZvQRqWYVstPLRZMPw8oFUewVlQ7nsGk0t7WZ2H
         +m2Lcsghj+CvMAGBfr/0BeSCYOwDhumcK8VDoqnGenKF3LWj5WfubrTdutdSdQffzfFd
         Oc/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qdt0h6m8;
       spf=pass (google.com: domain of 3wy9hxwokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Wy9hXwoKCUAcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id d11si1369808oti.2.2020.09.15.14.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wy9hxwokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id p20so3109459qvl.4
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:16 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:57cc:: with SMTP id
 y12mr3796349qvx.48.1600204635905; Tue, 15 Sep 2020 14:17:15 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:04 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <4ac1ed624dd1b0851d8cf2861b4f4aac4d2dbc83.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 22/37] arm64: mte: Add in-kernel MTE helpers
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qdt0h6m8;       spf=pass
 (google.com: domain of 3wy9hxwokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Wy9hXwoKCUAcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I1b5230254f90dc21a913447cb17f07fea7944ece
---
 arch/arm64/include/asm/esr.h         |  1 +
 arch/arm64/include/asm/mte-helpers.h | 48 ++++++++++++++++++++++++++++
 arch/arm64/include/asm/mte.h         | 17 ++++++----
 arch/arm64/kernel/mte.c              | 48 ++++++++++++++++++++++++++++
 arch/arm64/lib/mte.S                 | 17 ++++++++++
 5 files changed, 125 insertions(+), 6 deletions(-)
 create mode 100644 arch/arm64/include/asm/mte-helpers.h

diff --git a/arch/arm64/include/asm/esr.h b/arch/arm64/include/asm/esr.h
index 035003acfa87..bc0dc66a6a27 100644
--- a/arch/arm64/include/asm/esr.h
+++ b/arch/arm64/include/asm/esr.h
@@ -103,6 +103,7 @@
 #define ESR_ELx_FSC		(0x3F)
 #define ESR_ELx_FSC_TYPE	(0x3C)
 #define ESR_ELx_FSC_EXTABT	(0x10)
+#define ESR_ELx_FSC_MTE		(0x11)
 #define ESR_ELx_FSC_SERROR	(0x11)
 #define ESR_ELx_FSC_ACCESS	(0x08)
 #define ESR_ELx_FSC_FAULT	(0x04)
diff --git a/arch/arm64/include/asm/mte-helpers.h b/arch/arm64/include/asm/mte-helpers.h
new file mode 100644
index 000000000000..5dc2d443851b
--- /dev/null
+++ b/arch/arm64/include/asm/mte-helpers.h
@@ -0,0 +1,48 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Copyright (C) 2020 ARM Ltd.
+ */
+#ifndef __ASM_MTE_ASM_H
+#define __ASM_MTE_ASM_H
+
+#define __MTE_PREAMBLE		".arch armv8.5-a\n.arch_extension memtag\n"
+
+#define MTE_GRANULE_SIZE	UL(16)
+#define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
+#define MTE_TAG_SHIFT		56
+#define MTE_TAG_SIZE		4
+#define MTE_TAG_MASK		GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
+#define MTE_TAG_MAX		(MTE_TAG_MASK >> MTE_TAG_SHIFT)
+
+#ifndef __ASSEMBLY__
+
+#include <linux/types.h>
+
+#ifdef CONFIG_ARM64_MTE
+
+#define mte_get_ptr_tag(ptr)	((u8)(((u64)(ptr)) >> MTE_TAG_SHIFT))
+u8 mte_get_mem_tag(void *addr);
+u8 mte_get_random_tag(void);
+void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
+
+#else /* CONFIG_ARM64_MTE */
+
+#define mte_get_ptr_tag(ptr)	0xFF
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
+#endif /* __ASM_MTE_ASM_H  */
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 1c99fcadb58c..82cd7c89edec 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -5,14 +5,13 @@
 #ifndef __ASM_MTE_H
 #define __ASM_MTE_H
 
-#define MTE_GRANULE_SIZE	UL(16)
-#define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
-#define MTE_TAG_SHIFT		56
-#define MTE_TAG_SIZE		4
+#include <asm/mte-helpers.h>
 
 #ifndef __ASSEMBLY__
 
+#include <linux/bitfield.h>
 #include <linux/page-flags.h>
+#include <linux/types.h>
 
 #include <asm/pgtable-types.h>
 
@@ -45,7 +44,9 @@ long get_mte_ctrl(struct task_struct *task);
 int mte_ptrace_copy_tags(struct task_struct *child, long request,
 			 unsigned long addr, unsigned long data);
 
-#else
+void mte_assign_mem_tag_range(void *addr, size_t size);
+
+#else /* CONFIG_ARM64_MTE */
 
 /* unused if !CONFIG_ARM64_MTE, silence the compiler */
 #define PG_mte_tagged	0
@@ -80,7 +81,11 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
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
index 52a0638ed967..e238ffde2679 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -13,8 +13,10 @@
 #include <linux/swap.h>
 #include <linux/swapops.h>
 #include <linux/thread_info.h>
+#include <linux/types.h>
 #include <linux/uio.h>
 
+#include <asm/barrier.h>
 #include <asm/cpufeature.h>
 #include <asm/mte.h>
 #include <asm/ptrace.h>
@@ -72,6 +74,52 @@ int memcmp_pages(struct page *page1, struct page *page2)
 	return ret;
 }
 
+u8 mte_get_mem_tag(void *addr)
+{
+	if (system_supports_mte())
+		asm volatile(ALTERNATIVE("ldr %0, [%0]",
+					 __MTE_PREAMBLE "ldg %0, [%0]",
+					 ARM64_MTE)
+			     : "+r" (addr));
+
+	return 0xF0 | mte_get_ptr_tag(addr);
+}
+
+u8 mte_get_random_tag(void)
+{
+	u8 tag = 0xF;
+	u64 addr = 0;
+
+	if (system_supports_mte()) {
+		asm volatile(ALTERNATIVE("add %0, %0, %0",
+					 __MTE_PREAMBLE "irg %0, %0",
+					 ARM64_MTE)
+			     : "+r" (addr));
+
+		tag = mte_get_ptr_tag(addr);
+	}
+
+	return 0xF0 | tag;
+}
+
+void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
+{
+	void *ptr = addr;
+
+	if ((!system_supports_mte()) || (size == 0))
+		return addr;
+
+	/* Make sure that size is aligned. */
+	WARN_ON(size & (MTE_GRANULE_SIZE - 1));
+
+	tag = 0xF0 | (tag & 0xF);
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
index 03ca6d8b8670..cc2c3a378c00 100644
--- a/arch/arm64/lib/mte.S
+++ b/arch/arm64/lib/mte.S
@@ -149,3 +149,20 @@ SYM_FUNC_START(mte_restore_page_tags)
 
 	ret
 SYM_FUNC_END(mte_restore_page_tags)
+
+/*
+ * Assign allocation tags for a region of memory based on the pointer tag
+ *   x0 - source pointer
+ *   x1 - size
+ *
+ * Note: size must be non-zero and MTE_GRANULE_SIZE aligned
+ */
+SYM_FUNC_START(mte_assign_mem_tag_range)
+	/* if (src == NULL) return; */
+	cbz	x0, 2f
+1:	stg	x0, [x0]
+	add	x0, x0, #MTE_GRANULE_SIZE
+	sub	x1, x1, #MTE_GRANULE_SIZE
+	cbnz	x1, 1b
+2:	ret
+SYM_FUNC_END(mte_assign_mem_tag_range)
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4ac1ed624dd1b0851d8cf2861b4f4aac4d2dbc83.1600204505.git.andreyknvl%40google.com.
