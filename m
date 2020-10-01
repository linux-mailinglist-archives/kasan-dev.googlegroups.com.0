Return-Path: <kasan-dev+bncBDX4HWEMTEBRBL6E3H5QKGQEGD4BILY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 68F16280B12
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:44 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id d23sf57412ljg.21
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593904; cv=pass;
        d=google.com; s=arc-20160816;
        b=G20KBFJ6ofUWlEUZ3a9lPb0mzCgZRRcIY7uY31lb+N/Hn/ykBjgNZbNwzOLt5kkC1B
         ekiPX+LeaUQX/B/xBjhrVRW5BYkJlF8k44+gnJ5kQOZyKKiYAtNxzBxTtbYJHXoDj+TY
         dwBs1tU1T7KitKBVWUSzvIzsHBbS6PJ3RsG1u0AnjNK5ke8BOSMry2Lfbzj7JuBwQuJm
         aZEJP2wGpB7jt7ss2RADkKq5yNP5k9+/gdaJrRBdkHDw4DMzHdPxKFrsdsi9rhntEXkb
         d+1nbfAzD8nuSzRSQbJ/RZ839rFbv2/HBRUmbOa6GQvJy4T+Gq+zJTNoHDvaj9yA3t/5
         oAKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=/mhP8i377MECusupaDvNyusn2NIhpXltiC5aZJJbFFU=;
        b=ohbURyNMzt8SLV5rXs+A1o2/5Xy+WRExoew5W9SREziOEbtBibjNR37EOtbhuys91C
         q/s9awcpSGT7LULtj7nLCqQrObz9mZ+9OqUbQIVYPdpmGjqSWaWYidnCxR/150HfawKF
         3cBIiVyebRDwwUcWQvvjh5KwqZmyFTypnXFzecyDP4fFmvCJswvOi4u+41qdD6+omQr4
         bf49WJi6Lj/pfrQ2qvoZif9V9WTjLxKvydBI1nEz1sum7AkxAJz5ouJhMxd36DOPDesM
         Q9gtDdPUGN3Z0wSMqqWsGE7TKJTXG0Qc91lRASbLTVI2S7rs4cqMJW83wkt2Q6NFct7B
         YbDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kAwG9u97;
       spf=pass (google.com: domain of 3lmj2xwokcc0t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3LmJ2XwoKCc0t6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/mhP8i377MECusupaDvNyusn2NIhpXltiC5aZJJbFFU=;
        b=di/MXwOOoBtLVmdhPKClqEui/I+lpDCWQNXbyt8QNXk2N3Hn9eLFAPCfcDRaYxIB21
         ImcLym9jFbHxJxHnBGfhTE3nHkWhjMUD/HGtGMJo7DRU1vXwkdniXaXWy+2RzuilRb5k
         4/Yq1Bro8Yau47SysymLd0+yxOpuU/j8Jj+IxRMpp4KZtXmoXG2X3cAwCKsExDc0/IsM
         q4IsbttuvXTN0qquAsrgTNWHjd4z0m2tZe9ChdcFkzZJOtzF2mHEYcO5yGJqRfq4T+AR
         PAsRWNwfx8gClkSazKmEOp6dD4U4DX/oBunTrfhlTq3h3n9k8wjiWM9qUiH3dkyP5Nqv
         leFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/mhP8i377MECusupaDvNyusn2NIhpXltiC5aZJJbFFU=;
        b=cQCkD5cpUPVhnMCGz0e55ZVtimbUv5DXlQJcogw7aKkgtXgPQtUu5+hm5ku1teuBLg
         /Yf7P6fBnQ1CY5DXqJMGTaIBprUbZB/E/97TxBfd/fmY3MxocZLLRdTXohwNXhE5ZoMm
         9zuA6Nlewk9rcLnPc/8jmY3Hq55u4JrJVH6dPCc2sEEKByu4bAirTa65678dqN9f2lZv
         RtPaEoDg6JSodn7deKiAVrpuqsvRVOsshULqfQ3A+vkQOKoO5OdIsO85+9cCXHzeYGtR
         Hv7DysQqWZe7j7R9axWR0JqawLxrXmde2rZwuFbm6DT4oCKh+x6dhmTfio9UKAhz9upe
         g5cA==
X-Gm-Message-State: AOAM533jwDXOEkMlZbU6sRfb1MwQKtiiT0aRRXdJwAwYqTk+7DoIJqiF
	uNSa3egPFZ6e2stVqjX2zVs=
X-Google-Smtp-Source: ABdhPJzgJ9vomkxBOyFGhF/45MpbrhL3jtbr9HSDghj8KOh48znleeCmSAFTXIf/oZsxCgb0/mEdfQ==
X-Received: by 2002:ac2:434b:: with SMTP id o11mr3682070lfl.576.1601593903953;
        Thu, 01 Oct 2020 16:11:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7c08:: with SMTP id x8ls1069457ljc.6.gmail; Thu, 01 Oct
 2020 16:11:43 -0700 (PDT)
X-Received: by 2002:a2e:3312:: with SMTP id d18mr2890069ljc.328.1601593903016;
        Thu, 01 Oct 2020 16:11:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593903; cv=none;
        d=google.com; s=arc-20160816;
        b=fpHfl5A0ZGV6vKUYB71DT91dQr9e7whK3Js0Ycq+OY9mG6cnVPyd3sEAjnla5FhVvc
         hFWFX1IvhJdC3MLIImlqkIjCYf5pLVpEllMmP+1NqyTTJyY7aJ4hCmKH7dovEnV/WLiI
         nYSrYNzMVNEO/1L/UaZF3S8yCNiuAxT3MZe5VRKPAsHIXm90RG22puKd3fXoxPWPuYLO
         Oh0YxNoiQ0qp56JTiZywaLRwXLlK7s5dEOUZDhznhFec/I/DVKgopEpcoPkRv1pUqCa1
         /CPHH7Up0klNkDLV3n0xrIE56POsKHtVX8YReTqynEglERrGtYfQ343Hw2RNWhtTHz4M
         mkWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=9dHZTsumEZWfULwt3pS8Ru/v3DARM8JrrMIGCjKgew4=;
        b=IBTVRs0bvC6dtJmVXVXIJB9pEK+S0Kv7gjdoXm4OOmXk89pjE+qNi6QTnx69RKX8n0
         UQ9OAf8CqKXI3tOzb1lexIsJH5r2JLcZvsWW4cu4So+FD1DE4vDkyosSP7nos3Vd4xRA
         /WCeu5XDimRCXW9UGwTigw/MQAP7weHVs9XnFUdJFLCVfLHANCNU1dCD+tUuq03VRWVn
         ASPZNn23mhPJ39rEf+5hWK2CqxFN4uZpQaVwfd16LHZjqJOu9+a3EjkyENDz+sbHMyEc
         8v/iRy0DOuiieEglscHTeKAaXoZ6MqWQ1TyLn32HWzjaj0mldbIQyC+hDtHKhPFDR9eI
         yt9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kAwG9u97;
       spf=pass (google.com: domain of 3lmj2xwokcc0t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3LmJ2XwoKCc0t6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id z6si227019lfe.8.2020.10.01.16.11.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lmj2xwokcc0t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id u5so27212wme.3
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:42 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:408a:: with SMTP id
 n132mr2166937wma.45.1601593902336; Thu, 01 Oct 2020 16:11:42 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:25 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <96d3ade8c6e050fefc597531fa2889e67ed75349.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 24/39] arm64: mte: Add in-kernel MTE helpers
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
 header.i=@google.com header.s=20161025 header.b=kAwG9u97;       spf=pass
 (google.com: domain of 3lmj2xwokcc0t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3LmJ2XwoKCc0t6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/96d3ade8c6e050fefc597531fa2889e67ed75349.1601593784.git.andreyknvl%40google.com.
