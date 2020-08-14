Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLMT3P4QKGQE3Q5A72Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 84D08244DD0
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:13 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id w138sf2162845lff.22
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426093; cv=pass;
        d=google.com; s=arc-20160816;
        b=jQtZaimY4vmN1lRcK/JuqMQviUMwy4+EhGn5EW4ivHPqV8WK/U5LxaFaaZv1OfsKqv
         WkMvFgUj0e/mEnS7PmhqfPka8t9+QZTc0eBdMnRMSTRh8haBIMi5a+TGzJuyg7ZXs05Z
         MdRZQ5/k5cbYJbtTU4WREIg09yjHv9B0kR2wH7e+sK4+6MjgSlV7XGjRO4/V1hn34CJ2
         SewdIEYQzEKfIOARtqfjKF20YWMZ6HEJv71SIasp981/Pgywsca/y8aUFrsrrt6QXPwe
         MRCU1xjkHcHg/v1co8Cbb0mJtvbo2M+x3Lo4CIODW8REoqp9UB4BNa+krEFj23mVBL9I
         CufA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=AtwX2jfAJD+QYxTiGwAhW/AoRkj9K++FE7kbvJVtBcU=;
        b=TkPFab0JLkCDrpyjsIXO2vUNH1cG9kY/M4bINNaVLqaucmDR1z9uz+9cwcrqC8AYG8
         /Qd8W1SoZSLT9Vo4Vb2D4wDgqpGNH66nRR1ZLEaKAQTFmQzIftrvU98r6lvSqTx4wMax
         KkzMSoTB3A6bd4GVcmqJI3enEiRZNC+5bFZNwf4YaBxTv2dAhZffGRCS5IPcHqrh9KVA
         A6/k96uISjZpYH2ofVOXdXRcKQuzQGiyfrzusjSvMbUULO8EDtg32zrPb5rWVhbNS1aa
         FZkyQsVl+z1GkLyi1Xi6DCCdp6AlxAuSAbak6uJ+HHc4Vq9VRM8XImfHpRf0JnxtyHuM
         e0PQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="r3Pq4Nw/";
       spf=pass (google.com: domain of 3q8k2xwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3q8k2XwoKCRo0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AtwX2jfAJD+QYxTiGwAhW/AoRkj9K++FE7kbvJVtBcU=;
        b=O056SSb4UpbhcFPJ70cmSdIDL7KncY2OjxUA7JoCUVDPwfYmNWcPTXKcZN0ZppyuUu
         zomiYhZmeBfTpmYpMRbuajZVhjNiLKNcLB7bD6If6JE4KuU0/LwLUjbjUTq3X0QymxMH
         LS06YMlBS0LcbuFvHIQGWy+yMhY7NQBZBjerdPA1HEa0QZBW2zdcSXBIf9yHr9yHbOJ+
         Xp61qf5FHdsX3nDdgFjvWUPd9n7NYyXW8NQ1RJ/CJ484sXVbbloU+5kje6WyPheUja73
         vC5ZJ3vHrj7cEB8g0byeorvyLKrfgDDMrM/fGVIaFkNL43wpa2V5SqMnNDqVZIAmlcKr
         jIEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AtwX2jfAJD+QYxTiGwAhW/AoRkj9K++FE7kbvJVtBcU=;
        b=h7qeXQL4J5zm3tevPjUAw1DESeuEQwlOM2gMYjo8lIsQascYkFGiKKI97wEBZ2qK+R
         aJ3gB2+rBNP+8D1WXjMAlkMlRtyVD7XHHApChj+mtEcl8GDK64QNsmfEDrvaY//zMHo+
         ZYhBgAqEDmcuG8qVUMfMW4B4Zuv1dlK7qIyr/9P4Khlqg9R60elHB7WsWm89mOWazYpH
         lbwWThgJ7N5vejUSUcfDmuYawLrl2kKVe/1Pe5G3eR5JzoAPofKLq2cIhE0fEdYUJ1gY
         7Lz1HZ76LwoX+BteHVveBimDxtAzAsA5J7K2vAo65aj54Qjopj3ilJ+d67zkCBHI3RuE
         XryA==
X-Gm-Message-State: AOAM531m6qDq1bmjfbVaIj+qecM4kmXrnt5W4O2fH2EG/peT+cMg45Uh
	aFWFg/iFWe77HzzUFckND68=
X-Google-Smtp-Source: ABdhPJxJDNu5FUiL1SSkjfUGxWm9BTcWYwpfau4U/wYqRAU0RZiOftVicCWW3alQ8qPnPVypMcywqA==
X-Received: by 2002:a2e:9854:: with SMTP id e20mr1659585ljj.318.1597426093086;
        Fri, 14 Aug 2020 10:28:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a482:: with SMTP id h2ls170017lji.8.gmail; Fri, 14 Aug
 2020 10:28:12 -0700 (PDT)
X-Received: by 2002:a2e:a16e:: with SMTP id u14mr190730ljl.230.1597426092539;
        Fri, 14 Aug 2020 10:28:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426092; cv=none;
        d=google.com; s=arc-20160816;
        b=Bsb225Y4N+4+E9o3YgZFwoW9guHfZ+b1W5yYyZ9TyxIeslmBRtXC14AU5SWTezWncq
         /gIMLZB2vPJpbRVsrJt7xmzz6iqan4RgYttdUiRcmbF5s2uKgU8rFoFg5LiMI3KEFQc4
         TecPaJFs8t6iIV0th1dDhlIrCpl+iuyq3jzf9EF6gVaMAm1RahL0h0zENZqr+oRhYxoT
         S5cagBglJIIx1k8PBflyhmRecfDGgi5nbdtUOpdXcUK4u3FIjng6TfelelMjnmvTi5Cx
         nf3Jw0bfE7eH6Nf4UCj2yvpEjm2VZv22//7wF6xgNl6Y4gnCdsz5qyrtqTSB+7fRnIW/
         LspQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Riwx46dUdQZCUBoIKFQK30aeY6nxibjjbFZQvhGTSVk=;
        b=I/g110iuMIk6vyrwB83TEjZ/8EzQt4oUUgpSZ5PDhdn6nxPhpscUSe3kaQ1AuxldrD
         Wny1rk5sALzybj8vGhzBsTq6crYHPAFI+n1o/7HPp2D+qp4GpvjBL3si9wuO9XKBFLC/
         mn4Ax9ZfPpNR+DM9tJECGa5qjxjvc/jNVP0NXtqRkmS5XNI8s8zvBtcHHNCKqWTy6rm8
         OvM8cF+wjy1Iov65tP/qgEO6vPVD9vJXQP0Im6gttfRdcrOKTP2O9YqBtfpB8LXySV7a
         dyVkSSE3J7cj0KenPVcgZcAaap6/GjUc19Mjs9Ip43IPRzUMQd+125JAw0He+xzj8/Vc
         TlIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="r3Pq4Nw/";
       spf=pass (google.com: domain of 3q8k2xwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3q8k2XwoKCRo0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id u9si497015ljg.8.2020.08.14.10.28.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3q8k2xwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id t3so3597805wrr.5
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:12 -0700 (PDT)
X-Received: by 2002:a05:600c:c3:: with SMTP id u3mr424057wmm.1.1597426091488;
 Fri, 14 Aug 2020 10:28:11 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:02 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <2cf260bdc20793419e32240d2a3e692b0adf1f80.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 20/35] arm64: mte: Add in-kernel MTE helpers
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
 header.i=@google.com header.s=20161025 header.b="r3Pq4Nw/";       spf=pass
 (google.com: domain of 3q8k2xwokcro0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3q8k2XwoKCRo0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
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

MTE_GRANULE_SIZE definition is moved to mte_asm.h header that doesn't
have any dependencies and is safe to include into any low-level header.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/include/asm/esr.h     |  1 +
 arch/arm64/include/asm/mte.h     | 46 +++++++++++++++++++++++++++++---
 arch/arm64/include/asm/mte_asm.h | 10 +++++++
 arch/arm64/kernel/mte.c          | 43 +++++++++++++++++++++++++++++
 arch/arm64/lib/mte.S             | 41 ++++++++++++++++++++++++++++
 5 files changed, 138 insertions(+), 3 deletions(-)
 create mode 100644 arch/arm64/include/asm/mte_asm.h

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
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 1c99fcadb58c..733be1cb5c95 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -5,14 +5,19 @@
 #ifndef __ASM_MTE_H
 #define __ASM_MTE_H
 
-#define MTE_GRANULE_SIZE	UL(16)
+#include <asm/mte_asm.h>
+
 #define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
 #define MTE_TAG_SHIFT		56
 #define MTE_TAG_SIZE		4
+#define MTE_TAG_MASK		GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
+#define MTE_TAG_MAX		(MTE_TAG_MASK >> MTE_TAG_SHIFT)
 
 #ifndef __ASSEMBLY__
 
+#include <linux/bitfield.h>
 #include <linux/page-flags.h>
+#include <linux/types.h>
 
 #include <asm/pgtable-types.h>
 
@@ -45,7 +50,16 @@ long get_mte_ctrl(struct task_struct *task);
 int mte_ptrace_copy_tags(struct task_struct *child, long request,
 			 unsigned long addr, unsigned long data);
 
-#else
+void *mte_assign_valid_ptr_tag(void *ptr);
+void *mte_assign_random_ptr_tag(void *ptr);
+void mte_assign_mem_tag_range(void *addr, size_t size);
+
+#define mte_get_ptr_tag(ptr)	((u8)(((u64)(ptr)) >> MTE_TAG_SHIFT))
+u8 mte_get_mem_tag(void *addr);
+u8 mte_get_random_tag(void);
+void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
+
+#else /* CONFIG_ARM64_MTE */
 
 /* unused if !CONFIG_ARM64_MTE, silence the compiler */
 #define PG_mte_tagged	0
@@ -80,7 +94,33 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
 	return -EIO;
 }
 
-#endif
+static inline void *mte_assign_valid_ptr_tag(void *ptr)
+{
+	return ptr;
+}
+static inline void *mte_assign_random_ptr_tag(void *ptr)
+{
+	return ptr;
+}
+static inline void mte_assign_mem_tag_range(void *addr, size_t size)
+{
+}
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
 
 #endif /* __ASSEMBLY__ */
 #endif /* __ASM_MTE_H  */
diff --git a/arch/arm64/include/asm/mte_asm.h b/arch/arm64/include/asm/mte_asm.h
new file mode 100644
index 000000000000..aa532c1851e1
--- /dev/null
+++ b/arch/arm64/include/asm/mte_asm.h
@@ -0,0 +1,10 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Copyright (C) 2020 ARM Ltd.
+ */
+#ifndef __ASM_MTE_ASM_H
+#define __ASM_MTE_ASM_H
+
+#define MTE_GRANULE_SIZE	UL(16)
+
+#endif /* __ASM_MTE_ASM_H  */
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index eb39504e390a..e2d708b4583d 100644
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
@@ -72,6 +74,47 @@ int memcmp_pages(struct page *page1, struct page *page2)
 	return ret;
 }
 
+u8 mte_get_mem_tag(void *addr)
+{
+	if (system_supports_mte())
+		addr = mte_assign_valid_ptr_tag(addr);
+
+	return 0xF0 | mte_get_ptr_tag(addr);
+}
+
+u8 mte_get_random_tag(void)
+{
+	u8 tag = 0xF;
+
+	if (system_supports_mte())
+		tag = mte_get_ptr_tag(mte_assign_random_ptr_tag(NULL));
+
+	return 0xF0 | tag;
+}
+
+void * __must_check mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
+{
+	void *ptr = addr;
+
+	if ((!system_supports_mte()) || (size == 0))
+		return addr;
+
+	tag = 0xF0 | (tag & 0xF);
+	ptr = (void *)__tag_set(ptr, tag);
+	size = ALIGN(size, MTE_GRANULE_SIZE);
+
+	mte_assign_mem_tag_range(ptr, size);
+
+	/*
+	 * mte_assign_mem_tag_range() can be invoked in a multi-threaded
+	 * context, ensure that tags are written in memory before the
+	 * reference is used.
+	 */
+	smp_wmb();
+
+	return ptr;
+}
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
index 03ca6d8b8670..8c743540e32c 100644
--- a/arch/arm64/lib/mte.S
+++ b/arch/arm64/lib/mte.S
@@ -149,3 +149,44 @@ SYM_FUNC_START(mte_restore_page_tags)
 
 	ret
 SYM_FUNC_END(mte_restore_page_tags)
+
+/*
+ * Assign pointer tag based on the allocation tag
+ *   x0 - source pointer
+ * Returns:
+ *   x0 - pointer with the correct tag to access memory
+ */
+SYM_FUNC_START(mte_assign_valid_ptr_tag)
+	ldg	x0, [x0]
+	ret
+SYM_FUNC_END(mte_assign_valid_ptr_tag)
+
+/*
+ * Assign random pointer tag
+ *   x0 - source pointer
+ * Returns:
+ *   x0 - pointer with a random tag
+ */
+SYM_FUNC_START(mte_assign_random_ptr_tag)
+	irg	x0, x0
+	ret
+SYM_FUNC_END(mte_assign_random_ptr_tag)
+
+/*
+ * Assign allocation tags for a region of memory based on the pointer tag
+ *   x0 - source pointer
+ *   x1 - size
+ *
+ * Note: size is expected to be MTE_GRANULE_SIZE aligned
+ */
+SYM_FUNC_START(mte_assign_mem_tag_range)
+	/* if (src == NULL) return; */
+	cbz	x0, 2f
+	/* if (size == 0) return; */
+	cbz	x1, 2f
+1:	stg	x0, [x0]
+	add	x0, x0, #MTE_GRANULE_SIZE
+	sub	x1, x1, #MTE_GRANULE_SIZE
+	cbnz	x1, 1b
+2:	ret
+SYM_FUNC_END(mte_assign_mem_tag_range)
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2cf260bdc20793419e32240d2a3e692b0adf1f80.1597425745.git.andreyknvl%40google.com.
