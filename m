Return-Path: <kasan-dev+bncBAABBXWY32WQMGQE5CIJQOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E152840755
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 14:47:12 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id 5614622812f47-3bd53252a74sf5646354b6e.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 05:47:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706536031; cv=pass;
        d=google.com; s=arc-20160816;
        b=SEz0rln4bbRsuleOY/CsZRgmH/8BufQ/i3j2wQ1x3Xmk8e5XuJIN6DE7vE3yN45LMF
         nVr4jP1zwdUVaiMrCCsu3H4fb71p4vqM5UBE9ZF+wgRRqmejzbLAdYo0JweNtiGYXTHl
         Y33ZHc1brfkw1PjqURwMCjOSK9QBJ9GyWafpQ04t+cSr+aVzEvMswAo+oR81jN7IJElu
         16YA5drxoaLVgkcu9aRNY6UasslR5JX8rKpq1Ez1PGAyGmCn4kOBzazUof88ROZgciJs
         bC81Qclt/DtpFAI+1a9H8zE6fnzjTOCmuk8LQF+55LXCz5JSqQIQ2uulIRg1MwF7VlAz
         tpPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=hzgFscSkKJLnLb/YRxWRHyP++pn4h5ZyO8xrwVe7p3E=;
        fh=Qf2lQaBjDNXfvqeE8JAzaXUSPjCgnXS706XrLOdMMS8=;
        b=MwmkTT2L9tGlecf2reQ24REM0oR6Mc7zNSp7gwlrmAAPH6+sGkk+Sy+D0F5oA7TUt0
         VAgF+8j6NIDeOP8H/X6ZEPc3Hg5MHfmMvan+5yrNCY31c+QeauEcoYgBxzqg8OO6Km34
         WG4fEB1bMW4PD2yT8Iz4WUtxv0eVV0/j58J/1t5BIIvIJdaaXkTvIdSfqwGT6PYDWutf
         FBCuICSQXgdJ9mYxDrl4hymio5vGluNGtrwHoUZyhoLSYKOBpq+JfC6QLOBdMzc6HgcM
         /Ihmp4C7g/m00ulBfl5Iw9ew0RCUVpAmr5KzeyqLxU86mo7vPCclSQkddwhsJmtNDsRD
         b8yQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706536031; x=1707140831; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=hzgFscSkKJLnLb/YRxWRHyP++pn4h5ZyO8xrwVe7p3E=;
        b=T0CWOwyxNpEXxbDvmokngtbNR/VfQ7Gmf39Bwd+T7ux+7k+ze3c/E10/VRHi8mIJ30
         oJluXvof6kirNrD3win1cPYWPMbweWou8adbkgEwxGvFwtGeiBGIYGgWDpxHHuk24Blh
         kUOeDmOlNps0vYHNttTRAmA2ma+CVT59mNjn0O6Vm/nCgRo8GqgEHc3HFyFGJoHzj/SD
         VQYD0bN6QHdeMphY0/gpkTvJ4rm147Ysm5HICE+B9//Ei1CJt6FQ+NM3LHUlDRLE7FTZ
         qXupYoXYQNpY1Rm0EGuMKejkNSd47rKONSulSmeAc3lOoXl8PI5SudUxPEKYQLlsTPq/
         zqmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706536031; x=1707140831;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hzgFscSkKJLnLb/YRxWRHyP++pn4h5ZyO8xrwVe7p3E=;
        b=VrhorCGebSliPmkPSvBB1O/pBy7QLbP8BBoYgPiwE7XK0OeVv7es2972svaaMB7DZj
         RCGjzoux6Y2kyINhMndErZk2ZKnXYEaQ0COmFiHt4pB9+bOx5G52uH7r1CF9wzaRLYxI
         ghZWi7VjMZbVAxkWJ1eL8tKvBzltqyXvIWKN+pN8krr29TZVHRS+ggUMjgcXcTMzpfMs
         bDU7BsBP9puO9IcRUAAE214CHBRkLL2Oq5TX/Wz3AQ05Yg5k8rqfLwwTvBndA4J6HKRG
         0ND6k0gT3/Ga/icaANoWD/9+rJptTI7sHOQB+c0j3rMW3v8cZ2nOGvFpXbP7HZnsgZYH
         0mHQ==
X-Gm-Message-State: AOJu0YzJQZ2kRfJ5UKF4w2pFcFTCn513kdp4zblYsmKn+gLnYeOfNkC4
	Xql2CX9sId6dEX3Vnmt1IgK0mEQx4BE7Oc1LJl/YdmRq4Wef/N9r
X-Google-Smtp-Source: AGHT+IEIFXfL2s9+Pi88ZmdGv5ykjM+2X1rWP9PBfsTYhusLR5pbBjWSY9LRb16vmvgvXs7HXzFEYA==
X-Received: by 2002:a05:6870:6707:b0:214:a640:7a25 with SMTP id gb7-20020a056870670700b00214a6407a25mr5537452oab.3.1706536030898;
        Mon, 29 Jan 2024 05:47:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:ab8a:b0:214:ff3f:9c9f with SMTP id
 gs10-20020a056870ab8a00b00214ff3f9c9fls3812212oab.0.-pod-prod-07-us; Mon, 29
 Jan 2024 05:47:10 -0800 (PST)
X-Received: by 2002:a05:6871:b0f:b0:210:cccd:19fd with SMTP id fq15-20020a0568710b0f00b00210cccd19fdmr5088603oab.44.1706536030127;
        Mon, 29 Jan 2024 05:47:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706536030; cv=none;
        d=google.com; s=arc-20160816;
        b=ajJwKK62d3HpptG655D7FNSGt9MsXQkyZts7nqOm9owut1+DLjE5MQgYO+8qDJrgox
         QJXVbVodWmwvA0JqDeE6SLsr3ic7YJjUEuKunRjFBDicvK3L2o8c8H6n5J4mpJR33Xcr
         kBqF9PFMJE/JeHn9mCFLNmV4akVU/w0FxqNmKc9VXh+ufZHI+xAVnB2E7gmekWmhjafO
         zR9+GPIBJdwDyYFCFDeapWFGkNNI+vvUr3ck8kqDZIiC5nQ+OhfVjmhdPpokMBeca815
         3wVfpKEzzJHzNM4+YTTQuBc37yTYj3mgpM7kqzykMsBtxHLesG9xefpHoDy7MOIITWC2
         6Mog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=CCAT8rx4o8lYXQE9KbI4VDb/mpKWJwivRgZ4wGraeu8=;
        fh=Qf2lQaBjDNXfvqeE8JAzaXUSPjCgnXS706XrLOdMMS8=;
        b=vJbhBSY0akwi9qOsGzWaKETJ+TupKYexjM4qOEjh3M3smZNwe5J9dHc2RYtPNdD7eg
         sIaSpKdX3uy7Mat6dVYr+y8uPY1okR+0lke+PnhEFF9lDFKHR/lLXgNKD07/pY4aealN
         l7fWZM5EaoijVnYh9Ho9oPq+NBwjTFPykQFEmkZUs+bMAbJ+KY2LCcGw7f8k04aUyRAu
         qewJANUsdBqbLfsvPhrWtKu3q0otC5R/hfosZD33IK/rrCvQPvET6u/vo//8/TDL8TKt
         goD0F4EL4uElb6qRj12HDClXsYxzIJo+n0DXUb8sVNDOfEc4+eOtqSmGOTEYGVv06dWJ
         IdDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Forwarded-Encrypted: i=0; AJvYcCURgZZcZkr8tpwxcAJ+8O0qOQhvLdXKQBVjQu5TojEQN5Sz4RecrmPVW00P0mZL6EVw9WRVDHJPD9Wk20BH5m4M+oADExYni4xBUQ==
Received: from szxga04-in.huawei.com (szxga04-in.huawei.com. [45.249.212.190])
        by gmr-mx.google.com with ESMTPS id gh22-20020a0568703b1600b0021868acb041si467081oab.4.2024.01.29.05.47.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Jan 2024 05:47:10 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) client-ip=45.249.212.190;
Received: from mail.maildlp.com (unknown [172.19.162.112])
	by szxga04-in.huawei.com (SkyGuard) with ESMTP id 4TNqMP4rlkz1xmlr;
	Mon, 29 Jan 2024 21:46:09 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (unknown [7.193.23.234])
	by mail.maildlp.com (Postfix) with ESMTPS id 957621404DB;
	Mon, 29 Jan 2024 21:47:07 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Mon, 29 Jan 2024 21:47:05 +0800
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>, James Morse <james.morse@arm.com>, Robin
 Murphy <robin.murphy@arm.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Alexander Viro
	<viro@zeniv.linux.org.uk>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>, Michael Ellerman
	<mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Christophe Leroy
	<christophe.leroy@csgroup.eu>, Aneesh Kumar K.V <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>, Thomas Gleixner
	<tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov
	<bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, <x86@kernel.org>,
	"H. Peter Anvin" <hpa@zytor.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Tong Tiangen <tongtiangen@huawei.com>,
	<wangkefeng.wang@huawei.com>, Guohanjun <guohanjun@huawei.com>
Subject: [PATCH v10 6/6] arm64: introduce copy_mc_to_kernel() implementation
Date: Mon, 29 Jan 2024 21:46:52 +0800
Message-ID: <20240129134652.4004931-7-tongtiangen@huawei.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240129134652.4004931-1-tongtiangen@huawei.com>
References: <20240129134652.4004931-1-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as
 permitted sender) smtp.mailfrom=tongtiangen@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Tong Tiangen <tongtiangen@huawei.com>
Reply-To: Tong Tiangen <tongtiangen@huawei.com>
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

The copy_mc_to_kernel() helper is memory copy implementation that handles
source exceptions. It can be used in memory copy scenarios that tolerate
hardware memory errors(e.g: pmem_read/dax_copy_to_iter).

Currnently, only x86 and ppc suuport this helper, after arm64 support
machine check safe framework, we introduce copy_mc_to_kernel()
implementation.

Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
---
 arch/arm64/include/asm/string.h  |   5 +
 arch/arm64/include/asm/uaccess.h |  21 +++
 arch/arm64/lib/Makefile          |   2 +-
 arch/arm64/lib/memcpy_mc.S       | 257 +++++++++++++++++++++++++++++++
 mm/kasan/shadow.c                |  12 ++
 5 files changed, 296 insertions(+), 1 deletion(-)
 create mode 100644 arch/arm64/lib/memcpy_mc.S

diff --git a/arch/arm64/include/asm/string.h b/arch/arm64/include/asm/string.h
index 3a3264ff47b9..995b63c26e99 100644
--- a/arch/arm64/include/asm/string.h
+++ b/arch/arm64/include/asm/string.h
@@ -35,6 +35,10 @@ extern void *memchr(const void *, int, __kernel_size_t);
 extern void *memcpy(void *, const void *, __kernel_size_t);
 extern void *__memcpy(void *, const void *, __kernel_size_t);
 
+#define __HAVE_ARCH_MEMCPY_MC
+extern int memcpy_mcs(void *, const void *, __kernel_size_t);
+extern int __memcpy_mcs(void *, const void *, __kernel_size_t);
+
 #define __HAVE_ARCH_MEMMOVE
 extern void *memmove(void *, const void *, __kernel_size_t);
 extern void *__memmove(void *, const void *, __kernel_size_t);
@@ -57,6 +61,7 @@ void memcpy_flushcache(void *dst, const void *src, size_t cnt);
  */
 
 #define memcpy(dst, src, len) __memcpy(dst, src, len)
+#define memcpy_mcs(dst, src, len) __memcpy_mcs(dst, src, len)
 #define memmove(dst, src, len) __memmove(dst, src, len)
 #define memset(s, c, n) __memset(s, c, n)
 
diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 14be5000c5a0..61e28ef2112a 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -425,4 +425,25 @@ static inline size_t probe_subpage_writeable(const char __user *uaddr,
 
 #endif /* CONFIG_ARCH_HAS_SUBPAGE_FAULTS */
 
+#ifdef CONFIG_ARCH_HAS_COPY_MC
+/**
+ * copy_mc_to_kernel - memory copy that handles source exceptions
+ *
+ * @dst:	destination address
+ * @src:	source address
+ * @len:	number of bytes to copy
+ *
+ * Return 0 for success, or #size if there was an exception.
+ */
+static inline unsigned long __must_check
+copy_mc_to_kernel(void *to, const void *from, unsigned long size)
+{
+	int ret;
+
+	ret = memcpy_mcs(to, from, size);
+	return (ret == -EFAULT) ? size : 0;
+}
+#define copy_mc_to_kernel copy_mc_to_kernel
+#endif
+
 #endif /* __ASM_UACCESS_H */
diff --git a/arch/arm64/lib/Makefile b/arch/arm64/lib/Makefile
index a2fd865b816d..899d6ae9698c 100644
--- a/arch/arm64/lib/Makefile
+++ b/arch/arm64/lib/Makefile
@@ -3,7 +3,7 @@ lib-y		:= clear_user.o delay.o copy_from_user.o		\
 		   copy_to_user.o copy_page.o				\
 		   clear_page.o csum.o insn.o memchr.o memcpy.o		\
 		   memset.o memcmp.o strcmp.o strncmp.o strlen.o	\
-		   strnlen.o strchr.o strrchr.o tishift.o
+		   strnlen.o strchr.o strrchr.o tishift.o memcpy_mc.o
 
 ifeq ($(CONFIG_KERNEL_MODE_NEON), y)
 obj-$(CONFIG_XOR_BLOCKS)	+= xor-neon.o
diff --git a/arch/arm64/lib/memcpy_mc.S b/arch/arm64/lib/memcpy_mc.S
new file mode 100644
index 000000000000..7076b500d154
--- /dev/null
+++ b/arch/arm64/lib/memcpy_mc.S
@@ -0,0 +1,257 @@
+/* SPDX-License-Identifier: GPL-2.0-only */
+/*
+ * Copyright (c) 2012-2021, Arm Limited.
+ *
+ * Adapted from the original at:
+ * https://github.com/ARM-software/optimized-routines/blob/afd6244a1f8d9229/string/aarch64/memcpy.S
+ */
+
+#include <linux/linkage.h>
+#include <asm/assembler.h>
+
+/* Assumptions:
+ *
+ * ARMv8-a, AArch64, unaligned accesses.
+ *
+ */
+
+#define L(label) .L ## label
+
+#define dstin	x0
+#define src	x1
+#define count	x2
+#define dst	x3
+#define srcend	x4
+#define dstend	x5
+#define A_l	x6
+#define A_lw	w6
+#define A_h	x7
+#define B_l	x8
+#define B_lw	w8
+#define B_h	x9
+#define C_l	x10
+#define C_lw	w10
+#define C_h	x11
+#define D_l	x12
+#define D_h	x13
+#define E_l	x14
+#define E_h	x15
+#define F_l	x16
+#define F_h	x17
+#define G_l	count
+#define G_h	dst
+#define H_l	src
+#define H_h	srcend
+#define tmp1	x14
+
+/* This implementation handles overlaps and supports both memcpy and memmove
+   from a single entry point.  It uses unaligned accesses and branchless
+   sequences to keep the code small, simple and improve performance.
+
+   Copies are split into 3 main cases: small copies of up to 32 bytes, medium
+   copies of up to 128 bytes, and large copies.  The overhead of the overlap
+   check is negligible since it is only required for large copies.
+
+   Large copies use a software pipelined loop processing 64 bytes per iteration.
+   The destination pointer is 16-byte aligned to minimize unaligned accesses.
+   The loop tail is handled by always copying 64 bytes from the end.
+*/
+
+SYM_FUNC_START(__pi_memcpy_mcs)
+	add	srcend, src, count
+	add	dstend, dstin, count
+	cmp	count, 128
+	b.hi	L(copy_long)
+	cmp	count, 32
+	b.hi	L(copy32_128)
+
+	/* Small copies: 0..32 bytes.  */
+	cmp	count, 16
+	b.lo	L(copy16)
+	CPY_MC(9998f, ldp	A_l, A_h, [src])
+	CPY_MC(9998f, ldp	D_l, D_h, [srcend, -16])
+	CPY_MC(9998f, stp	A_l, A_h, [dstin])
+	CPY_MC(9998f, stp	D_l, D_h, [dstend, -16])
+	mov x0, #0
+	ret
+
+	/* Copy 8-15 bytes.  */
+L(copy16):
+	tbz	count, 3, L(copy8)
+	CPY_MC(9998f, ldr	A_l, [src])
+	CPY_MC(9998f, ldr	A_h, [srcend, -8])
+	CPY_MC(9998f, str	A_l, [dstin])
+	CPY_MC(9998f, str	A_h, [dstend, -8])
+	mov x0, #0
+	ret
+
+	.p2align 3
+	/* Copy 4-7 bytes.  */
+L(copy8):
+	tbz	count, 2, L(copy4)
+	CPY_MC(9998f, ldr	A_lw, [src])
+	CPY_MC(9998f, ldr	B_lw, [srcend, -4])
+	CPY_MC(9998f, str	A_lw, [dstin])
+	CPY_MC(9998f, str	B_lw, [dstend, -4])
+	mov x0, #0
+	ret
+
+	/* Copy 0..3 bytes using a branchless sequence.  */
+L(copy4):
+	cbz	count, L(copy0)
+	lsr	tmp1, count, 1
+	CPY_MC(9998f, ldrb	A_lw, [src])
+	CPY_MC(9998f, ldrb	C_lw, [srcend, -1])
+	CPY_MC(9998f, ldrb	B_lw, [src, tmp1])
+	CPY_MC(9998f, strb	A_lw, [dstin])
+	CPY_MC(9998f, strb	B_lw, [dstin, tmp1])
+	CPY_MC(9998f, strb	C_lw, [dstend, -1])
+L(copy0):
+	mov x0, #0
+	ret
+
+	.p2align 4
+	/* Medium copies: 33..128 bytes.  */
+L(copy32_128):
+	CPY_MC(9998f, ldp	A_l, A_h, [src])
+	CPY_MC(9998f, ldp	B_l, B_h, [src, 16])
+	CPY_MC(9998f, ldp	C_l, C_h, [srcend, -32])
+	CPY_MC(9998f, ldp	D_l, D_h, [srcend, -16])
+	cmp	count, 64
+	b.hi	L(copy128)
+	CPY_MC(9998f, stp	A_l, A_h, [dstin])
+	CPY_MC(9998f, stp	B_l, B_h, [dstin, 16])
+	CPY_MC(9998f, stp	C_l, C_h, [dstend, -32])
+	CPY_MC(9998f, stp	D_l, D_h, [dstend, -16])
+	mov x0, #0
+	ret
+
+	.p2align 4
+	/* Copy 65..128 bytes.  */
+L(copy128):
+	CPY_MC(9998f, ldp	E_l, E_h, [src, 32])
+	CPY_MC(9998f, ldp	F_l, F_h, [src, 48])
+	cmp	count, 96
+	b.ls	L(copy96)
+	CPY_MC(9998f, ldp	G_l, G_h, [srcend, -64])
+	CPY_MC(9998f, ldp	H_l, H_h, [srcend, -48])
+	CPY_MC(9998f, stp	G_l, G_h, [dstend, -64])
+	CPY_MC(9998f, stp	H_l, H_h, [dstend, -48])
+L(copy96):
+	CPY_MC(9998f, stp	A_l, A_h, [dstin])
+	CPY_MC(9998f, stp	B_l, B_h, [dstin, 16])
+	CPY_MC(9998f, stp	E_l, E_h, [dstin, 32])
+	CPY_MC(9998f, stp	F_l, F_h, [dstin, 48])
+	CPY_MC(9998f, stp	C_l, C_h, [dstend, -32])
+	CPY_MC(9998f, stp	D_l, D_h, [dstend, -16])
+	mov x0, #0
+	ret
+
+	.p2align 4
+	/* Copy more than 128 bytes.  */
+L(copy_long):
+	/* Use backwards copy if there is an overlap.  */
+	sub	tmp1, dstin, src
+	cbz	tmp1, L(copy0)
+	cmp	tmp1, count
+	b.lo	L(copy_long_backwards)
+
+	/* Copy 16 bytes and then align dst to 16-byte alignment.  */
+
+	CPY_MC(9998f, ldp	D_l, D_h, [src])
+	and	tmp1, dstin, 15
+	bic	dst, dstin, 15
+	sub	src, src, tmp1
+	add	count, count, tmp1	/* Count is now 16 too large.  */
+	CPY_MC(9998f, ldp	A_l, A_h, [src, 16])
+	CPY_MC(9998f, stp	D_l, D_h, [dstin])
+	CPY_MC(9998f, ldp	B_l, B_h, [src, 32])
+	CPY_MC(9998f, ldp	C_l, C_h, [src, 48])
+	CPY_MC(9998f, ldp	D_l, D_h, [src, 64]!)
+	subs	count, count, 128 + 16	/* Test and readjust count.  */
+	b.ls	L(copy64_from_end)
+
+L(loop64):
+	CPY_MC(9998f, stp	A_l, A_h, [dst, 16])
+	CPY_MC(9998f, ldp	A_l, A_h, [src, 16])
+	CPY_MC(9998f, stp	B_l, B_h, [dst, 32])
+	CPY_MC(9998f, ldp	B_l, B_h, [src, 32])
+	CPY_MC(9998f, stp	C_l, C_h, [dst, 48])
+	CPY_MC(9998f, ldp	C_l, C_h, [src, 48])
+	CPY_MC(9998f, stp	D_l, D_h, [dst, 64]!)
+	CPY_MC(9998f, ldp	D_l, D_h, [src, 64]!)
+	subs	count, count, 64
+	b.hi	L(loop64)
+
+	/* Write the last iteration and copy 64 bytes from the end.  */
+L(copy64_from_end):
+	CPY_MC(9998f, ldp	E_l, E_h, [srcend, -64])
+	CPY_MC(9998f, stp	A_l, A_h, [dst, 16])
+	CPY_MC(9998f, ldp	A_l, A_h, [srcend, -48])
+	CPY_MC(9998f, stp	B_l, B_h, [dst, 32])
+	CPY_MC(9998f, ldp	B_l, B_h, [srcend, -32])
+	CPY_MC(9998f, stp	C_l, C_h, [dst, 48])
+	CPY_MC(9998f, ldp	C_l, C_h, [srcend, -16])
+	CPY_MC(9998f, stp	D_l, D_h, [dst, 64])
+	CPY_MC(9998f, stp	E_l, E_h, [dstend, -64])
+	CPY_MC(9998f, stp	A_l, A_h, [dstend, -48])
+	CPY_MC(9998f, stp	B_l, B_h, [dstend, -32])
+	CPY_MC(9998f, stp	C_l, C_h, [dstend, -16])
+	mov x0, #0
+	ret
+
+	.p2align 4
+
+	/* Large backwards copy for overlapping copies.
+	   Copy 16 bytes and then align dst to 16-byte alignment.  */
+L(copy_long_backwards):
+	CPY_MC(9998f, ldp	D_l, D_h, [srcend, -16])
+	and	tmp1, dstend, 15
+	sub	srcend, srcend, tmp1
+	sub	count, count, tmp1
+	CPY_MC(9998f, ldp	A_l, A_h, [srcend, -16])
+	CPY_MC(9998f, stp	D_l, D_h, [dstend, -16])
+	CPY_MC(9998f, ldp	B_l, B_h, [srcend, -32])
+	CPY_MC(9998f, ldp	C_l, C_h, [srcend, -48])
+	CPY_MC(9998f, ldp	D_l, D_h, [srcend, -64]!)
+	sub	dstend, dstend, tmp1
+	subs	count, count, 128
+	b.ls	L(copy64_from_start)
+
+L(loop64_backwards):
+	CPY_MC(9998f, stp	A_l, A_h, [dstend, -16])
+	CPY_MC(9998f, ldp	A_l, A_h, [srcend, -16])
+	CPY_MC(9998f, stp	B_l, B_h, [dstend, -32])
+	CPY_MC(9998f, ldp	B_l, B_h, [srcend, -32])
+	CPY_MC(9998f, stp	C_l, C_h, [dstend, -48])
+	CPY_MC(9998f, ldp	C_l, C_h, [srcend, -48])
+	CPY_MC(9998f, stp	D_l, D_h, [dstend, -64]!)
+	CPY_MC(9998f, ldp	D_l, D_h, [srcend, -64]!)
+	subs	count, count, 64
+	b.hi	L(loop64_backwards)
+
+	/* Write the last iteration and copy 64 bytes from the start.  */
+L(copy64_from_start):
+	CPY_MC(9998f, ldp	G_l, G_h, [src, 48])
+	CPY_MC(9998f, stp	A_l, A_h, [dstend, -16])
+	CPY_MC(9998f, ldp	A_l, A_h, [src, 32])
+	CPY_MC(9998f, stp	B_l, B_h, [dstend, -32])
+	CPY_MC(9998f, ldp	B_l, B_h, [src, 16])
+	CPY_MC(9998f, stp	C_l, C_h, [dstend, -48])
+	CPY_MC(9998f, ldp	C_l, C_h, [src])
+	CPY_MC(9998f, stp	D_l, D_h, [dstend, -64])
+	CPY_MC(9998f, stp	G_l, G_h, [dstin, 48])
+	CPY_MC(9998f, stp	A_l, A_h, [dstin, 32])
+	CPY_MC(9998f, stp	B_l, B_h, [dstin, 16])
+	CPY_MC(9998f, stp	C_l, C_h, [dstin])
+	mov x0, #0
+	ret
+
+9998:	mov x0, #-EFAULT
+	ret
+SYM_FUNC_END(__pi_memcpy_mcs)
+
+SYM_FUNC_ALIAS(__memcpy_mcs, __pi_memcpy_mcs)
+EXPORT_SYMBOL(__memcpy_mcs)
+SYM_FUNC_ALIAS_WEAK(memcpy_mcs, __memcpy_mcs)
+EXPORT_SYMBOL(memcpy_mcs)
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 9ef84f31833f..e6519fd329b2 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -79,6 +79,18 @@ void *memcpy(void *dest, const void *src, size_t len)
 }
 #endif
 
+#ifdef __HAVE_ARCH_MEMCPY_MC
+#undef memcpy_mcs
+int memcpy_mcs(void *dest, const void *src, size_t len)
+{
+	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
+	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
+		return (unsigned long)len;
+
+	return __memcpy_mcs(dest, src, len);
+}
+#endif
+
 void *__asan_memset(void *addr, int c, ssize_t len)
 {
 	if (!kasan_check_range(addr, len, true, _RET_IP_))
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240129134652.4004931-7-tongtiangen%40huawei.com.
