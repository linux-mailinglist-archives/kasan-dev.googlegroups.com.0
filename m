Return-Path: <kasan-dev+bncBAABB45S3G5AMGQEBSY3NVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E5109E894F
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Dec 2024 03:44:04 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6d8fe8a0371sf23312946d6.1
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Dec 2024 18:44:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733712243; cv=pass;
        d=google.com; s=arc-20240605;
        b=I++KvdCtEX4/Grf3Plp3EN8RANpS42nPpQCBGLjl1xbgzDEA145usg8xtUInNh8kMD
         3pPFMQWTosavqWVmOnAEsZGFw0RQ89CWIuykZsuQwU+sC0tzMvSLm8fpef8pmVZ3nX/O
         dWmRs5TANabXrDPypq7jq8l95tlZUszk0MBIgmhwzNhySIiI7saTQeUEWSp2eONYLuSR
         jtwy7wji9z+jxX4yvpC9bjLmaFwqP3sNRiRKWFFfDP9bt5uzzf4Orm7MlxGKHeAtERdY
         fUMVxYQsQBenQmII9OEX1chtHCnm05GlyFZxk7jZbwUsw1of/DUXiEOu3ymmR8fXMo7n
         m4Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=dkRFCz5Oz4YtBQ0E22dH6rhLCBpZLDGjJ2tSuELTygk=;
        fh=gbHQ30TL3rWhQTTBK1Uo3MbdxiHUEi1TKv1GEcdiebM=;
        b=QCkqskpk21BRiemEKnVmwOkfBIPEKjZ36iULzJDCf9Uv74MDKDxes4c0IkpPg5bH1H
         o0wqp8Jpu5tYcEq1NcfPqkFmv201bIdejgO28cA+N0gtasrJKtaHQ3cO6G88m6Bd228i
         6nri7/BHgielgnTkIYoi2f77ok1ZLNZ/PMM2aKgQy8YMB5fL6YJUOOPUy6s+I9bgUziq
         0+DKtdip9tgPV6FzL+hn1VJGg0IY1cqqnkHN2IKsMlTtvCf3SASYtvE839A0URAkLJ53
         yaFDX4HwGp/3vwZYLf5V0iLJ1F6091sbHcLQjjRccR/pbhYhCLE5lz7kTNbhpRImlqrb
         QSjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733712243; x=1734317043; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dkRFCz5Oz4YtBQ0E22dH6rhLCBpZLDGjJ2tSuELTygk=;
        b=r5KKTd3uPSqWOP74xSGv+AAOgG9umWqTtGudqnBs1mSo+7z4JuOGNr+rkkoA7yhH9s
         k6wxxg1HYzqL2RyI08Ix/CK6LKAhtcmQHp18/1WJ5EogjCID6Ba8YZ93wbx6bUj67lHY
         xu0HCIx6C6QUS4Q4/qJFjyXdvYZh7kTFffQrUuA8e3D+vD1vHL4WxoKw6Yf1KoGz1nfY
         VaHoxhe2a76m5pDg8UWyscC9x0dVkVVLcWxTACH8OaKi1TsB8a0tRD8M6mQEBuLSNtJ5
         O2QZLH72TJOfGm3tw0UinXbkwvhqoIoLSfRD0D+s9CF9hHeqpa4a7sq3em8whLiT5Rbt
         Wn6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733712243; x=1734317043;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dkRFCz5Oz4YtBQ0E22dH6rhLCBpZLDGjJ2tSuELTygk=;
        b=JAiATNQ7J3lLbhVpqEF/GWwd99SnmS+Mapj2LEtCouw1Ak6VYasHLe/HZzu3Tnv1vC
         qSL3wOPbGRCPCjKlQ9CkM0IcX2EskKWkVYM/0jy9+hBRdgLazap8J585slClYUAg9WyM
         U3Q7dEsXijcih9QSrpWKlDJgMQJfIFwhw4JL7OsuSKrdCUu1z0BnozmMgf3n6TbK3cOh
         XHAuQ068MTmhFkikY62ebOby1vo2jSkuD/XMIq3OOcpnGmdVV5Crzk9R5L0D0Lw2eRfq
         kuUejSNLrWBy8KrhFuOLSDed9SmIscdjBHGQacvBBcehACDDMaP2o6qEs+BdDivsjjBL
         74cw==
X-Forwarded-Encrypted: i=2; AJvYcCVk/VtUB8ep3Lao8o5KuCVYn5tgK12hZk+THCQHMStFPWT3SkOHpnS6MDMxLQVpPmkHEJJuoA==@lfdr.de
X-Gm-Message-State: AOJu0YzOoD/NfJ7VYEFERl3KoF/k7rjiARryf38+9hrkc7cgXzbE2oGS
	o2V0yP6+4RTvxfpHdgcO/6e4ut8NfmPz1qHZmSoM6oTFFeTu3Bm9
X-Google-Smtp-Source: AGHT+IHjZ+bR3rv+WrEWg3SshW/7YaN9lVRzylMDg0e+n/xKYDQbVpoOPb27uuhrIy8m6ajQkd570w==
X-Received: by 2002:a05:6214:d44:b0:6d4:586:6292 with SMTP id 6a1803df08f44-6d8e717d01cmr169876466d6.26.1733712243236;
        Sun, 08 Dec 2024 18:44:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:d6d:b0:6cb:be88:c825 with SMTP id
 6a1803df08f44-6d8f9d490cals27575566d6.0.-pod-prod-05-us; Sun, 08 Dec 2024
 18:44:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWGJAq8GbMmnbfhIbcByyk98YRXLWRFez6g/4yOp2xaxhiSKcK02Pz/ZrUTSCwFRduIAsJybGykfw8=@googlegroups.com
X-Received: by 2002:a05:6102:32ca:b0:4af:eed0:91f1 with SMTP id ada2fe7eead31-4afeed0a218mr2675991137.13.1733712242622;
        Sun, 08 Dec 2024 18:44:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733712242; cv=none;
        d=google.com; s=arc-20240605;
        b=gFvVaCCwNob9xwXD2ZtptToLzyM5+Ksu4D7lB9W5TvDVP2bzM/vBo/PlComccJnYgq
         QxUzM0OqEdwAT+PEP9El/YW0OnchEP1JlHKK1B2ppbE2T9sBuuU6wVW37dZ9kVadnOV5
         X4Utd5X+cOj72M8cJ7Od8z98lwSjn3PWjc7TJFplfBIcc6pErP37VYBS2UktOCEABY9t
         PpiDWeFLxOaIUzl/PacivHojuk+4H6H0myNPyf9jdtsiDTKFVHsZFicp7Kf6CMFiDFsB
         P2uO/1taE+MomvZImrUn7Q6gCEcx7F3HGPLTwYMtNEVPm/7fyCEmRJpi6tPkr4QGyo4Y
         lNzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=3LXOxUklyNgf5lug7zsMwusW92Er0cLCd2wPgXWZ91s=;
        fh=zBWha3m7j9g4fOlI2Dk54gN6qyAThRjo4Lp4VAY4w1U=;
        b=EBQ8azAyWFj0WcM4kFAQp8TURTxLwGyUkM3y3giwgL3DXWgSLjZhg0waAF32TKt0Vy
         SG+mT1O/20GwNjAgLxP7ua7egKFJ/LqTOwvyIiTUrOd92IiZIvS37Oegz0sXKkM6C+ya
         E57GPKigbHsih+6IlH/9mFpRozLx9SJiJY/cOUHbE3w50yi0VNHZKXSQVtE6mBSV1VM+
         JakvLxwRjVvcFlxDJzkMT7f29+P3m22KY+dgG1dy+dDySNnXAAcm6Xr0Y9+k2gzyO214
         OYvVZhUOuNNuiTKaVeLNrytsvqmVPTN3LHLFoSBKtoSFTa5VP6L+1JvICU7ZeObKCXmz
         SMQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga05-in.huawei.com (szxga05-in.huawei.com. [45.249.212.191])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-85c2bc8f161si307918241.1.2024.12.08.18.44.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 Dec 2024 18:44:02 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.191 as permitted sender) client-ip=45.249.212.191;
Received: from mail.maildlp.com (unknown [172.19.88.234])
	by szxga05-in.huawei.com (SkyGuard) with ESMTP id 4Y65hf0h34z1kvfy;
	Mon,  9 Dec 2024 10:41:06 +0800 (CST)
Received: from kwepemk500005.china.huawei.com (unknown [7.202.194.90])
	by mail.maildlp.com (Postfix) with ESMTPS id A318F14010C;
	Mon,  9 Dec 2024 10:43:28 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemk500005.china.huawei.com (7.202.194.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.11; Mon, 9 Dec 2024 10:43:26 +0800
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mark Rutland <mark.rutland@arm.com>, Jonathan Cameron
	<Jonathan.Cameron@Huawei.com>, Mauro Carvalho Chehab
	<mchehab+huawei@kernel.org>, Catalin Marinas <catalin.marinas@arm.com>, Will
 Deacon <will@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, James
 Morse <james.morse@arm.com>, Robin Murphy <robin.murphy@arm.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Michael Ellerman
	<mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Christophe
 Leroy <christophe.leroy@csgroup.eu>, Aneesh Kumar K.V
	<aneesh.kumar@kernel.org>, "Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
	<x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, Madhavan Srinivasan
	<maddy@linux.ibm.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Tong Tiangen <tongtiangen@huawei.com>,
	<wangkefeng.wang@huawei.com>, Guohanjun <guohanjun@huawei.com>
Subject: [PATCH v13 5/5] arm64: introduce copy_mc_to_kernel() implementation
Date: Mon, 9 Dec 2024 10:42:57 +0800
Message-ID: <20241209024257.3618492-6-tongtiangen@huawei.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20241209024257.3618492-1-tongtiangen@huawei.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 kwepemk500005.china.huawei.com (7.202.194.90)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.191 as
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

Currently, only x86 and ppc support this helper, Add this for ARM64 as
well, if ARCH_HAS_COPY_MC is defined, by implementing copy_mc_to_kernel()
and memcpy_mc() functions.

Because there is no caller-saved GPR is available for saving "bytes not
copied" in memcpy(), the memcpy_mc() is referenced to the implementation
of copy_from_user(). In addition, the fixup of MOPS insn is not considered
at present.

Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
---
 arch/arm64/include/asm/string.h  |  5 ++
 arch/arm64/include/asm/uaccess.h | 18 ++++++
 arch/arm64/lib/Makefile          |  2 +-
 arch/arm64/lib/memcpy_mc.S       | 98 ++++++++++++++++++++++++++++++++
 mm/kasan/shadow.c                | 12 ++++
 5 files changed, 134 insertions(+), 1 deletion(-)
 create mode 100644 arch/arm64/lib/memcpy_mc.S

diff --git a/arch/arm64/include/asm/string.h b/arch/arm64/include/asm/string.h
index 3a3264ff47b9..23eca4fb24fa 100644
--- a/arch/arm64/include/asm/string.h
+++ b/arch/arm64/include/asm/string.h
@@ -35,6 +35,10 @@ extern void *memchr(const void *, int, __kernel_size_t);
 extern void *memcpy(void *, const void *, __kernel_size_t);
 extern void *__memcpy(void *, const void *, __kernel_size_t);
 
+#define __HAVE_ARCH_MEMCPY_MC
+extern int memcpy_mc(void *, const void *, __kernel_size_t);
+extern int __memcpy_mc(void *, const void *, __kernel_size_t);
+
 #define __HAVE_ARCH_MEMMOVE
 extern void *memmove(void *, const void *, __kernel_size_t);
 extern void *__memmove(void *, const void *, __kernel_size_t);
@@ -57,6 +61,7 @@ void memcpy_flushcache(void *dst, const void *src, size_t cnt);
  */
 
 #define memcpy(dst, src, len) __memcpy(dst, src, len)
+#define memcpy_mc(dst, src, len) __memcpy_mc(dst, src, len)
 #define memmove(dst, src, len) __memmove(dst, src, len)
 #define memset(s, c, n) __memset(s, c, n)
 
diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 5b91803201ef..2a14b732306a 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -542,4 +542,22 @@ static inline void put_user_gcs(unsigned long val, unsigned long __user *addr,
 
 #endif /* CONFIG_ARM64_GCS */
 
+#ifdef CONFIG_ARCH_HAS_COPY_MC
+/**
+ * copy_mc_to_kernel - memory copy that handles source exceptions
+ *
+ * @to:		destination address
+ * @from:	source address
+ * @size:	number of bytes to copy
+ *
+ * Return 0 for success, or bytes not copied.
+ */
+static inline unsigned long __must_check
+copy_mc_to_kernel(void *to, const void *from, unsigned long size)
+{
+	return memcpy_mc(to, from, size);
+}
+#define copy_mc_to_kernel copy_mc_to_kernel
+#endif
+
 #endif /* __ASM_UACCESS_H */
diff --git a/arch/arm64/lib/Makefile b/arch/arm64/lib/Makefile
index 78b0e9904689..326d71ba0517 100644
--- a/arch/arm64/lib/Makefile
+++ b/arch/arm64/lib/Makefile
@@ -13,7 +13,7 @@ endif
 
 lib-$(CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE) += uaccess_flushcache.o
 
-lib-$(CONFIG_ARCH_HAS_COPY_MC) += copy_mc_page.o
+lib-$(CONFIG_ARCH_HAS_COPY_MC) += copy_mc_page.o memcpy_mc.o
 
 obj-$(CONFIG_CRC32) += crc32.o crc32-glue.o
 
diff --git a/arch/arm64/lib/memcpy_mc.S b/arch/arm64/lib/memcpy_mc.S
new file mode 100644
index 000000000000..cb9caaa1ab0b
--- /dev/null
+++ b/arch/arm64/lib/memcpy_mc.S
@@ -0,0 +1,98 @@
+/* SPDX-License-Identifier: GPL-2.0-only */
+/*
+ * Copyright (C) 2013 ARM Ltd.
+ * Copyright (C) 2013 Linaro.
+ *
+ * This code is based on glibc cortex strings work originally authored by Linaro
+ * be found @
+ *
+ * http://bazaar.launchpad.net/~linaro-toolchain-dev/cortex-strings/trunk/
+ * files/head:/src/aarch64/
+ */
+
+#include <linux/linkage.h>
+#include <asm/assembler.h>
+#include <asm/cache.h>
+#include <asm/asm-uaccess.h>
+
+/*
+ * Copy a buffer from src to dest (alignment handled by the hardware)
+ *
+ * Parameters:
+ *	x0 - dest
+ *	x1 - src
+ *	x2 - n
+ * Returns:
+ *	x0 - bytes not copied
+ */
+	.macro ldrb1 reg, ptr, val
+	KERNEL_MEM_ERR(9997f, ldrb  \reg, [\ptr], \val)
+	.endm
+
+	.macro strb1 reg, ptr, val
+	strb \reg, [\ptr], \val
+	.endm
+
+	.macro ldrh1 reg, ptr, val
+	KERNEL_MEM_ERR(9997f, ldrh  \reg, [\ptr], \val)
+	.endm
+
+	.macro strh1 reg, ptr, val
+	strh \reg, [\ptr], \val
+	.endm
+
+	.macro ldr1 reg, ptr, val
+	KERNEL_MEM_ERR(9997f, ldr \reg, [\ptr], \val)
+	.endm
+
+	.macro str1 reg, ptr, val
+	str \reg, [\ptr], \val
+	.endm
+
+	.macro ldp1 reg1, reg2, ptr, val
+	KERNEL_MEM_ERR(9997f, ldp \reg1, \reg2, [\ptr], \val)
+	.endm
+
+	.macro stp1 reg1, reg2, ptr, val
+	stp \reg1, \reg2, [\ptr], \val
+	.endm
+
+end	.req	x5
+SYM_FUNC_START(__memcpy_mc_generic)
+	add	end, x0, x2
+#include "copy_template.S"
+	mov	x0, #0				// Nothing to copy
+	ret
+
+	// Exception fixups
+9997:	sub	x0, end, dst			// bytes not copied
+	ret
+SYM_FUNC_END(__memcpy_mc_generic)
+
+#ifdef CONFIG_AS_HAS_MOPS
+	.arch_extension mops
+SYM_FUNC_START(__memcpy_mc)
+alternative_if_not ARM64_HAS_MOPS
+	b       __memcpy_mc_generic
+alternative_else_nop_endif
+
+dstin   .req    x0
+src     .req    x1
+count   .req    x2
+dst     .req    x3
+
+	mov     dst, dstin
+	cpyp    [dst]!, [src]!, count!
+	cpym    [dst]!, [src]!, count!
+	cpye    [dst]!, [src]!, count!
+
+	mov	x0, #0				// Nothing to copy
+	ret
+SYM_FUNC_END(__memcpy_mc)
+#else
+SYM_FUNC_ALIAS(__memcpy_mc, __memcpy_mc_generic)
+#endif
+
+EXPORT_SYMBOL(__memcpy_mc)
+SYM_FUNC_ALIAS_WEAK(memcpy_mc, __memcpy_mc)
+EXPORT_SYMBOL(memcpy_mc)
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 88d1c9dcb507..a12770fb2e9c 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -79,6 +79,18 @@ void *memcpy(void *dest, const void *src, size_t len)
 }
 #endif
 
+#ifdef __HAVE_ARCH_MEMCPY_MC
+#undef memcpy_mc
+int memcpy_mc(void *dest, const void *src, size_t len)
+{
+	if (!kasan_check_range(src, len, false, _RET_IP_) ||
+	    !kasan_check_range(dest, len, true, _RET_IP_))
+		return (int)len;
+
+	return __memcpy_mc(dest, src, len);
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241209024257.3618492-6-tongtiangen%40huawei.com.
