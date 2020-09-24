Return-Path: <kasan-dev+bncBDX4HWEMTEBRBB6GWT5QKGQE7JMB5TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id DA3C9277BE5
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:52 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id q12sf361441pjg.9
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987911; cv=pass;
        d=google.com; s=arc-20160816;
        b=f13xX06wtoJMkn4A/y4Gc49IxO2/s+qpciCGDvgSCc4okOFg20FSmJ4zZvrn3KaWza
         6DTHiLdkBfqAuq0NF60fCYFD2iAGrD8RHZawGsVZI0W/tXFrbmkw2Z5tFdzjedylOQAj
         KesPzg/8QF7l0iw1Qn3wy1JPvWMvrq1PAUTvESqwXi6zE2wdJt4o/v8hlLPept2Ek808
         3YLdtWDEf4yDRAmrS6Rso6ElkeabIra7EGBVLXjnLFkRaZn0B2lnDu1oqM+2Zs9AfR1X
         RnGGSmW/rWfbyil34NF9jCySOvcAw1KNwrJBFO2qef6M+HzEY6v4jYzAIgZBijaUIFpS
         rDIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Nno+2jSf1lQirvD52IWV/8fyhzIo47jaANyA09ES3qA=;
        b=rjWFDGtHnCYlix+/Vm1Ua4OF+ahXmGw9pUjF8z5G+cgy5H2QHEHkicXu/i79Jtwl9r
         kO1Qh9vznkM/CtuuWbjeIQSXpU9q49A4BSiOs19FjYVKWKXFXla+7PFQJPFEfexkJECh
         AN+PmpZJ96ONQXGdqrWNwFGyqLHlGK/dyw44bKqfvaUQUQOvGIp3JLpLOQIk+JjAc/dR
         qxqObY07awonj0Y8hwqUQOCOJRMROLBg9xmNXC0+ke9TlUPTSPjiMGjiDDsv4O+iwREW
         wxMFnImUs/plHATQHkojVvBf/HO6YS1CjZdFCiXmGxlkbu3dWLOP+aE21Lx3ClQxo4/J
         XeXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QaNn3Q1s;
       spf=pass (google.com: domain of 3bintxwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3BiNtXwoKCQMdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Nno+2jSf1lQirvD52IWV/8fyhzIo47jaANyA09ES3qA=;
        b=S3sugozddiyfqftVzFBN2jwDlwE0Wv+DyUCg8E+CSG64bxMIStmXSOMLy31v5mvELX
         aIW39WnF8AtL+JbGbKwMg7TM0uu6YeUbJXBGynipjOuhkWz5iNsdgNcrLcpBt+l2Ph0F
         Hyw0ZUXPt8Y2XKTVi4phb2/ulUa+yA+huui7z4lw56/0EVslro46sky3dlnTucVm+GIG
         WHU/ahDL86dRLW1AIzySRj8Yt2ppIbweDIbrXd0MFRI6BKtmv9mjhZ4APzbELChM7MVi
         8TwuheaqvFq8DIMbLGZ5aVdfsrl2zKK7l0BH0V0NGUU+eatR7McPjXAA+0d1Bs7uoaUa
         myAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nno+2jSf1lQirvD52IWV/8fyhzIo47jaANyA09ES3qA=;
        b=FT+8S1NNlDJcZVFGgKhEp+/xTuEgQwZDUS6d/i0J54aM9t4F6AQnyg8cLw/tcUhc0s
         8ayUsS5Gy9l/d008QCjBdSMN1JDJMRB8gwrIT+jn0N3gh4fRh2abLMzdUceznrbn+Ijd
         RfV2nv5mdwGirBfHZi8wv0wUSrKP2pWpzKe74JDm1UZod0RfZhnZhPRbb3helcR9WbIS
         t/Uk82/rMUzJGWdSnxi0UIWxuWHleyWnUtg6OAtxY2dyQVLjO8sK74/M+F5Xr4gNUvLC
         IVPr+dKlVB/KfAZPtPeUUBlO9r0DdSNK9Eb39v+WHbFpnj1zetqey8xI6ee/vAOcojKO
         ucjQ==
X-Gm-Message-State: AOAM533jpReF6KMKWjA1gKWLGh4gm0FQBTW1pBiD1o5s/C9SFNkGuZAg
	ApwEOFQLznXvbAWGX0h4Qi4=
X-Google-Smtp-Source: ABdhPJxPqIKi4ez2uMdknezWewp+7xEB9vn0WC8O87O7miQUmNSgUnSFkcXfq6jPp1E/ukBtA5R1yQ==
X-Received: by 2002:a17:90b:46c4:: with SMTP id jx4mr1129872pjb.190.1600987911644;
        Thu, 24 Sep 2020 15:51:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c7d3:: with SMTP id gf19ls324447pjb.0.canary-gmail;
 Thu, 24 Sep 2020 15:51:51 -0700 (PDT)
X-Received: by 2002:a17:902:bb8c:b029:d2:2503:e458 with SMTP id m12-20020a170902bb8cb02900d22503e458mr1385296pls.18.1600987911067;
        Thu, 24 Sep 2020 15:51:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987911; cv=none;
        d=google.com; s=arc-20160816;
        b=r8tkdodAvrAvkNu56hlL2ibWCM922o4alYd66OVSiKfPHyzH7bKgFTDjjUhRaHBt2Q
         vv0HE1zvV8Ub64XlVx62J1/2KQuurx82sa0yLxz3PVrBlS7eJHa33/65CvL9SqWV0YQ7
         2RaCdJxusD0HZrt3URYBM7EMcZGwKGs9Qi8O1izDSFWJ2bWXbK7sw6f1Q4qv3pGwKFV5
         yBqyedc8j+XOkXFteyUXG7OwCKt7/w5Hj5CoG/PBJfHhnPXfOIbdquHX9HTHvWdsCfOZ
         NFjxJBS8qbxKuVg3FkgubuBjW0yrRbgbu5mfy9Fej5QfmZF27gJyx7QUuIiszEJBeNUF
         z/Dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=fTQzr3b/f/Y2f2WUZm2mA8+YP+UMaet6Rq3JBXSottg=;
        b=Smh+t7HDL8/GnJOQXs9TtzGrE7MwwGJMJTt+ZqqUWKTgIroExJemaan4mcvGSvHQR8
         IbzWHJdHkuj57on78oRxxXNCBvU1rUJI9wkQ5N/snc3nThD0Y0SkialayIzu4h7vYBDc
         iNf80U/eIM1LjbQWzNimfGZoSuoWJ+q1hfWbwze0lXK9ZaWJ0Q5YWkz/rgyv+iv/MluL
         +FtGUrjKc9k1S8QUlCnpiZy4Bp8piZzYg2R57ELvmV2ID1LoVpwmZh8guTPBwDQqm/08
         ggT3utjx9J4Qd198bkNuY/gg8/JcclIjGF4REhk5GdySf/J7DQw8MzU9BbvskpTjNB+2
         +i0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QaNn3Q1s;
       spf=pass (google.com: domain of 3bintxwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3BiNtXwoKCQMdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id d3si54392pld.1.2020.09.24.15.51.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bintxwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id w2so466529qvr.19
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:51 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:58aa:: with SMTP id
 ea10mr1647878qvb.58.1600987910123; Thu, 24 Sep 2020 15:51:50 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:31 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <ae603463aed82bdff74942f23338a681b8ed8820.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 24/39] arm64: mte: Add in-kernel MTE helpers
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
 header.i=@google.com header.s=20161025 header.b=QaNn3Q1s;       spf=pass
 (google.com: domain of 3bintxwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3BiNtXwoKCQMdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
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
 arch/arm64/include/asm/mte-kasan.h | 60 ++++++++++++++++++++++++++++++
 arch/arm64/include/asm/mte.h       | 17 ++++++---
 arch/arm64/kernel/mte.c            | 44 ++++++++++++++++++++++
 arch/arm64/lib/mte.S               | 19 ++++++++++
 5 files changed, 135 insertions(+), 6 deletions(-)
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
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
new file mode 100644
index 000000000000..b0f27de8de33
--- /dev/null
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -0,0 +1,60 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Copyright (C) 2020 ARM Ltd.
+ */
+#ifndef __ASM_MTE_ASM_H
+#define __ASM_MTE_ASM_H
+
+#include <asm/compiler.h>
+
+#define __MTE_PREAMBLE		ARM64_ASM_PREAMBLE ".arch_extension memtag\n"
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
+static inline u8 mte_get_ptr_tag(void *ptr)
+{
+	u8 tag = (u8)(((u64)(ptr)) >> MTE_TAG_SHIFT);
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
+#endif /* __ASM_MTE_ASM_H  */
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 1c99fcadb58c..3a2bf3ccb26c 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -5,14 +5,13 @@
 #ifndef __ASM_MTE_H
 #define __ASM_MTE_H
 
-#define MTE_GRANULE_SIZE	UL(16)
-#define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
-#define MTE_TAG_SHIFT		56
-#define MTE_TAG_SIZE		4
+#include <asm/mte-kasan.h>
 
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
index 52a0638ed967..833b63fdd5e2 100644
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
@@ -72,6 +74,48 @@ int memcmp_pages(struct page *page1, struct page *page2)
 	return ret;
 }
 
+u8 mte_get_mem_tag(void *addr)
+{
+	if (!system_supports_mte())
+		return 0xFF;
+
+	asm volatile(__MTE_PREAMBLE "ldg %0, [%0]"
+		    : "+r" (addr));
+
+	return 0xF0 | mte_get_ptr_tag(addr);
+}
+
+u8 mte_get_random_tag(void)
+{
+	void *addr;
+
+	if (!system_supports_mte())
+		return 0xFF;
+
+	asm volatile(__MTE_PREAMBLE "irg %0, %0"
+		    : "+r" (addr));
+
+	return 0xF0 | mte_get_ptr_tag(addr);
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
index 03ca6d8b8670..aa0ab01252fe 100644
--- a/arch/arm64/lib/mte.S
+++ b/arch/arm64/lib/mte.S
@@ -149,3 +149,22 @@ SYM_FUNC_START(mte_restore_page_tags)
 
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
+	/* if (size == 0) return; */
+	cbz	x1, 2f
+1:	stg	x0, [x0]
+	add	x0, x0, #MTE_GRANULE_SIZE
+	subs	x1, x1, #MTE_GRANULE_SIZE
+	b.gt	1b
+2:	ret
+SYM_FUNC_END(mte_assign_mem_tag_range)
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ae603463aed82bdff74942f23338a681b8ed8820.1600987622.git.andreyknvl%40google.com.
