Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSUASP6AKGQEYRBTALI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FB2328C2DC
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:00 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id l12sf13442430qtu.22
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535498; cv=pass;
        d=google.com; s=arc-20160816;
        b=q0YVPcJM1YQC2ZyhRhvLGBkiaJOXX3TfTmZotLJix9l2I8kgYCurEFH7EgZfv9Pfm7
         E09VLmMFg1WwJGMAd0Q53qRQ6d1nrXVEHEk1nwnqqWU3iA69Jch8faArEdecS54md8+L
         uP2xq7hDroTY8JPb4tdijit8D8+QB9RnUPxs+rolLGsjNMoQ31cZ9y0Nt1owtetx3OTq
         xMVy7MRCv6No86kzgI7XM8Bqbpya8kZ10cZdZbnLu+7gVkKK/f8uwYeKhLncW62P2whG
         XlbiViNtqfMHoQ1a8WgXkoiRA1uO1JXWIQLhzCdKeEZiypbVuXpayfruym0ZS2apIpxY
         ksDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=8VMOnxJuAFAI1NlOWrzDpqAyPelxVDO6m4dOl6M+DDs=;
        b=uFo29ST53kb/MJI+1nJIVb8Ctm5/viXMrRUBK+h3hAMacaS5YP6HF1RifkFsfkbX+Q
         dQlLffd7ZXMiyPJJxbn8ZfRI+LA2/R+YKehHO6W1mtDvkGFwd1sJCcZc/0XFEvPcOaal
         0Stw/zat5elNdwfPPd9K2JNXcOvNMy+PO12dlsJRoOhjO9N0OumxAXarRPqhFykjM5oL
         TEjOa8Xx/iBxF9LkQIIHVfw2RpZ8y2wQeZ7xd0FBR7+kyVs0bIEorXPEEa3XE2OEGmT1
         tenaL/dnZtJMM2+GZIuZ8GKlyG01jWP6C+N++VDNiqcH71gqZ9YvtMn3+vgMQrqL4fSb
         WK4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AMrZ3EMA;
       spf=pass (google.com: domain of 3sccexwokcd4andreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ScCEXwoKCd4ANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8VMOnxJuAFAI1NlOWrzDpqAyPelxVDO6m4dOl6M+DDs=;
        b=Sy99QcsDirfrRv2CAT7YkRV8+vwe/uwCNV4uG7QqQWpAbMrnoDhSomoFax1OkWDI52
         wooCDvEf0Nr+rdIgY62Eype5mfI3KX27g7RVVYMQneCtO3OH6yEC5QGJ9SjqCZTb8UQ9
         VDlGzPJcWObHjwyvgt4MDhAxfLcLNWvm8+l/QQ4xFkNJklRBB3/D0Cd7bTnRIAFeKHHq
         B7cbYum6lsbKqGpk6QDR0iIWHJ0B7kq00eAl1s8li6M7FiioA0kinm3nEujh+alnORXp
         lYXFkrKM1gzRxCMTlUl7rUwvYcntvyB9RLVussu+uPIPU7WU0ep+xuCvXqpOYt4B4rZE
         AzNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8VMOnxJuAFAI1NlOWrzDpqAyPelxVDO6m4dOl6M+DDs=;
        b=agY9a5V3Z4V6i7gypGTFy5Bz+AyVa++B/Kk1o8At3zpSU6caQMOqcdj9feDIBNTrgV
         ULZ4r6ZyX51Gvn4hJcc/QG0ofcSvmMoCgBG83XxnfETPy9ENAppGxGRm/g2wnSM/PNyB
         QSyYicWAD6jNpMJ5yKOtXH6DqenEcB7K9Ez9mmVSjJmu+/lPdGkulTR/DPaKMiuJQWCd
         Ze6r1eObO9KFs7enNQo1YUGWGN0ShOAJ9o8La0wWEulMh3CV4c8Ys33XzfagQtJaxYMn
         PSL30MwRVdCHZzNPmX7WDMezjENoaaz5oYRiHREY+RlPgMZ8weQaTx9z6wgQMePTQdZf
         +DSg==
X-Gm-Message-State: AOAM531bFJQHGl55v/s06/vsIuJQbJxmAJBGrbkZMDcseAea4ye2d2R5
	4YdH/9wnzWwSYSINo3ctwMk=
X-Google-Smtp-Source: ABdhPJzrkgwArdIMbE0wGc8yjTTtMvbmUopIZ6J67d6xGmNvc+yVRsqQUT1whpJmY2NBpzYhJviu5w==
X-Received: by 2002:a05:620a:127c:: with SMTP id b28mr12028324qkl.491.1602535498493;
        Mon, 12 Oct 2020 13:44:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4721:: with SMTP id l1ls4341126qvz.2.gmail; Mon, 12 Oct
 2020 13:44:58 -0700 (PDT)
X-Received: by 2002:ad4:46a8:: with SMTP id br8mr26442076qvb.24.1602535498068;
        Mon, 12 Oct 2020 13:44:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535498; cv=none;
        d=google.com; s=arc-20160816;
        b=y+rvD777KusQDVjOkEEP9c68bqQUQJTaDEDFN1Iu/dYZWCqFRfJgaWQpErvVvHBZEY
         1uqF6yEwr03TeTR/NKMe7rN0NvDxGXH6Xr4J+3xwXyFPU3egF5J7Yq0RbSG7EXu/wmGr
         Eqe4/K92b28K0l4js+GycQQjyeeVoq9PUQQDRtDRMG82NFgMqP/DSsNAmaqPnlhnrT1T
         E8q9o01v03WUUkbtGWo2mcm6/w4K2MW8zsyrK5eynpekD0xXCzPcEbrpu/lVQWowmhDp
         eXqHe9dw2Ory0QHCSeHxa2Bu5Bgt0GFA8p7cVfP4F0FLeJsWufYqcEXosjxCWtYboSoa
         gwRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=2YuwFsyPoWR0tT86g3EMbRjUWeTYuejltLWeuL6WmRs=;
        b=Rg/m0YqGgiRnXsR71DZhrpD1GDPbYMCE41fk5ChPVkksjCioi+21j5yOrJoOKLqmQ1
         TCZtPiPfdCssQOJGgXTzEWMA8OjJRcOux2p7N//2djXKwaIMtbltGYPLv3k2JeMR8h1m
         jny74QOwfs/cXR/nFoKBGqT0shcK76eo8jGE2sQcN4L9FXFfT7rbJF1p1jaz9tvR1vT1
         rfJdgHSI2Ez6iAUIR8koueQysPbCv1xBi7a00HXHJ4B+9dq5fxVMP7Ji4RTuYGtluMDN
         HAPl/fDJ6UQQM0jynUwRwq9kvKwG1oJvH1cd3IdMAXckc3C3DeDPqRaOkm/+msg6dyYR
         Uc6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AMrZ3EMA;
       spf=pass (google.com: domain of 3sccexwokcd4andreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ScCEXwoKCd4ANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id v35si74483qtv.1.2020.10.12.13.44.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:44:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sccexwokcd4andreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id 7so13436667qtp.18
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:44:58 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5143:: with SMTP id
 g3mr25423632qvq.2.1602535497630; Mon, 12 Oct 2020 13:44:57 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:08 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <94dfda607f7f7a28a5df9ee68703922aa9a52a1e.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 02/40] arm64: mte: Add in-kernel MTE helpers
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
 header.i=@google.com header.s=20161025 header.b=AMrZ3EMA;       spf=pass
 (google.com: domain of 3sccexwokcd4andreyknvlgoogle.comkasan-devgooglegroups.com@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ScCEXwoKCd4ANDREYKNVLGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--andreyknvl.bounces.google.com;
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/94dfda607f7f7a28a5df9ee68703922aa9a52a1e.1602535397.git.andreyknvl%40google.com.
