Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBL4K3X7QKGQEASMCS5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 86D402ED5A2
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jan 2021 18:30:24 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id x4sf5270020oia.8
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jan 2021 09:30:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610040623; cv=pass;
        d=google.com; s=arc-20160816;
        b=M7EpSyjHW2o3F2C2B7eMJjsdFscW5F5BStTHjLZNhwf5uCQssL6LwnNK4T8a7HHuWU
         XgL7mOp6Y1pnXVgDbrE2178oVhmAKUDA3mkySuj2sJfm0UHR6t6DPcS7e1boXEegENBs
         FNEZdLZxI4Lznxvmtu85koaQGoBQsx6YHi1tia4XNlDltFlkaOCihR0lSEkCj/46ISiv
         08cJ8YpK1klSbY/2TLcyzCr0cM1/88lXLoQ8tCaDppIXEdfark7A9hnA6qr3ovjSt8xK
         K2wqCez2oYg4KP/iExLMl+D9fvyxyglWeCOJOX+UNDTJ+FwFTs2KCeap5lX0PGI31vZ1
         1KKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8G9C8CtpxPMdXvTDGpAoePXiHmfmVlqxMYLU3d0JZ5w=;
        b=x3wH4GxKfNG8UgOfU/Mr6xQpIS3d+upoau0jgDxzhHLMXM1yjSIkBZMS0PQx75+hde
         eT1zMqRQ5SVeN6qMZCXzOfBkQWsqqwkHed4iuAP1b1M+G00VrEUah80ecE1OEZYvlFSU
         iJeYpms7Rg/pDxCJBLXgsWsV3UtNK6CRj8SUm94zqpoj3rSgHyX73R/Yq2sMH24zdg7Z
         jILFTk1LJDLIu04N0S4XqJD9dTWMTAKAZ2BMTzgSp/PUD7JvmYwmXMi4LGc7Itg9nVsp
         iKrMXXXWWaLaSBHUgFa9PRQCM9w5QLRk+nSkulPbJ3O14MupKnO7fLwysKy/M92jkOAi
         LAhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8G9C8CtpxPMdXvTDGpAoePXiHmfmVlqxMYLU3d0JZ5w=;
        b=mMhsgoHzrr2zPMFa9PXyFr9EDNgpVyjHyLzuuOlJVpmSIfCRQmuTcwuUnyYXRF9Iip
         DReoXXdhH62qAQFYHWphOunRNiQWxxmBXN/8Bk4/zwI4AXmZwPTdZUGV0LDhhSwps3L9
         FyYkJyIhNZQ8f72Q74kgmUlg5lf//qBKNXTcFwQPx/uKq56/XWT+V/WJ0bTRIJN1SWn3
         NBM/3kmyVpPC+Plb2v5Ild2w07b0RCQm5ymlEdSDyAh5ioiQV1CxBAEtxHr6pidaBczU
         hP04jJwmB2ZM0N5H+tL1F1jvlUHKLMUkinN0uUbaMthu7m0QXRjRzIYZgNZU9UbCUfA7
         VQWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8G9C8CtpxPMdXvTDGpAoePXiHmfmVlqxMYLU3d0JZ5w=;
        b=UVE8LB7XicZ9G2F/10VihMYKQ7cqfZiuXjX5KCXJOnKlW+C9erkSjN//lO6XgxhyKA
         xALihSjnGEvrRemJnXZr91HiAqiYukX9gghB/dVwg18mjJ/BFeZCw5o4QziIP/X7IfEF
         jg6PPpN5OchgKliLDD3eoK1tLqlgv3HPvVLU8EbN2ktvSKgUJWSTELp445akY2ZcnoDF
         ASPA8aKWoLVpXTAy2RJwLhDCMcazPsCr6/jHsp8Q+ju7CHgZ/l3Nj29yr/DKyYPlq+2v
         7N5vx9a13Oxksd+MYOVhRN1MU/J6l0/lfpyra6uWqJVOOv3wdP4cQWuiLCULIomS068X
         U6Pg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532AaWS+r9CR+Yv39MSMUJERGmsLgiP8QOid5ZdHqGokVhUmAmL2
	d1MPaKh8F4o+AMRvbqhHhUc=
X-Google-Smtp-Source: ABdhPJwyErRuHFEM+zyl0qpi6hKBUkwfRku25T3Lz/1ETQTlVITpVsOIbCOg+Dki7u29o9z5hkvdvA==
X-Received: by 2002:aca:c30b:: with SMTP id t11mr7361294oif.61.1610040623292;
        Thu, 07 Jan 2021 09:30:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:331:: with SMTP id 46ls2103825otv.7.gmail; Thu, 07 Jan
 2021 09:30:23 -0800 (PST)
X-Received: by 2002:a05:6830:1d6b:: with SMTP id l11mr7279080oti.170.1610040622989;
        Thu, 07 Jan 2021 09:30:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610040622; cv=none;
        d=google.com; s=arc-20160816;
        b=SvwhTbqmjb4Sut5f8pjXhcLtgT2g/R0O4RU+RZcCiP3KKhrorThfMPWWU6+bu1BR+D
         7HdLtFiDxMRoM3iUOmVVljtR4z0z7vjDm5f8jiVvJ/Unx2G6iheiJMeH68lAVJ4pEQly
         tRSUUosTDJr41mlceZv87/K0jMDleECgSVb8i3HMMfRtUh4hP0EGF27Z+EPRcqmvQlec
         oMeDjKiMUgfuvBXqI2cmD2GDOFuadJMT2n+AIyhgCgmOOGfJ7zdxRg89SNOENzLVhWAj
         p9N5J7lHKPOH5XIL1QAgJvh4GutSpjO3T3aDunw9zaixwOxL+ck6Ey1Cd08xLPrqPTCm
         8HmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=A7dRfvvnorO5T4qUXPOONNEKGf/3hijHBYRGk1/Eho8=;
        b=ClaWhixyd94rWI2YAARYBF8z1Oh1kzqNoQ6JAq9Poj72gY2Ag+PgXnMwzXozTKarMu
         caynnl3fgNznZErTGM+ANFdFQpJGepEmH5V7rarr4nr06QUIwOf7jH273/vr98aG87kR
         1tGcMxmwtKvv7ASf4rDVwDzTe+QvjjEpeX6rg1uPvqzpt6J1HudswiCYJA6G0T9U+qfv
         /HC2kUt3zQWduwUXPsdul/TKqWKUMEm9fT3aT5QGN/izKMxDJhzOoy9w6PFauT+vUIzn
         HeQBqFRhPTQ7wLF+UifN1eQUw3TRmtqMxpbAOcFCaH7oFSQACdbT1qNmpK3Gx8Z4go9n
         lTkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id u2si919115otg.1.2021.01.07.09.30.22
        for <kasan-dev@googlegroups.com>;
        Thu, 07 Jan 2021 09:30:22 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A4EE0ED1;
	Thu,  7 Jan 2021 09:30:22 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id EAA443F719;
	Thu,  7 Jan 2021 09:30:20 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 1/4] kasan, arm64: Add KASAN light mode
Date: Thu,  7 Jan 2021 17:29:05 +0000
Message-Id: <20210107172908.42686-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210107172908.42686-1-vincenzo.frascino@arm.com>
References: <20210107172908.42686-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Content-Type: text/plain; charset="UTF-8"
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

Architectures supported by KASAN HW can provide a light mode of
execution. On an MTE enabled arm64 hw for example this can be identified
with the asynch mode of execution. If an async exception occurs, the
arm64 core updates a register which is asynchronously detected the next
time in which the kernel is accessed.

KASAN requires a specific mode of execution to make use of this hw feature.

Add KASAN HW light execution mode.

Note: This patch adds the KASAN_ARG_MODE_LIGHT config option and the
"light" kernel command line option to enable the described feature.
This patch introduces the kasan_def.h header to make easier to propagate
the relevant enumerations to the architectural code.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h    |  2 +-
 arch/arm64/include/asm/mte-kasan.h |  5 +++--
 arch/arm64/kernel/mte.c            |  2 +-
 include/linux/kasan.h              |  1 +
 include/linux/kasan_def.h          | 25 +++++++++++++++++++++++++
 mm/kasan/hw_tags.c                 | 24 ++++--------------------
 mm/kasan/kasan.h                   |  2 +-
 7 files changed, 36 insertions(+), 25 deletions(-)
 create mode 100644 include/linux/kasan_def.h

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 18fce223b67b..3a7c5beb7096 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -231,7 +231,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
-#define arch_enable_tagging()			mte_enable_kernel()
+#define arch_enable_tagging(mode)		mte_enable_kernel(mode)
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
 #define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 26349a4b5e2e..79e612c31186 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -9,6 +9,7 @@
 
 #ifndef __ASSEMBLY__
 
+#include <linux/kasan_def.h>
 #include <linux/types.h>
 
 /*
@@ -29,7 +30,7 @@ u8 mte_get_mem_tag(void *addr);
 u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
-void mte_enable_kernel(void);
+void mte_enable_kernel(enum kasan_arg_mode mode);
 void mte_init_tags(u64 max_tag);
 
 #else /* CONFIG_ARM64_MTE */
@@ -52,7 +53,7 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return addr;
 }
 
-static inline void mte_enable_kernel(void)
+static inline void mte_enable_kernel(enum kasan_arg_mode mode)
 {
 }
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index dc9ada64feed..24a273d47df1 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -151,7 +151,7 @@ void mte_init_tags(u64 max_tag)
 	write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
 }
 
-void mte_enable_kernel(void)
+void mte_enable_kernel(enum kasan_arg_mode mode)
 {
 	/* Enable MTE Sync Mode for EL1. */
 	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 5e0655fb2a6f..026031444217 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -2,6 +2,7 @@
 #ifndef _LINUX_KASAN_H
 #define _LINUX_KASAN_H
 
+#include <linux/kasan_def.h>
 #include <linux/static_key.h>
 #include <linux/types.h>
 
diff --git a/include/linux/kasan_def.h b/include/linux/kasan_def.h
new file mode 100644
index 000000000000..e774b0122980
--- /dev/null
+++ b/include/linux/kasan_def.h
@@ -0,0 +1,25 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _LINUX_KASAN_DEF_H
+#define _LINUX_KASAN_DEF_H
+
+enum kasan_arg_mode {
+	KASAN_ARG_MODE_DEFAULT,
+	KASAN_ARG_MODE_OFF,
+	KASAN_ARG_MODE_LIGHT,
+	KASAN_ARG_MODE_PROD,
+	KASAN_ARG_MODE_FULL,
+};
+
+enum kasan_arg_stacktrace {
+	KASAN_ARG_STACKTRACE_DEFAULT,
+	KASAN_ARG_STACKTRACE_OFF,
+	KASAN_ARG_STACKTRACE_ON,
+};
+
+enum kasan_arg_fault {
+	KASAN_ARG_FAULT_DEFAULT,
+	KASAN_ARG_FAULT_REPORT,
+	KASAN_ARG_FAULT_PANIC,
+};
+
+#endif /* _LINUX_KASAN_DEF_H */
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 55bd6f09c70f..d5c6ad8b2c44 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -19,25 +19,6 @@
 
 #include "kasan.h"
 
-enum kasan_arg_mode {
-	KASAN_ARG_MODE_DEFAULT,
-	KASAN_ARG_MODE_OFF,
-	KASAN_ARG_MODE_PROD,
-	KASAN_ARG_MODE_FULL,
-};
-
-enum kasan_arg_stacktrace {
-	KASAN_ARG_STACKTRACE_DEFAULT,
-	KASAN_ARG_STACKTRACE_OFF,
-	KASAN_ARG_STACKTRACE_ON,
-};
-
-enum kasan_arg_fault {
-	KASAN_ARG_FAULT_DEFAULT,
-	KASAN_ARG_FAULT_REPORT,
-	KASAN_ARG_FAULT_PANIC,
-};
-
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
 static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
@@ -60,6 +41,8 @@ static int __init early_kasan_mode(char *arg)
 
 	if (!strcmp(arg, "off"))
 		kasan_arg_mode = KASAN_ARG_MODE_OFF;
+	else if (!strcmp(arg, "light"))
+		kasan_arg_mode = KASAN_ARG_MODE_LIGHT;
 	else if (!strcmp(arg, "prod"))
 		kasan_arg_mode = KASAN_ARG_MODE_PROD;
 	else if (!strcmp(arg, "full"))
@@ -118,7 +101,7 @@ void kasan_init_hw_tags_cpu(void)
 		return;
 
 	hw_init_tags(KASAN_TAG_MAX);
-	hw_enable_tagging();
+	hw_enable_tagging(kasan_arg_mode);
 }
 
 /* kasan_init_hw_tags() is called once on boot CPU. */
@@ -145,6 +128,7 @@ void __init kasan_init_hw_tags(void)
 	case KASAN_ARG_MODE_OFF:
 		/* If KASAN is disabled, do nothing. */
 		return;
+	case KASAN_ARG_MODE_LIGHT:
 	case KASAN_ARG_MODE_PROD:
 		static_branch_enable(&kasan_flag_enabled);
 		break;
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index cc4d9e1d49b1..78c09279327e 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -284,7 +284,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
 #endif
 
-#define hw_enable_tagging()			arch_enable_tagging()
+#define hw_enable_tagging(mode)			arch_enable_tagging(mode)
 #define hw_init_tags(max_tag)			arch_init_tags(max_tag)
 #define hw_get_random_tag()			arch_get_random_tag()
 #define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210107172908.42686-2-vincenzo.frascino%40arm.com.
