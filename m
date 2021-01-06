Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB6OK237QKGQETYA4ZUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id F1F8C2EBD59
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jan 2021 12:56:42 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id t23sf1629221ioh.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jan 2021 03:56:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609934201; cv=pass;
        d=google.com; s=arc-20160816;
        b=hWWOb7UcLl0es0uZeU1A622GY6s8ouRSYx+GLJI/4RW7FJJ37QlwWyddcRTrHeI/VO
         ebd+fVA5UP8SxkK9K0BCsTU0d0AzLCt7kEyFNRy1S99ZW/UYvdNDvCOFq4xXTlDJYgZi
         +QbIi7xQEW9dYn4LbWLcjFo4KagC3FwJwzpPw7TaYSBK+tpsfEGaFZvYR9WiYkg59VO4
         smtavxObiL+6RQ6cuXcpxyJkU981MEGErv+00nUxnNWD9PnuW/HGZ/kgHoPXZavFG4s8
         af2pIY5+GpXcAOzTsSCEkZa3hre8qIDz8oefkutyQ2nTrUwWYqwe5+crb2CNNEuU4qsQ
         sC+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZHweyMuWnziPi6KI3nUpJQ9gbVnlQsY0ZHDliurTxLw=;
        b=tm1rB4fcQV+i4CQFgce0FynkAiUj5TQ2XHu3CmcYxuAxtPTgy/DMwhsl0/OqRLHyC9
         8fNSnU6CCwRUAlUP554ETaoDVjqpuHHl96wzWEL+8/jPKPDgTtiN50SiDMqCn2KCRoqr
         oq79eTzfk+eXZljj5qfBi0nT+mS10W/p/hmUFGqScV3sljK//fUHJavg1BPYni4PoW57
         8WXLaGEUN/4WjCkLzv6jUtAN5vDjLZWCErQiGeSDD0MMgegtuALpmtDO5Z5achncZPlr
         +Wk16nEQf4VNfDk4Ly6wCVm1UHyrN172fl5AUdZmrYu2Cqhz06SdACbB8hPuTzf8BKwk
         2DtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZHweyMuWnziPi6KI3nUpJQ9gbVnlQsY0ZHDliurTxLw=;
        b=gh4ibni/HN5jsmlT/DQjuRLV+JsPdmaTkoGPxf6kVoiE8RkaGgdewZ2NEqhKz7jspi
         jvn1hTHbcIvreScslnUH00GtJzAqA2rv6hFRQCy7KgzLmwXKPmBlPGZSn2gyK+axovoK
         o92+bRov/Oc9OPuE5SAZJEnenJbNkfZanTkmljwDDDYN/qEEgiR7dcQw4aP900LwIH2X
         LTCSVqiyxS5t88L0DMJjMtYJDQx4pLzNiMlGtDMws32kg/lD/msY1mP96JWgzCkqgFyq
         ZA5pJ18Bj//udDe9DxdIkJSqp+hYxWXJ61ZU6zviRw9UyTS4bMhZeAJxkP3PnfpR7iMn
         7mrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZHweyMuWnziPi6KI3nUpJQ9gbVnlQsY0ZHDliurTxLw=;
        b=uehuwNhAZke/7XePqexhLnHN4uWU1MrfEcBklNDBpUlfMyhyVLq52cO5pW7F0AtAFP
         sPXE3Lt+pYSXBJ0R98ZbhgHPnrSKGPZ/kZWoG43law08mdcKR8ZN1zLYQ6rsPw7WzlDJ
         QZK1W4BiHYMzNU6LACvtuv+OPL1LTskyxkmeUX0pjdKH4r/9akL0tQ/0oB+Tn3T0LhtK
         id9O2ePFPNTqBmEXOnn9rkotsYPYWH9R5VsMbYScORTQQ2w5oVIKRp7A1RXPzZ2075ge
         JSCNAQmJSz274ALFlHFN8xweNq+zizBwApN6e4LExqBCJvrMdu1r/axgUL5PfpiV0R4n
         c3RA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530H4Uy4TJrjfUJvZ9THPjQd6IxwL8A2FLhzTppDU70F1m8NZfDU
	JMtEhcCc7E4AZy1tds3a9MA=
X-Google-Smtp-Source: ABdhPJwVlIeJ6DxNcXt678D1QvzuefbrHV0k2O9Jon8cSn0iqgxPUzcCOMpialwaQyqSTBCrbJV51A==
X-Received: by 2002:a92:ac08:: with SMTP id r8mr3684796ilh.166.1609934201650;
        Wed, 06 Jan 2021 03:56:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8c86:: with SMTP id g6ls387030ion.0.gmail; Wed, 06 Jan
 2021 03:56:41 -0800 (PST)
X-Received: by 2002:a6b:6810:: with SMTP id d16mr2593437ioc.100.1609934201235;
        Wed, 06 Jan 2021 03:56:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609934201; cv=none;
        d=google.com; s=arc-20160816;
        b=acB7N8qjl2w+SBDoi5xIV8DtH5kiJs+no6UyJPYEJzqvxvh+6o4dxYNRq5N9To8Klv
         juB2LuX5UEH997MZMuLUkGKtMUx7i881HBGo1oTi59dTZgGp41k4Kizxarvn1rh2a6qI
         R7lbQQmnoKTYPXypQyr9oH0r2EY+Z9zDjQl5TiBaWl1tD0LCZeFFIMEwFlpJ4LWosA3W
         ZTqS44O8zk1Y5cjYfF0qtOFd5tCr9RYE5PZbkmFHtZ1rcjcXU1NTOrsAaYBgad7hooXR
         URk84v83RVpIWzmBJ0Ar4p9RMt9Cz6uad4OcfBNWL5OKkHGF0r3f9AmshAYRx49TvQKZ
         b7Ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=E3L8DHcBGg+4h9DjQpNSceSPrRswALaBnXB8LzlzuPk=;
        b=FhXquf3r87C8B/+aeegnoRjlRnjjfEtnM2r1xJIoKLAWnoNqX6So7GWg2/S18h/SEs
         QBYENOWnpHodyXZEWvi6DOmAROVsuuxk5kiy0LTDd0Q5Z8Ln77qk3s8YcKwkfS6ZZ5VL
         nFPDcOb7kduN1Ek/7f3hXYarmD40/z8VU9jeKXFt3aXKvNra+x7J9xwqfJOU5UXIQI5i
         tUdDIabCgFukGqh0inW+OhK2YEmzS55PqWBlaxMm8hECeefMYs/vvHrb9+URKKLH3p1K
         XAMoDt80BVl1EWCPuzSggtvcJOQzsAy15s5dD3uVkpA+h+lvLxTiP84vnxrRFK1HVC2w
         gF0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i5si144737ilu.5.2021.01.06.03.56.41
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Jan 2021 03:56:41 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B099F106F;
	Wed,  6 Jan 2021 03:56:40 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 117583F70D;
	Wed,  6 Jan 2021 03:56:38 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 1/4] kasan, arm64: Add KASAN light mode
Date: Wed,  6 Jan 2021 11:55:16 +0000
Message-Id: <20210106115519.32222-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.29.2
In-Reply-To: <20210106115519.32222-1-vincenzo.frascino@arm.com>
References: <20210106115519.32222-1-vincenzo.frascino@arm.com>
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
 arch/arm64/include/asm/mte-kasan.h |  5 ++--
 arch/arm64/kernel/mte.c            |  2 +-
 include/linux/kasan.h              |  1 +
 include/linux/kasan_def.h          | 39 ++++++++++++++++++++++++++++++
 mm/kasan/hw_tags.c                 | 24 +++---------------
 mm/kasan/kasan.h                   |  2 +-
 7 files changed, 50 insertions(+), 25 deletions(-)
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
index 000000000000..5e2b3ea5472b
--- /dev/null
+++ b/include/linux/kasan_def.h
@@ -0,0 +1,39 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _LINUX_KASAN_DEF_H
+#define _LINUX_KASAN_DEF_H
+
+#ifdef CONFIG_KASAN
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
+#else
+enum kasan_arg_mode {
+	KASAN_ARG_MODE_DEFAULT,
+};
+
+enum kasan_arg_stacktrace {
+	KASAN_ARG_STACKTRACE_DEFAULT,
+};
+
+enum kasan_arg_fault {
+	KASAN_ARG_FAULT_DEFAULT,
+};
+#endif
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
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210106115519.32222-2-vincenzo.frascino%40arm.com.
