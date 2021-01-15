Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB6EHQ2AAMGQEC4YFIOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F45E2F7825
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 13:00:57 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id a17sf7687388qko.11
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 04:00:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610712056; cv=pass;
        d=google.com; s=arc-20160816;
        b=aiKz87fdk+soIW4YGlIQ2BH25FTfNyCrJ73EJ/AbkQEOlipJl7mbj+DoVBWe6Ut1LA
         VcqSW01IbfA3HvSEPH90+yGCtGC+SLcC+zxRMp9o7TYekqsbXNKI+HxzIBAnWiuQ/cqR
         /yY61n51y64rBXllocrfhEJ1urgA9xY5sqverMfnDCzRQDxsei8OwgpcNtal12vv3Aec
         RYRw0xfyBt1Np54QCFAJxkQUTekphB9NvBRSpaQia2y/mjCiH75Shczqw/kiV+kd7cO6
         GjM2H+Zznlpoxsab0utkP0SjlYHfdiuz827bjWD9BdHSwZOT5a0NvNLzF1e18kKS8ql4
         v8iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=x982V7oNC/WXeJYHd3LetHtFcHNpaY/xg7Xc/x7yrrw=;
        b=oecgQm2ZQKd/XKP6f26rwhhE2ofYJR/yO7rLG11TbUYOUv1WRedWCu9CIWAY6IwQCy
         2aGq1ZqxxP2mVhXOxpGDMDPsNtAc7ofDFIJ/SYvDm50djXN7gU8Pcf3EzalaNTP6TAQr
         tvs1xEL0qo2yYqeiz16YyuPTAT9fwME8Gf/4Njq1ONYqzRU9wJXTyvkQs61h/GCAT4mn
         7a7chZpwm0HkT67eFFmnWY8+HrfdqKJjlRjxGldynAc0/v/mcaZo9yZQkoITtNuoLy4z
         q7K/qF1OTHgMBxYI5+4Yc9DzyInS2/xRFsJRfXTESuHaQkIM8Hnoa+M7tRV9/avY/gdp
         /E0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x982V7oNC/WXeJYHd3LetHtFcHNpaY/xg7Xc/x7yrrw=;
        b=SzHnWPj3ogmlp73HWVx8+bOZ4315JUmRh3gzt/g4emvFlpK3unw+wb/e4I6BRm4L4w
         RBOsi+Bac7kekE6FJiXzqI4Bsf61VI8J6huBX2UdeIaoc9p6So+BuYywH4Wydk8J749p
         t4PF+I4q9NZWW803N7GmrkSlyXITdFFmNc0Tc1tJ1bRgzXQ8rmweHeZssHasSV5bCZAS
         4F/hdsEhN08SNDjCtLpmPMAcJ1UmB/gOu7USifK7oKgt2fb0TA+SoZGBsw3JO7Q8IbNv
         aog3wC2Hq6An9mMLtOXk4kTGo2lHqGxrJ3VoQVzsYeRcLA8oUiHqgZZ0Vl+xR22tUTab
         nOIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x982V7oNC/WXeJYHd3LetHtFcHNpaY/xg7Xc/x7yrrw=;
        b=YjhLFYQhZSy7/BHr8DQNzTuvcQs1Cjt3b3o707cMriLF/J/NZXq/Mk3RmftES4bVkF
         IAhRBwnbhhOlGokJfrE8cEwpiLRTfw1RqNJcoVhZtP00VKeRN5bJRqP7LfFStAEYNnH5
         87+GOX62z8OCkMpxZwB/FLwVPC1Mq4DIpcmJwjZFs+/L5hlI1K1FTiKf1xG+5hVFZGPU
         jmusMrAeh1IRwBhqastu6j9kXgioUuv8PjrRsuE0WRAiiSsj/krnpbx6GkyIq1yb6mxj
         pIbTDm6OOPLue65asIOv5JtWtB1ErAuE3/DkParaexCel38lfndR98RlfLcULlnqvjNw
         Tgtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533g5PiSxkVKuHFb6y9O8NaYX8rfhaDgOGo1cdIt/L+UyPGi8uzA
	9VJnw1XQLP3NmgzRaPOdhHE=
X-Google-Smtp-Source: ABdhPJzt0W/AfD9qrndFBxFAFDB5fmmnThoDtJ/W00pB7tjM5Ny2xmufGigaTJ6tx7D5yhWEbAO62A==
X-Received: by 2002:a05:620a:81b:: with SMTP id s27mr11972429qks.385.1610712056162;
        Fri, 15 Jan 2021 04:00:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:205e:: with SMTP id d30ls4458249qka.3.gmail; Fri,
 15 Jan 2021 04:00:55 -0800 (PST)
X-Received: by 2002:a37:e108:: with SMTP id c8mr11948521qkm.305.1610712055745;
        Fri, 15 Jan 2021 04:00:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610712055; cv=none;
        d=google.com; s=arc-20160816;
        b=YPR27aVYa6jJOqTjhWx1zCDXY5V/9yf2rsZwXfOS0xldfS/LWTIqav5GOsXePAZgbA
         X9z7lEwkcpMdKqCk4IGvf878hPT2VUPRROIELBz4Js/8C97skN5YYgH+Py/MMqGri1Vk
         iPw+zYb5hpDlqJLMnKIX5yhukNoX//JsHjqMpOd8JxBXPFmEBZ89tUnBiM6usrwAWqqb
         UniMeBmLwOsxz2T8p0m39wA3yDpUhq6kXj2s+v6erbzRoNYSuaKpvqe7TNgrr+LdKPCu
         MAfpHoDLzRyT7KeUqgnT9DS+ZPb86eDD0+DxG1tTPHe95cPFEFaBfrsyE2BpNW/TxYfK
         Ir7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=3726wVWUbdgyKPYmdFgnPAyl+FUPPF0YQnYEPB7n/0E=;
        b=dGdEOBN4CRUhVppQ3cuVBDTf0VzVIyIvgqAqhnxVVWkzQcFpDGAc/4wFJVE5WehF9+
         iRtTSXBenWfTmpnDMYlimpWG94QEQWx8R1+DMBX9dWf5+KBnHCxXfKDplkzto4o0GM5W
         HIVhCHt4uvCZXM71nLCy/wVC/gexxu/6wNDGE423Y3DN76HtGDzAtZQ+G1dTLvfjipdc
         10YNWuxN8V0/g8A7aYTKwZ/oGG4DFdVvmurYcHIlP/aHu7/Pk3iHXI69LWC9W/mNcbM2
         PIVlfX3BouaMtnR5IJWok65rJkWqnzlsa3whsNAhxzUNBQ/yliqr3odFAWE48O9vSbgH
         d74Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z94si1095838qtc.0.2021.01.15.04.00.55
        for <kasan-dev@googlegroups.com>;
        Fri, 15 Jan 2021 04:00:55 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5777411B3;
	Fri, 15 Jan 2021 04:00:55 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id ACBD73F70D;
	Fri, 15 Jan 2021 04:00:53 -0800 (PST)
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
Subject: [PATCH v3 1/4] kasan, arm64: Add KASAN light mode
Date: Fri, 15 Jan 2021 12:00:40 +0000
Message-Id: <20210115120043.50023-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210115120043.50023-1-vincenzo.frascino@arm.com>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
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
with the asynch mode of execution.
In this mode, if a tag check fault occurs, the TFSR_EL1 register is
updated asynchronously. The kernel checks the corresponding bits
periodically.

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
 include/linux/kasan_def.h          | 10 ++++++++++
 mm/kasan/hw_tags.c                 | 19 ++++++++++++++++++-
 mm/kasan/kasan.h                   |  2 +-
 7 files changed, 35 insertions(+), 6 deletions(-)
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
index 26349a4b5e2e..5402f4c8e88d 100644
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
+void mte_enable_kernel(enum kasan_hw_tags_mode mode);
 void mte_init_tags(u64 max_tag);
 
 #else /* CONFIG_ARM64_MTE */
@@ -52,7 +53,7 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return addr;
 }
 
-static inline void mte_enable_kernel(void)
+static inline void mte_enable_kernel(enum kasan_hw_tags_mode mode)
 {
 }
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index dc9ada64feed..53a6d734e29b 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -151,7 +151,7 @@ void mte_init_tags(u64 max_tag)
 	write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
 }
 
-void mte_enable_kernel(void)
+void mte_enable_kernel(enum kasan_hw_tags_mode mode)
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
index 000000000000..0a55400809c9
--- /dev/null
+++ b/include/linux/kasan_def.h
@@ -0,0 +1,10 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _LINUX_KASAN_DEF_H
+#define _LINUX_KASAN_DEF_H
+
+enum kasan_hw_tags_mode {
+	KASAN_HW_TAGS_SYNC,
+	KASAN_HW_TAGS_ASYNC,
+};
+
+#endif /* _LINUX_KASAN_DEF_H */
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 55bd6f09c70f..6c3b0742f639 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -22,6 +22,7 @@
 enum kasan_arg_mode {
 	KASAN_ARG_MODE_DEFAULT,
 	KASAN_ARG_MODE_OFF,
+	KASAN_ARG_MODE_LIGHT,
 	KASAN_ARG_MODE_PROD,
 	KASAN_ARG_MODE_FULL,
 };
@@ -60,6 +61,8 @@ static int __init early_kasan_mode(char *arg)
 
 	if (!strcmp(arg, "off"))
 		kasan_arg_mode = KASAN_ARG_MODE_OFF;
+	else if (!strcmp(arg, "light"))
+		kasan_arg_mode = KASAN_ARG_MODE_LIGHT;
 	else if (!strcmp(arg, "prod"))
 		kasan_arg_mode = KASAN_ARG_MODE_PROD;
 	else if (!strcmp(arg, "full"))
@@ -105,9 +108,21 @@ static int __init early_kasan_fault(char *arg)
 }
 early_param("kasan.fault", early_kasan_fault);
 
+static inline int hw_init_mode(enum kasan_arg_mode mode)
+{
+	switch (mode) {
+	case KASAN_ARG_MODE_LIGHT:
+		return KASAN_HW_TAGS_ASYNC;
+	default:
+		return KASAN_HW_TAGS_SYNC;
+	}
+}
+
 /* kasan_init_hw_tags_cpu() is called for each CPU. */
 void kasan_init_hw_tags_cpu(void)
 {
+	enum kasan_hw_tags_mode hw_mode;
+
 	/*
 	 * There's no need to check that the hardware is MTE-capable here,
 	 * as this function is only called for MTE-capable hardware.
@@ -118,7 +133,8 @@ void kasan_init_hw_tags_cpu(void)
 		return;
 
 	hw_init_tags(KASAN_TAG_MAX);
-	hw_enable_tagging();
+	hw_mode = hw_init_mode(kasan_arg_mode);
+	hw_enable_tagging(hw_mode);
 }
 
 /* kasan_init_hw_tags() is called once on boot CPU. */
@@ -145,6 +161,7 @@ void __init kasan_init_hw_tags(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115120043.50023-2-vincenzo.frascino%40arm.com.
