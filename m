Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBMN6XWBAMGQETTPEPZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9314933B3BB
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 14:20:50 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id co15sf13527762pjb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 06:20:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615814449; cv=pass;
        d=google.com; s=arc-20160816;
        b=GXC7ZNW60pszFrxpgqzMT/RB4D4IovRN++nJvcUnUJTiIoxZIrw/I9xTS0Ya1O/yvY
         LUc6oqM0EjeS9qSxb2uAdpJV5Y47cmU+GeBl5ECnA/dEc8d+LllwvJouzYWje8RpsmGt
         8zNvxl1prnMbAD8a03IYj9ZieeiO13YNcoXiztMf2u09ofc/mZI3HB+rBu8ynOqb9m4A
         wirafullbXxnQDGi/vVGVdC+A6PXx87hx32cX30ovcSIvwYkI/FP/jJ67KSad5dKEkbd
         ZqT0w/NInKz7D7XsEchHF1yyG7ooSo2QK5MPBwlA+0Fh71OrZBSD778fgmqUHkMYG7vV
         M9NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Ux+Mj4IBWaAeyBTT9uJGC/fMin+VX7zYJMHPhkufzww=;
        b=lxd0SsrUhL3uLA6swRQwonvbAZshKPsIthKqSjVStc2rYhPsdVrNHPQc1TQPTz835G
         a6PC14UWPukHypLE0Rlc9vZevK9HgF7LA3AYyDUCqR+FwZfNNn5IlCJOMJziv01+wZYc
         Qxu/kweNrZrYXF8cmLYdeH2jCo8dcFc1R8VZg1W6X/WaOaNjYQeGVUX2Hh2CQJ5T8M0T
         yxLtQ6/7fMJtiiRn/6AhQKpvfFXdfSdReOeo7vMwa7wbjRhgPscFLqlgBRDEhQVSm29h
         0DIFN3HVh1k9dLx1NyKRWnrF3S7hn6Lo+ejrh410LWLUjZ++hVxZbbXrefrIlm4OYj75
         OvuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ux+Mj4IBWaAeyBTT9uJGC/fMin+VX7zYJMHPhkufzww=;
        b=ZrIPbgM/F9W0+h/7nRRhByL6J3LlKQjh/5M84ShgWuhsz1On/IK4xlrOcxxcSOaNMf
         VGcRX1F3ob0GwjmVBOLStbOuRSkB02o6UMAo3dRAscqwya+APfNafn7hHx/WjCXBLg4f
         IVBA9AU3DFQeEjI6bohDFc4pqpHmQnc7Di5zRABIXFj1LPdVAthP5EUc2x+rov2my+f7
         U5oy9UKxtdlUPNi1wlqIexuwkjcuqSIfMvfTCeCmxGCBFLof1GudZMaTT6PV3EDn0H0b
         kG3JAkiGQzbdjjak7uTDP7cx9eFCQRT0M3LUZ34NJINDQAXKOgDXlGeHk5A78FQWG8IG
         wzDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ux+Mj4IBWaAeyBTT9uJGC/fMin+VX7zYJMHPhkufzww=;
        b=dIOhemIVfayEXwR030+gnPsImJqcPmI0bqVTHvbv1iG7nHGVfatGhStYZMoo8VrJzw
         XmqsLB59DKMSXI/xAWdM2Fpqt3MyaxcGm/WbUkK+IyrPMXShV3VRdjwOy6uT1Z5IEvI8
         oO219jKipMGJfIzQx/3Vg8/4uis3GBOyMSQbzVaiuKEutiLAw3iqbRacSYg6lNuwagrP
         xcRHxc2G2ibAMwLNyalOzomjR73Eft16b/qEsPhz6KmpKA9h3jSukAgEoKxGdBM7ONf+
         pJVhngewo8yGODvyAsmG5YfojKqL8+tnXXw9tzLwyozFwmzCTPkUpC1KvbfD2teURKrz
         aLdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/8DQoo8FlYzJFKMhuE4sGWq12WQ7uIBJWcxNhYER+oCU8Kesx
	SJRkUSZ+3uE6flJcCvy7rBo=
X-Google-Smtp-Source: ABdhPJyCBWmsYD2u/R33CQ4iFtp0Mnt9mmLPYIONfqpQ7e6j8ZhRDI22k5KOl2o8yco825botUs6jA==
X-Received: by 2002:a63:fc12:: with SMTP id j18mr22961391pgi.334.1615814449151;
        Mon, 15 Mar 2021 06:20:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c40a:: with SMTP id k10ls8788126plk.2.gmail; Mon, 15
 Mar 2021 06:20:48 -0700 (PDT)
X-Received: by 2002:a17:902:ea0e:b029:e4:81d4:ddae with SMTP id s14-20020a170902ea0eb02900e481d4ddaemr11753937plg.12.1615814448646;
        Mon, 15 Mar 2021 06:20:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615814448; cv=none;
        d=google.com; s=arc-20160816;
        b=OUmfOu89363QTT6ajL8MFS1I1P/pgNbwOLYCIbXdrcaXrM5YJ8Dk5isPQ9x2tTEffk
         N1uIKLe6Kyewa33+yTFrhOn50j87zvBWdmpeoKjFQxJj0pwK8qwYw9GHb7bAkhEBedzM
         scCW1n6W6tq07/tjCIGtnI6nrrHTWhJEY7Z8Y6cD+xNtNTfhqP3Z4oyk74UF3yvNmYYD
         l5Cx8Em8xqKlOeSSTu8FY5xrvloyEHNkXpd9MEgyDZFHL2L6tPAqPYEQ7yEGRZNZy1iW
         kgso3qQcV8uZ8DEEsyPdjXj49ArkR5MFYWKni4NDTudwLGxE7VvuUmAIiC35UG7wXT2x
         EqRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=1RUn9XsiCZQZBMrQyuEq12BxdzA02gh1Z+IYuqP+bfQ=;
        b=ra0z/nSYZ6alMUVGRi1/JX6KBKuY5PggHydI8wLMXSG/A6KBg2IY2IMNeQIO4l+YSb
         8yfLd6Sz7ftU/W4ng8eHBARbVrdKCUxeBWS9YVFSvAIIcHldDNm6Ui77uKsKGi7SyO8D
         8fVOAy5Xz2FfbMBD8R5sVa+mStAPYAOk+Mnrzsj8HBLih7qkTt0wfwvtXeIe2id9vRtA
         KnzJMX/vlLt/ZJf6/niCglxEsfyWKaG/cWIuwVzHiYzidjuPh5Y1pyDWH5vJad1RpErS
         dvjrhzWtTUeSAwmlSoVPcbs1NqzTeyK74y68OAhSVe+v5xjkzngha6xFnCfcF+RaxzZh
         uRFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r7si1621582pjp.3.2021.03.15.06.20.48
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Mar 2021 06:20:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 268641474;
	Mon, 15 Mar 2021 06:20:48 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 44B5B3F792;
	Mon, 15 Mar 2021 06:20:46 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v16 9/9] kasan, arm64: tests supports for HW_TAGS async mode
Date: Mon, 15 Mar 2021 13:20:19 +0000
Message-Id: <20210315132019.33202-10-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210315132019.33202-1-vincenzo.frascino@arm.com>
References: <20210315132019.33202-1-vincenzo.frascino@arm.com>
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

From: Andrey Konovalov <andreyknvl@google.com>

This change adds KASAN-KUnit tests support for the async HW_TAGS mode.

In async mode, tag fault aren't being generated synchronously when a
bad access happens, but are instead explicitly checked for by the kernel.

As each KASAN-KUnit test expect a fault to happen before the test is over,
check for faults as a part of the test handler.

Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Acked-by: Andrey Konovalov <andreyknvl@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h |  1 +
 lib/test_kasan.c                | 17 +++++++++++------
 mm/kasan/hw_tags.c              |  6 ++++++
 mm/kasan/kasan.h                |  6 ++++++
 mm/kasan/report.c               |  5 +++++
 5 files changed, 29 insertions(+), 6 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index a07923eb33c5..7d0fd4f36e23 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -246,6 +246,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 #define arch_enable_tagging_sync()		mte_enable_kernel_sync()
 #define arch_enable_tagging_async()		mte_enable_kernel_async()
 #define arch_set_tagging_report_once(state)	mte_set_report_once(state)
+#define arch_force_async_tag_fault()		mte_check_tfsr_exit()
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
 #define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 929fbe06b154..0882d6c17e62 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -69,10 +69,10 @@ static void kasan_test_exit(struct kunit *test)
  * resource named "kasan_data". Do not use this name for KUnit resources
  * outside of KASAN tests.
  *
- * For hardware tag-based KASAN, when a tag fault happens, tag checking is
- * normally auto-disabled. When this happens, this test handler reenables
- * tag checking. As tag checking can be only disabled or enabled per CPU, this
- * handler disables migration (preemption).
+ * For hardware tag-based KASAN in sync mode, when a tag fault happens, tag
+ * checking is auto-disabled. When this happens, this test handler reenables
+ * tag checking. As tag checking can be only disabled or enabled per CPU,
+ * this handler disables migration (preemption).
  *
  * Since the compiler doesn't see that the expression can change the fail_data
  * fields, it can reorder or optimize away the accesses to those fields.
@@ -80,7 +80,8 @@ static void kasan_test_exit(struct kunit *test)
  * expression to prevent that.
  */
 #define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {		\
-	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))			\
+	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&			\
+	    !kasan_async_mode_enabled())			\
 		migrate_disable();				\
 	WRITE_ONCE(fail_data.report_expected, true);		\
 	WRITE_ONCE(fail_data.report_found, false);		\
@@ -92,10 +93,14 @@ static void kasan_test_exit(struct kunit *test)
 	barrier();						\
 	expression;						\
 	barrier();						\
+	if (kasan_async_mode_enabled())				\
+		kasan_force_async_fault();			\
+	barrier();						\
 	KUNIT_EXPECT_EQ(test,					\
 			READ_ONCE(fail_data.report_expected),	\
 			READ_ONCE(fail_data.report_found));	\
-	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {			\
+	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&			\
+	    !kasan_async_mode_enabled()) {			\
 		if (READ_ONCE(fail_data.report_found))		\
 			kasan_enable_tagging_sync();		\
 		migrate_enable();				\
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 1df4ce803861..4004388b4e4b 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -252,4 +252,10 @@ void kasan_enable_tagging_sync(void)
 }
 EXPORT_SYMBOL_GPL(kasan_enable_tagging_sync);
 
+void kasan_force_async_fault(void)
+{
+	hw_force_async_tag_fault();
+}
+EXPORT_SYMBOL_GPL(kasan_force_async_fault);
+
 #endif
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 56b155ddaf30..f34253e29b4a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -304,6 +304,9 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #ifndef arch_set_tagging_report_once
 #define arch_set_tagging_report_once(state)
 #endif
+#ifndef arch_force_async_tag_fault
+#define arch_force_async_tag_fault()
+#endif
 #ifndef arch_get_random_tag
 #define arch_get_random_tag()	(0xFF)
 #endif
@@ -318,6 +321,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define hw_enable_tagging_async()		arch_enable_tagging_async()
 #define hw_init_tags(max_tag)			arch_init_tags(max_tag)
 #define hw_set_tagging_report_once(state)	arch_set_tagging_report_once(state)
+#define hw_force_async_tag_fault()		arch_force_async_tag_fault()
 #define hw_get_random_tag()			arch_get_random_tag()
 #define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
 #define hw_set_mem_tag_range(addr, size, tag, init) \
@@ -335,11 +339,13 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 void kasan_set_tagging_report_once(bool state);
 void kasan_enable_tagging_sync(void);
+void kasan_force_async_fault(void);
 
 #else /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
 
 static inline void kasan_set_tagging_report_once(bool state) { }
 static inline void kasan_enable_tagging_sync(void) { }
+static inline void kasan_force_async_fault(void) { }
 
 #endif /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
 
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 8b0843a2cdd7..14bd51ea2348 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -366,6 +366,11 @@ void kasan_report_async(void)
 {
 	unsigned long flags;
 
+#if IS_ENABLED(CONFIG_KUNIT)
+	if (current->kunit_test)
+		kasan_update_kunit_status(current->kunit_test);
+#endif /* IS_ENABLED(CONFIG_KUNIT) */
+
 	start_report(&flags);
 	pr_err("BUG: KASAN: invalid-access\n");
 	pr_err("Asynchronous mode enabled: no access details available\n");
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210315132019.33202-10-vincenzo.frascino%40arm.com.
