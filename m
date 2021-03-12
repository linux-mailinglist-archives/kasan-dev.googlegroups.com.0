Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBMHSVWBAMGQEWW2CKLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id BF3B4338FC1
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:22:41 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id d15sf2234005ila.10
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:22:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615558960; cv=pass;
        d=google.com; s=arc-20160816;
        b=Om3l8zynMz/85+3cyBEvsfR6ZSfQqmfEfjHaWaaLh6pKgsGSAz7oRQkkv3C/iIcuRV
         eisi9nQBnZIQIixFNz301rY3iBc4GBPRXCMjK07D87xiC7JWPKDtXP6sBveyeGsYmdWI
         JDuuTduGEF3ROxgBW4rEduawz16mRhbKWV2RYSxwh6z7J/bTdyuu2JNyGFbV13oiTaXY
         WTXRzTPCwEwv353OtAs0LxXo82Qks/oRlwKi0lNRij9oAa/K5g7veK8fyTscgDDN1fCx
         +g4feDudnm4kzf1sNsnAo26FL80+s5jX9xJ/gLWeL/3a9CTJYVYW14L7v94xgAPs3yMS
         8iYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MMzkBcgFTlzegNyOni5n8E0PAn84JcpWJvoUaxwKlHs=;
        b=x0Ic+uPc2/8ET3J37T+dKQZcbKTliogw846qEkgtfqRWohqyD7Xc9ax6fFxYVHPKJ0
         40faBJzBFYp9wFKsOafyCPqvEgTJ9DbiPfx+pYlpMRqv3U8Dr4eJBhi7uQ7UTF6D+QDS
         S2bwSQBf3PaQKg5DwYV5nbORSWpj/DBlt5eoBcNYodTHn5zu4ImdtRjWE6qH2Mub911a
         BS75JgSF7aLe9DyA+zaUmnQACPM92VOjpVU1akSjzPcYHrw/GGxu6INv9sOGRLL5CDks
         5ubXjHGmeartN1exQJBll4elDKwUK85HdYGYGiQ+wFiU6FZ22lKU96drBPPP720ZqyYG
         Z0sw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MMzkBcgFTlzegNyOni5n8E0PAn84JcpWJvoUaxwKlHs=;
        b=Msys/D8q+v0XY654SUxpckrNZ5DLVS0J6I2o41gXq/fMumzQU2Dj710Fz/V4kJIFyK
         MfrExVsNCVoVxwWABerzvEzhJRz59z94oiwKepsvQ6M6Lo4UMgaGB4ornEeJvp0nyIRD
         zwtJx+GuRvwKoziByo9lmcOJPh/Znl+NrGIw06L7dZO+NeJm9y88rdqPi/u89BeR60LV
         WIVNs26yFL0t2uU5bXpULjMDQT9JZyKlQcwakgVbLaRNJPnCQL05S/ZV7P7JPJS6Y7Ix
         AeUrJsxxEzAoz1jIBxobyF/aUgd1x2g6v0WfgA5IEwcFQauBr2Wrmrnnk9Oih56oE9Xo
         wJgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MMzkBcgFTlzegNyOni5n8E0PAn84JcpWJvoUaxwKlHs=;
        b=b0mRmRktUHfUyOsHFNte+1d0qxojd6FJLW9Ah1kl/bs4MX5/BUJgTsYFXlboXM/6lG
         dfyMfU0jQNwxXZQOUrdgOhMIrOGMxFLBw+R65m7c6vRWmESdBeCbmdHTUMd0YAcxc+0O
         4UnvSqH6z4tJ6CpTFF7al/rmKOj3oPrZnr21qH9XofuSnXd0+Nwc99OFmy8Mj5y+DHqL
         jTtf1i8vF5IQGIDszij8diRLyByLGsxzDWYYPnTg3VHn7yJjQo2LOdAJ7Duq/rOnVLFw
         d7BsGoFcLOL0brGxmYxCQxINHq8b4UGgNxow7egHZufcDkb6eVrtNkO2zoKgI+0yZWy9
         8lBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qRfPs0/GTnxW5OMIwahkhmtBu6obF7KcbcbgXRunMBY8U83P7
	uuYG7lBCVFUhpJwzbXOCAj8=
X-Google-Smtp-Source: ABdhPJwE8V4l8FvfA+E5tjvn9+4qDU5xBZZDJIWks7H9oFP67Lt8uBZ/p2ohUSCt4RmSk7P6xXW/VQ==
X-Received: by 2002:a92:dc50:: with SMTP id x16mr2893100ilq.281.1615558960809;
        Fri, 12 Mar 2021 06:22:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:271f:: with SMTP id m31ls1251079jav.2.gmail; Fri,
 12 Mar 2021 06:22:40 -0800 (PST)
X-Received: by 2002:a05:6638:1648:: with SMTP id a8mr8474747jat.25.1615558960240;
        Fri, 12 Mar 2021 06:22:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615558960; cv=none;
        d=google.com; s=arc-20160816;
        b=rAa4FzqHyPENdTLMl8+pnT0ppy2yyi2S+g1HtMkdUUixNuEsFds96kJx+rsyByUzT5
         9sRrGxNkbuJ7bnjux/h2GtTaVeuQwzkrNZZOdWxX+j6sawxKFNu4TDMk0UtT0AGGe0SN
         g9IpeU/XvkOGdbYk4bsdqnbGcIJ3TzQ7j5Zzm4N9OOdWHA935FJxUSGncHY15ySsqiEE
         P1zm6EccXmu5YPQoy1aXpcjQV2D31Bbd3FEtV3naijDMalQgJ5EtQOZpDQC8wR98+1dy
         H3xggf+KFalFzcO+f2jpRCbafxDDDxjsJaI63E7qZFw4WNbX2visL6sOdlu9vFMK2sqt
         AQeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=cdnapsTum7aE95DEfem5nGTQTu7YwZ+zAdPV8eFk4UM=;
        b=rZdRZQlfBml/UIqzFBEOEc/1cYZjt2F5j6UNZIuHelP62qdN0cQYMxkPRa0ZQkJgWG
         h1yMudXHxnyGG0TolfeZ6sHlu1zyMlMYiFawEorOqgmTe4KLlFA1nKfO235IpKkat6kd
         5BbsgkZxkcDT1rGhi+1oXwN+3zyxCH7ohxezFhVDKYRaDqsIq7806XgvVUMJ5Frjsnd0
         CEnRilyoUBZpFO+tEGY7eACYhVPS/PW4+T+geYjGMCxFKaSV6P9PLR7mrbPXbExKfAwe
         d81ZpINvMX8fk6AB/A2IqOqpg4TBzt1tLqbU09JOW4SpNDh8ldEX1wxB1+sSkASZ3NFb
         kyeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l15si238214ilh.0.2021.03.12.06.22.39
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Mar 2021 06:22:40 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B3A8C11B3;
	Fri, 12 Mar 2021 06:22:39 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D16D13F793;
	Fri, 12 Mar 2021 06:22:37 -0800 (PST)
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
Subject: [PATCH v15 8/8] kasan, arm64: tests supports for HW_TAGS async mode
Date: Fri, 12 Mar 2021 14:22:10 +0000
Message-Id: <20210312142210.21326-9-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210312142210.21326-1-vincenzo.frascino@arm.com>
References: <20210312142210.21326-1-vincenzo.frascino@arm.com>
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/include/asm/memory.h |  1 +
 lib/test_kasan.c                | 17 +++++++++++------
 mm/kasan/hw_tags.c              |  6 ++++++
 mm/kasan/kasan.h                |  6 ++++++
 mm/kasan/report.c               |  5 +++++
 5 files changed, 29 insertions(+), 6 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 8b0beaedbe1f..b943879c1c24 100644
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
index 479c31a5dc21..785e724ce0d8 100644
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
index 02957cec1a61..c1581e8a9b8e 100644
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
 #define hw_set_mem_tag_range(addr, size, tag)	arch_set_mem_tag_range((addr), (size), (tag))
@@ -334,11 +338,13 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
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
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210312142210.21326-9-vincenzo.frascino%40arm.com.
