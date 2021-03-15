Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBIV6XWBAMGQEH54BYOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D17C33B3B2
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 14:20:35 +0100 (CET)
Received: by mail-ot1-x33c.google.com with SMTP id 88sf10020095otd.17
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 06:20:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615814434; cv=pass;
        d=google.com; s=arc-20160816;
        b=wG2GNXpJOsQiYIJpZTFvBQHdZ6pJR0yMJhlTNn7xd5ruYLLE3GDG3fBuQ6ljTa+6yX
         AMYf+sRgcGYrv5NKUtAxIhRcW6QYDB9ItwkKtar3CemdV+N9/u6lTuWh3afx5dQFMfTy
         zMvPv/D/pu6UF49hRkKbypctQ9h6iCdwx6EyTWBGn0cYbfMT6ijyqDLD1dfP8eTDeCv/
         BNgnN80cCo0CPJ9WGuPjdLmxsdXd8VRBQ+c4v3njwYnzHzEDxG85tXPfIHmOYpcCq8+i
         CA2X2sWJCF5v/b5RpR+GBjapY2KvHN0gbCuMCVmvhe/4aRtrjQHaU93HzNS42l5NNQTM
         pHdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=m/MqBUQmS/cCaxs/NtL7Mh4crXipYX0XuGniLVXmnxI=;
        b=QSYfZUku6qVT+mhAysjXUkOu+78SYpL9c4/FqY2IkGSASn6MjHvbnaTS1J1wpRisCf
         nor6f0HgGJSpwYFZp3QJz3zBZ63weLUXASL+Y515BdAQdZj2FWSVt3sE38FOp7dEW/sN
         fBQ7M5YM2dKfkYCGwclK/tnSjpwGuYzgrZbM6846scDEbqY8YfBtnUuDwO1gdQ2IdWDs
         BmZS4BPMxdtQqln4S8x+fCbNvWYGnK5nbsYQplOBtEcbOtj/4T30BbsJVSsS8oERFCRT
         kH5Tp/w19ol+FEyjgGHgw+8/9sZqfdOJ+Mpm3UCwCxXiDIrYXul8XBXOBj3W+j68TtdV
         OxIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m/MqBUQmS/cCaxs/NtL7Mh4crXipYX0XuGniLVXmnxI=;
        b=iVZbJs1lYDohlaeP8g7cguvZv0KpiceTkaH7bQ3LyMYuxR38bmKLOso9Jl9HV5FTgN
         vXpqMuxJcuRw5Y/gSJqnQEEUROy45QhMztVu1bxJkECsZ+UXtrL/h3/9nil7meBkyS7x
         PtSx5VQxObPxOetp+pV7HaUTuxONT4LiyqxqC/nqYhIPWWL96UW9M03QbHlHOhUjrQet
         ucJvJj1PoR+wI5kau13j2l/IkOnJ9kpkaHMaJResVy+tMGfbWrFWiWCgEoBHJ/zb1qEk
         zoENmPqwGwOkNDv9fpYPG6xFylFQxtRKZh6k4/tLB5v8K2hObYeIgas9ecZPKq08mv5D
         2d8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m/MqBUQmS/cCaxs/NtL7Mh4crXipYX0XuGniLVXmnxI=;
        b=aDlBNF4HQowp/qYCRYy0wOy5LCnkbtKGEVCTotHuIll2zf38pfal2wu96tOhDblkyS
         nsHhnddXnS5CHFydymbbH1SRecXX1cYkaPv+xShIwBCSarJ5i9JlIpXX70tyWPiipeWQ
         +tzrYbkEiXDvAg2p5sLxTt42prgbh8Bx4LKYVxrZsNUDIY0SYIP7ctJVzH+i5E1tHkwQ
         AVJHJrCRCBgQcdZeY5VuopaedfhRENlbw4PzbTBp9ofiW/xKw1iR3OwwrbsRPbAIKTLZ
         +vN5g6O3C1I4F1u50T/2hjZAH5Wkr+BmmtJxIwe0kn0DUS2mbaftCs8Xv+uj2kkdMiZM
         3/1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ERxTS0u9TwoXnRsWmdv+tcZkkSf9DsJXWlxgiq13+uW+6wq0g
	gIIapNT3YA21488xqPSL6r8=
X-Google-Smtp-Source: ABdhPJzQNU/76vbwebw1XXqZkIW94eV2m7UKK5ciq4Iu3Fh/B3eewA3Hz7Mi2W/AcpakdAvVVnERXw==
X-Received: by 2002:a9d:740a:: with SMTP id n10mr2144989otk.27.1615814434080;
        Mon, 15 Mar 2021 06:20:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d54d:: with SMTP id m74ls598879oig.11.gmail; Mon, 15 Mar
 2021 06:20:33 -0700 (PDT)
X-Received: by 2002:aca:1e16:: with SMTP id m22mr5634653oic.153.1615814433737;
        Mon, 15 Mar 2021 06:20:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615814433; cv=none;
        d=google.com; s=arc-20160816;
        b=UFLXzEM+M9F7LrpDUObzQAULmSJHPeFYgwtbPBVIUI3MdQFcGkk25MmsKP7l+YLBvr
         czgVEas2qhomFHxuynb/rJrTW3rxh6hauDRYrRFkj8D2MMXVd7h9VZU5fpQHcM7yvni8
         K2pr+Y1QOavQPQrxOckIKm7SIMp6xygcxSX7bm4VDKuspIMxZJTDOZxUoymamElGy+VX
         ukwNyuumeVWvSq2+bFlZdh8DYvn8x1W6z5Y4owejAMM1j0zyqf4dlVJ23V1WJdY+i3mq
         RIf6Kae53jxzfHiFJhLf3vhnIRX2pV8xK4JblmQh4FD37UGmTEFZaxsgPRxqWv2b45M0
         AAjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=xDK0UDmN+bRD6WHnNkhYvwoY1orazkY+kpEmB7709PI=;
        b=wUn+l7J3mDdCP3n2Lr/JslDBRvCKrzomfWNFujV+lEv20vzPRzS0G/n/KX4o4N4zlf
         n5KkiLp1G8M8adkmwT7hCoC8o3HhpoCjdyeqgTJawfqz3QcjnSUmvviNdVsTOQtMWAF4
         6gy9HJl3uCEzpcs6MkS1feDaC9OLN8sayJOvl85F0ITsNPqXdI5Tf4MWfSeWTlMbz/Ub
         rLUuRoTaXuG1Y3Kz5I8aM/Y0p60dUEt7JndgCmjYeU5DZSXSeNGZv8U/h8XYpZb0Znvn
         HvfoNo1cOWd3oCBlM8ENixQf6FoIl1sPOEg6W72Pw5IFMuKdT/UCq01uc5zaJgI5J+zJ
         UJ9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z24si507420oid.3.2021.03.15.06.20.33
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Mar 2021 06:20:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 76598106F;
	Mon, 15 Mar 2021 06:20:33 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 7992B3F792;
	Mon, 15 Mar 2021 06:20:31 -0700 (PDT)
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
Subject: [PATCH v16 2/9] kasan: Add KASAN mode kernel parameter
Date: Mon, 15 Mar 2021 13:20:12 +0000
Message-Id: <20210315132019.33202-3-vincenzo.frascino@arm.com>
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

Architectures supported by KASAN_HW_TAGS can provide a sync or async mode
of execution. On an MTE enabled arm64 hw for example this can be identified
with the synchronous or asynchronous tagging mode of execution.
In synchronous mode, an exception is triggered if a tag check fault occurs.
In asynchronous mode, if a tag check fault occurs, the TFSR_EL1 register is
updated asynchronously. The kernel checks the corresponding bits
periodically.

KASAN requires a specific kernel command line parameter to make use of this
hw features.

Add KASAN HW execution mode kernel command line parameter.

Note: This patch adds the kasan.mode kernel parameter and the
sync/async kernel command line options to enable the described features.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Acked-by: Andrey Konovalov <andreyknvl@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
[ Add a new var instead of exposing kasan_arg_mode to be consistent with
  flags for other command line arguments. ]
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst |  9 +++++
 lib/test_kasan.c                  |  2 +-
 mm/kasan/hw_tags.c                | 60 ++++++++++++++++++++++++++++---
 mm/kasan/kasan.h                  | 18 ++++++----
 4 files changed, 78 insertions(+), 11 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index ddf4239a5890..6f6ab3ed7b79 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -161,6 +161,15 @@ particular KASAN features.
 
 - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
 
+- ``kasan.mode=sync`` or ``=async`` controls whether KASAN is configured in
+  synchronous or asynchronous mode of execution (default: ``sync``).
+  Synchronous mode: a bad access is detected immediately when a tag
+  check fault occurs.
+  Asynchronous mode: a bad access detection is delayed. When a tag check
+  fault occurs, the information is stored in hardware (in the TFSR_EL1
+  register for arm64). The kernel periodically checks the hardware and
+  only reports tag faults during these checks.
+
 - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
   traces collection (default: ``on``).
 
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index d77c45edc7cd..929fbe06b154 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -97,7 +97,7 @@ static void kasan_test_exit(struct kunit *test)
 			READ_ONCE(fail_data.report_found));	\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {			\
 		if (READ_ONCE(fail_data.report_found))		\
-			kasan_enable_tagging();			\
+			kasan_enable_tagging_sync();		\
 		migrate_enable();				\
 	}							\
 } while (0)
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 2aad21fda156..1df4ce803861 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -25,6 +25,12 @@ enum kasan_arg {
 	KASAN_ARG_ON,
 };
 
+enum kasan_arg_mode {
+	KASAN_ARG_MODE_DEFAULT,
+	KASAN_ARG_MODE_SYNC,
+	KASAN_ARG_MODE_ASYNC,
+};
+
 enum kasan_arg_stacktrace {
 	KASAN_ARG_STACKTRACE_DEFAULT,
 	KASAN_ARG_STACKTRACE_OFF,
@@ -38,6 +44,7 @@ enum kasan_arg_fault {
 };
 
 static enum kasan_arg kasan_arg __ro_after_init;
+static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
 static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
 
@@ -45,6 +52,10 @@ static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
 DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
 EXPORT_SYMBOL(kasan_flag_enabled);
 
+/* Whether the asynchronous mode is enabled. */
+bool kasan_flag_async __ro_after_init;
+EXPORT_SYMBOL_GPL(kasan_flag_async);
+
 /* Whether to collect alloc/free stack traces. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
 
@@ -68,6 +79,23 @@ static int __init early_kasan_flag(char *arg)
 }
 early_param("kasan", early_kasan_flag);
 
+/* kasan.mode=sync/async */
+static int __init early_kasan_mode(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "sync"))
+		kasan_arg_mode = KASAN_ARG_MODE_SYNC;
+	else if (!strcmp(arg, "async"))
+		kasan_arg_mode = KASAN_ARG_MODE_ASYNC;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.mode", early_kasan_mode);
+
 /* kasan.stacktrace=off/on */
 static int __init early_kasan_flag_stacktrace(char *arg)
 {
@@ -115,7 +143,15 @@ void kasan_init_hw_tags_cpu(void)
 		return;
 
 	hw_init_tags(KASAN_TAG_MAX);
-	hw_enable_tagging();
+
+	/*
+	 * Enable async mode only when explicitly requested through
+	 * the command line.
+	 */
+	if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
+		hw_enable_tagging_async();
+	else
+		hw_enable_tagging_sync();
 }
 
 /* kasan_init_hw_tags() is called once on boot CPU. */
@@ -132,6 +168,22 @@ void __init kasan_init_hw_tags(void)
 	/* Enable KASAN. */
 	static_branch_enable(&kasan_flag_enabled);
 
+	switch (kasan_arg_mode) {
+	case KASAN_ARG_MODE_DEFAULT:
+		/*
+		 * Default to sync mode.
+		 * Do nothing, kasan_flag_async keeps its default value.
+		 */
+		break;
+	case KASAN_ARG_MODE_SYNC:
+		/* Do nothing, kasan_flag_async keeps its default value. */
+		break;
+	case KASAN_ARG_MODE_ASYNC:
+		/* Async mode enabled. */
+		kasan_flag_async = true;
+		break;
+	}
+
 	switch (kasan_arg_stacktrace) {
 	case KASAN_ARG_STACKTRACE_DEFAULT:
 		/* Default to enabling stack trace collection. */
@@ -194,10 +246,10 @@ void kasan_set_tagging_report_once(bool state)
 }
 EXPORT_SYMBOL_GPL(kasan_set_tagging_report_once);
 
-void kasan_enable_tagging(void)
+void kasan_enable_tagging_sync(void)
 {
-	hw_enable_tagging();
+	hw_enable_tagging_sync();
 }
-EXPORT_SYMBOL_GPL(kasan_enable_tagging);
+EXPORT_SYMBOL_GPL(kasan_enable_tagging_sync);
 
 #endif
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 29248f933080..9d97b104c3b0 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -21,6 +21,7 @@ static inline bool kasan_stack_collection_enabled(void)
 #endif
 
 extern bool kasan_flag_panic __ro_after_init;
+extern bool kasan_flag_async __ro_after_init;
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
@@ -275,8 +276,11 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #ifdef CONFIG_KASAN_HW_TAGS
 
-#ifndef arch_enable_tagging
-#define arch_enable_tagging()
+#ifndef arch_enable_tagging_sync
+#define arch_enable_tagging_sync()
+#endif
+#ifndef arch_enable_tagging_async
+#define arch_enable_tagging_async()
 #endif
 #ifndef arch_init_tags
 #define arch_init_tags(max_tag)
@@ -294,7 +298,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define arch_set_mem_tag_range(addr, size, tag, init) ((void *)(addr))
 #endif
 
-#define hw_enable_tagging()			arch_enable_tagging()
+#define hw_enable_tagging_sync()		arch_enable_tagging_sync()
+#define hw_enable_tagging_async()		arch_enable_tagging_async()
 #define hw_init_tags(max_tag)			arch_init_tags(max_tag)
 #define hw_set_tagging_report_once(state)	arch_set_tagging_report_once(state)
 #define hw_get_random_tag()			arch_get_random_tag()
@@ -304,7 +309,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
-#define hw_enable_tagging()
+#define hw_enable_tagging_sync()
+#define hw_enable_tagging_async()
 #define hw_set_tagging_report_once(state)
 
 #endif /* CONFIG_KASAN_HW_TAGS */
@@ -312,12 +318,12 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #if defined(CONFIG_KASAN_HW_TAGS) && IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_set_tagging_report_once(bool state);
-void kasan_enable_tagging(void);
+void kasan_enable_tagging_sync(void);
 
 #else /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
 
 static inline void kasan_set_tagging_report_once(bool state) { }
-static inline void kasan_enable_tagging(void) { }
+static inline void kasan_enable_tagging_sync(void) { }
 
 #endif /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
 
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210315132019.33202-3-vincenzo.frascino%40arm.com.
