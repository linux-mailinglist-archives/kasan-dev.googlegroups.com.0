Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBBE3TGBAMGQEVCIGUUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D45E133131A
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 17:15:01 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id d4sf7885277ioc.16
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 08:15:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615220100; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jh8ihtQTvXlFreilTlQVlylz0wat4DZkDOH93JZ/lwAfEx3x4GbY01uKtS6l/CrJ1y
         PuymXwEq4U8661BY8XXOuA7mE2mTSRKEjUIKag3ej68/g8BeEvp40poGWUBjB57HkUj3
         YlqZfeSLXmip/PxMJNw5jjmKbvVIIBUVkXBHQP5JIXUnJjjaguoXN3sXzGzQWFdaNrg7
         he576/IJQXIOjQPxU1Avw4SsSrroeEqPfsT5yWWkHa4ICCXfK4714izTGvI1/VjhIGMb
         glBQTqR8c9ocb/Wy8pGbfVrs5cweSX84TDXTc33OeDazqk3OiRPoJv3p/QFP6xFPQzHm
         fO7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oB1csfv4LnjIYcY3y2a0fkJsCep0e2DZ8QcH5ZkPBRk=;
        b=ZeRTKyS9eJBRElAmE+tK1HSRPcb6liyLvuwaaVzZztXmBMsTmA688uulueCIjwF1Mo
         t+LbRWgp26xCcIpuIULuArv9MYqUj7gmciVZ5KMc7sNysDdYDqmISb2fkbroKMvbBVbW
         eXPz8nMOwa9+NGZKU3PRYXOh0bJuDknzqwX6CKQuk200smMFqqYJxsaJHj3i/3WwjsGs
         J+EWWBHS0JX3rTnc8tpjpmUja0jWwEbJg3oe55iO4ZaMSpq1vxnBLVpud9i1oqesBXC8
         LYXtkgW3i4l5Puf1KXq7IwIGskANlJboP+hVejCN4Gwdrl0IMYvKj9zi3l0u7CAkcwlh
         G1Yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oB1csfv4LnjIYcY3y2a0fkJsCep0e2DZ8QcH5ZkPBRk=;
        b=DeGjBtYypEPx5oc2+0j+6L9Vu/SAPe3vrkCRGOfaaPZIvJsrSImqKHJT0YW2PKbMC/
         GdqusPryf5K88P2Cf0yfnx6e3uYf04w6vhuut+lGw78C4iOmhM2NjZl2NG8a+p6xKzcP
         ScLxcoLHJ4N8mQJ8RbRwH5NdgNUtUJf0uRgJeLcA1pHnbqxixyKXmS1GbKPd/7a0Gtvq
         a8ZLypM3Rso8QkL8wc0l2zixBw/zO4mRU8JqDTTfy4LvTzRFAiqV35FWLH9q4vKG7nBn
         tUGXOh/DT33HeR7XPwn8SbuhY6OoUcBL2YF4jL7m1apVdxfaHeoxN3G+GVuAaDKs96aY
         l81Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oB1csfv4LnjIYcY3y2a0fkJsCep0e2DZ8QcH5ZkPBRk=;
        b=bsxd6xsxUC5F5Kz2yYY9se7r+R7BB24WOaoDkbX4ZNeADV2O9frYWpS4QAfLqCxNYj
         pwc+uViHaWluSu7mbd7BINVtFDXuY1B1dOLqnxbgVs2TRES2Y0FJZoKtmuk2ayLKrdHF
         n01nqwj8a45DYgdC/iZQ5tH3nyH9K6UnSVGzwaNqZd+UuVEIwSYNiwhzU+Iw7mLz12bJ
         KJgimqbnzm1rS3NzkEPd34svHGvfkdu0golALRdoY2bXLLmUKjhtZ66OHXx6X6Nay4cQ
         Vpvt04bNfzeKczJG0QdHrcCN5QP7lol/wUYUMgb4/1EB0CKaYQ4b/CJ1PzvQLXxNj4LL
         5l7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532fHFaFcc5O9GkbD+CG1v5eVnqa836/BygeM9TdxIH6dDmDDop2
	NwGoZ4PZ54KxmWVUJIyWH9I=
X-Google-Smtp-Source: ABdhPJz/Kfn/l9r1ekJT3XoE3zjU0sjXLJZiFheE9qHPHqAVcST+HAxCoiYqSyCWafdPqgdYaWqOTg==
X-Received: by 2002:a02:3ec7:: with SMTP id s190mr24124708jas.11.1615220100510;
        Mon, 08 Mar 2021 08:15:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:15c8:: with SMTP id f8ls820000iow.6.gmail; Mon, 08
 Mar 2021 08:15:00 -0800 (PST)
X-Received: by 2002:a5d:8d03:: with SMTP id p3mr18425711ioj.64.1615220100106;
        Mon, 08 Mar 2021 08:15:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615220100; cv=none;
        d=google.com; s=arc-20160816;
        b=DsJG2dzdWPqF3kRP7nPgba/lsY8ZDMqB7KxN/W2ls2GBUDbrgJT5EqKcL32YrYD7pH
         xdE4fsT1d6PFqrWyi6uf8FJ51TgZRrD1wr+rQL8nFX5VrQ/ymdn4//F8I2EB3JP336Fs
         NUakZskKjtQmiGUlAHZe+6YfDqM6JJNUrKyHoxByOzbDGa8c3BXS+cobWHk3u6GoibgL
         r07GnWbtvmArnMmIMf5fxirpqeWuGXtyaPHRHoyY6AMPDFcVMohzAUMVo/i6EGx8b/vk
         Fmz5sCQUCJ+NO5LmVuBTUhgn30lBTD+p9ztWDGtRBnnpvGfyZub6QRNjrJu3or2EoEIr
         yqBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=FrTAqvbuBhxLtpx1MxW5TIy283al8H0/gyxbBa60BS8=;
        b=Bkvix/vSNmeKERcMLiaYK21bjI8Yp1Oe+NoWW7CTdVsPOevJu8URxGvwiqWNTN46s4
         fBObJolyJ1/1jSyH+RLLWnNSJbsNKlvlJcLAY2O0HiWKPjCa101YBZK/9JpdCx6H/pKc
         q0O87FZCii/r+NX0S/YX2C+tQmXkIE4d5hT1GTHlv3OqNxZOTAQTPWzkoySb9Cm0e4j1
         O0JpUf9ntdORHZqrcyMfV0xwJuyz9IGSWzOthb041LoGt11OhGYpDOCI2Sy/lMliqQs7
         wyi/g24k74Ebc8tYZr+2iNVSDUFdhI52Uo55ZxIoPeAZfauaEYpE9x0BXQ/fpMeEvA5E
         IJUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id y8si646247iom.1.2021.03.08.08.14.59
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Mar 2021 08:14:59 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2D1C21063;
	Mon,  8 Mar 2021 08:14:59 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2F26E3F73C;
	Mon,  8 Mar 2021 08:14:57 -0800 (PST)
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
Subject: [PATCH v14 2/8] kasan: Add KASAN mode kernel parameter
Date: Mon,  8 Mar 2021 16:14:28 +0000
Message-Id: <20210308161434.33424-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210308161434.33424-1-vincenzo.frascino@arm.com>
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
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
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
[ Add a new var instead of exposing kasan_arg_mode to be consistent with
  flags for other command line arguments. ]
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst |  9 +++++
 lib/test_kasan.c                  |  2 +-
 mm/kasan/hw_tags.c                | 66 +++++++++++++++++++++++++++++--
 mm/kasan/kasan.h                  | 13 ++++--
 4 files changed, 81 insertions(+), 9 deletions(-)

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
index e5647d147b35..479c31a5dc21 100644
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
index 2aad21fda156..6d3eca5bb784 100644
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
@@ -194,10 +246,16 @@ void kasan_set_tagging_report_once(bool state)
 }
 EXPORT_SYMBOL_GPL(kasan_set_tagging_report_once);
 
-void kasan_enable_tagging(void)
+void kasan_enable_tagging_sync(void)
+{
+	hw_enable_tagging_sync();
+}
+EXPORT_SYMBOL_GPL(kasan_enable_tagging_sync);
+
+void kasan_enable_tagging_async(void)
 {
-	hw_enable_tagging();
+	hw_enable_tagging_async();
 }
-EXPORT_SYMBOL_GPL(kasan_enable_tagging);
+EXPORT_SYMBOL_GPL(kasan_enable_tagging_async);
 
 #endif
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3436c6bf7c0c..2118c2ac9c37 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -21,6 +21,7 @@ static inline bool kasan_stack_collection_enabled(void)
 #endif
 
 extern bool kasan_flag_panic __ro_after_init;
+extern bool kasan_flag_async __ro_after_init;
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
@@ -294,7 +295,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
 #endif
 
-#define hw_enable_tagging()			arch_enable_tagging()
+#define hw_enable_tagging_sync()		arch_enable_tagging_sync()
+#define hw_enable_tagging_async()		arch_enable_tagging_async()
 #define hw_init_tags(max_tag)			arch_init_tags(max_tag)
 #define hw_set_tagging_report_once(state)	arch_set_tagging_report_once(state)
 #define hw_get_random_tag()			arch_get_random_tag()
@@ -303,7 +305,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
-#define hw_enable_tagging()
+#define hw_enable_tagging_sync()
+#define hw_enable_tagging_async()
 #define hw_set_tagging_report_once(state)
 
 #endif /* CONFIG_KASAN_HW_TAGS */
@@ -311,12 +314,14 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #if defined(CONFIG_KASAN_HW_TAGS) && IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_set_tagging_report_once(bool state);
-void kasan_enable_tagging(void);
+void kasan_enable_tagging_sync(void);
+void kasan_enable_tagging_async(void);
 
 #else /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
 
 static inline void kasan_set_tagging_report_once(bool state) { }
-static inline void kasan_enable_tagging(void) { }
+static inline void kasan_enable_tagging_sync(void) { }
+static inline void kasan_enable_tagging_async(void) { }
 
 #endif /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
 
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210308161434.33424-3-vincenzo.frascino%40arm.com.
