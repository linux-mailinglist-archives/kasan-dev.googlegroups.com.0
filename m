Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBJHSVWBAMGQE2T4UJDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B755338FBA
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:22:29 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id o11sf13419854pgv.6
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:22:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615558948; cv=pass;
        d=google.com; s=arc-20160816;
        b=xMEu/QVIzW08VxF1OhnfMDqXX038bPjfEJJ2lRiZfaIADMA4Uj2R/sYtQ/fcqjSF3N
         Luq5Do2Hz/MapMA9aHiXDL5oiRRl6uQZ3WrYRq/Yp4zlLmixizSlNIMIgwjTezpAcOm7
         6yVlwg2/QrsEChIovYiChKYv/gqlHaimhZwQYqu/k+FqstLX6BmjQv+0l7Ar0p1EQlC0
         fNx7hX5kt3exXVkE7mcq/rMYdSwXDKpYlWybGH18nhCS4VRDliEFN4yRthlxf7ucnruK
         ByyL+4ZyLupLmtLmGFnE65IcO5Ae2vqy/fTymez2leBUpiFEb4w6f9Ui0y7fMCQU3996
         UfqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=I4y35Zi4b7TyUSvgYlRHYNe2VBUp1PqS4Gk0Tv8DklU=;
        b=0s/UZCt7MQYPfeDfhezSebwyt3Zwn3AYydF4boPT3BoMhDBtVdgLXDINB44TF0LsM+
         XWIw4XsU0zyeZPFuZBCrsMKTkxVWkYLf65T0JCptC0v0FMr3jZl7X88y4kICnYGFHpDB
         1EjgNN/4HurfRdCUVF3KC33hDjnegsz9lMdBl8Kale5k/azJC78eg9QBX6fu7iZJXJWw
         H+xS2ePkadROElGAY2DVGqFVOHZVdIIldruiLXfqUGJ1XclN9+XwJ6DkX58YL/K6kkh1
         WNDaQLQIwHTGonHzsnZfMQwAlYT81BudQCW+jdB3qYjU/H5N2uimbQWwxXFYSwYq3Ov+
         s7aQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I4y35Zi4b7TyUSvgYlRHYNe2VBUp1PqS4Gk0Tv8DklU=;
        b=fFILlsm9eR4ERDb4H14NIjjHRIADwhyk42KSOHNQD+2UIV6gGDEM+BORrWDfTFAVyJ
         q5V1JxCSrJLz7qe1pfrf1NJphMhe/RHnCt4bAI1vYRPvZpp1Gefm0b7RJnJbHxvcFptO
         8pyZi6YF0yqdHXRUgYZhe3q6NeuwzSUEXolddl0h17hL0oWOa6GUIgV+FZ5m6av6v6zb
         WXogpufp2MVuyx87hInMvGIm4s5Cjg81Z/ThPjUQXeeC8adoAUJ45XtmDlYPGlk7SU7W
         G/bdUyUZ08uvccm/IzY+CeIlmA81M8RGrStwvnMz//fYRAA1VXVkjDisoQERvEO8R1mA
         DtyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I4y35Zi4b7TyUSvgYlRHYNe2VBUp1PqS4Gk0Tv8DklU=;
        b=ZdV8TmP9MyfaqOMFgsNo3tfRKSZ77W+V6bWga6zUKAshL6j9YlmrKYHxwEmpJCAz/u
         Ui0Ywb0cWddxvaliSmd7GsK91ricpzyYnqrSlXl53ZYqWZG9vFoD+vHjJP+WNyGCIOWB
         g4t/Tt37v25dCsAdSnRE4zhhV0fhDrzlF4JrW2MNNyf0KQ339s6E+QOB8QWHJYg2YWGD
         fRuID0vWm8QPKEqeE4ZyVHdHNuCweJNCfFkHO5n1VpQAN9Y7X71Kys7HapchCrvCZB8x
         sulV3Uxutq7lMWibIJTWuqo6Tbav+gzs74n8PgfAPf8ScpZRdz4L588jP+hRxk8r3WD7
         z70w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5312WPukcfwCVSntJxy0qzyA5P5H6I8iE+/j+DdS/e7hwKOAEo4+
	YP22/C3zuQsOG1517sP9P4I=
X-Google-Smtp-Source: ABdhPJzkNAkva6BO0fCUD9RY59iLGBn8Qj00T58axWWso/cc5kreZyUxRV60cgUHhSsko+WpveYH7A==
X-Received: by 2002:a17:90a:c20a:: with SMTP id e10mr13800412pjt.221.1615558948194;
        Fri, 12 Mar 2021 06:22:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ed0d:: with SMTP id u13ls3825570pfh.3.gmail; Fri, 12 Mar
 2021 06:22:27 -0800 (PST)
X-Received: by 2002:a62:7c0b:0:b029:1fb:6b7e:8bc6 with SMTP id x11-20020a627c0b0000b02901fb6b7e8bc6mr12575634pfc.0.1615558947626;
        Fri, 12 Mar 2021 06:22:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615558947; cv=none;
        d=google.com; s=arc-20160816;
        b=qwaKmKtTjbqTbZvO14VvpAn2DibDKQWnjh9DdhnZtMAtutY0SKEEwWS2HvDVkptG33
         gXgRkbzcaK9CkQMA9nQ0ohP65LP1bQ1bH6eYXCVVNQgCAAadRC0ryEIsHhehcyvAksla
         Trja3eHJ/dlPdbRreZBCILjjuaC+daYEiZ4fBqO4AdSqXgMjBuhTRfb5Nbu+nDke5h1j
         iX3C/QthPTqG9udvODNtkVQmBMpcNxmzHAEpFzzQDAUVvMcbufkKQDYmMln+EG4YRRkD
         BqB9o00GIsh1uwu/MmkSDZRkrfDvCji0l8p1ZuVL/MAJzwKWvoug10oa5bWSbnq+zDvS
         BfVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=N8jOnQDZaK+wnyu5vcLWg2+LnZ/sUk9f81zR19rVsCs=;
        b=aivl0D1RzNxjN9Cd0HxDMzehelyHRQM0JSCIW++W7kyLvMlmsKkZpANPIda3lzNemm
         uYf3x/hTYfxVG0qvWRXObvemiQv/zadPhlYQtNLRINsQyAhNHgPs04n9LhBY/Xl1SJKB
         sQLabpCxQeumFkObJIMx8maMoHoZltn2XIcXv7/lYq5+Yob3csrvTDCU4BtleT2vyaQW
         f/lihI9CtCEUrRA2xHgpoZjjJR3WAXvDf3lC0g/CSCgI3RdGyUk7tI2+enXV4XNg1Dk8
         zNyfyIyuYtBN8LL+md1N78VQTOc92nMqqKoIrU+5othAfj5Hxgy6LxmI4qznOIySRSrt
         Jilg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z16si436434pju.0.2021.03.12.06.22.27
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Mar 2021 06:22:27 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1F63011B3;
	Fri, 12 Mar 2021 06:22:27 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 20DEC3F793;
	Fri, 12 Mar 2021 06:22:25 -0800 (PST)
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
Subject: [PATCH v15 2/8] kasan: Add KASAN mode kernel parameter
Date: Fri, 12 Mar 2021 14:22:04 +0000
Message-Id: <20210312142210.21326-3-vincenzo.frascino@arm.com>
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
index 3436c6bf7c0c..265ad35a04ad 100644
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
 #define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
 #endif
 
-#define hw_enable_tagging()			arch_enable_tagging()
+#define hw_enable_tagging_sync()		arch_enable_tagging_sync()
+#define hw_enable_tagging_async()		arch_enable_tagging_async()
 #define hw_init_tags(max_tag)			arch_init_tags(max_tag)
 #define hw_set_tagging_report_once(state)	arch_set_tagging_report_once(state)
 #define hw_get_random_tag()			arch_get_random_tag()
@@ -303,7 +308,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
-#define hw_enable_tagging()
+#define hw_enable_tagging_sync()
+#define hw_enable_tagging_async()
 #define hw_set_tagging_report_once(state)
 
 #endif /* CONFIG_KASAN_HW_TAGS */
@@ -311,12 +317,12 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
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
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210312142210.21326-3-vincenzo.frascino%40arm.com.
