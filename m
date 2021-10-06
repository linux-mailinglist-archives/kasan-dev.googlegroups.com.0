Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBPUK66FAMGQEL6O3O5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 267024241C7
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 17:48:15 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id c42-20020a05651223aa00b003fd328cfeccsf2346956lfv.4
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 08:48:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633535294; cv=pass;
        d=google.com; s=arc-20160816;
        b=bdQaRkkmCX+Gqk+rTaaTn2i+YKOznZOeV/rUb9c51ol4dba7eb0W6zkyxLP5t2AZ5h
         8iIsSiJLqglZ2iEJSzrPrAfqie/blUMSbI3vUqqlBdvYVJUDHMjfwqXy0U83DtuMfEPc
         AkFy/QX2vg6kHCDbfzY/LJmwmMuFxZnvLUUW76Y3nS2ixvLVeUWKREsgr0UxGuP9iWZS
         3x9VJKM+D/ps9NvSbA5+1z+etKuHMjy11exSjjXdy9wsGDSrN6igTS/2U+OH+tgl7VXc
         knLyJ9PM2GgN8A46mWYCHmhJAJeX2rW+z8i/8TqopFfLn5XPoXEJl055pcPX2z4qfiS5
         7tBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Hc8rRMPHr//b38KCgsBTHoji5/ws4yfbEgYJ5K4PIaE=;
        b=LVq9i2ap6LCQLsAFSNqncJNR+0MFZmUxu8TBFXRRnD5p2YiDTH4irXxWZzABXXvNHR
         cXCWo6weStzqWnS9wO+nevPfc72q3qwPYvWJGX0aTKN3cZSP+RXrREr952cxYvxwgOJM
         8gCkoSzTveiLE5bOTuOBTAK84t+bmIp9FucK5wHONkhuW0iRwfix5gKAhgxGV0FqRUE8
         ghYs0rV0O1GawODut/pdUP5f0drMFR0Ska40WtQwEZgalFg3UlEKJ8qDH1cWaCmg29sc
         wfqO/EiLG7V+Y0xFvYxKvDxWepvNcU46rBi1xVvGewu8QCLJtPyKduLj0xNOUx6m2D4e
         LhkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hc8rRMPHr//b38KCgsBTHoji5/ws4yfbEgYJ5K4PIaE=;
        b=cYxmVAVibvgzYltmYEil7KuN5CSm4EsS2BPekbgwxTWeZcDzmIi654BQ1HF+JGn1rL
         BN++Qeh6LDnnlosFR5nMHEuMfecqjTWZHMrgPJdNHhnxzoFxxC2CqD4pMX8ctMyaMUPI
         4Oa9TeM+YPwNQwguImoglbWLxyjleJrImGc1QfOI7yU/CJd8HYw/w/4w08znjx5KUhkN
         syUMuPBmqXvZdYB9+4n2kKYT3tanQUF01wKvh4AA9MVMEvaACLtOkGhWx6zJgvuRr3JM
         UA6gqGpIJdZsDZdKbub+DLTDOH2Swzef/dA8m2i2jIudzFbhGNNhgkpR5ofhCrtDAC7W
         YhIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hc8rRMPHr//b38KCgsBTHoji5/ws4yfbEgYJ5K4PIaE=;
        b=on0WI4vGvuTs9X8wDDdZNTyDPMXwzYCR4QSsFEXOT7GlIT+BMhykwZBFCk29eBbVqj
         ukGw/RbPNwTyNS4kjvzIbTUaOhnL5qDX8oaOyVHJ8O5LB4Z/eOE+P2qCPrIiCYkphg/A
         jpAVlzpJgtOWLeEarKZjJVVYNf9GhrYtQ7W5I2x28gcrTOc2w6mfQ9v2K7DFIGxZWQrr
         McpYzaMUG5uxqpCfRnha3TcEA/qCYhXEqZF1NKZZmoCCab9DUVD7tlkycAY0AJpHYHsw
         50IsKFbcnIea5f0XGRLarK6oVlBInOqm4X8e8D+jabIbk0fGydjO1En4J6lPjx6MRytt
         gOCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533WxgOGFjATCk05lJYeGQD53pYU8Gr1PiTvKkQisFIw6VibUtBS
	6oAe0IIxNq5n1x2k+5Sm5Gs=
X-Google-Smtp-Source: ABdhPJynqWp3sCHnJ0z4tb41DSvCAuuPGnfzpLYq4TZGGlOrQ4iu8nmvfVoRcevjvYtNycZ/wU9nqw==
X-Received: by 2002:a05:6512:1024:: with SMTP id r4mr10697320lfr.369.1633535294698;
        Wed, 06 Oct 2021 08:48:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f14:: with SMTP id y20ls279245lfa.1.gmail; Wed, 06
 Oct 2021 08:48:13 -0700 (PDT)
X-Received: by 2002:a19:7b05:: with SMTP id w5mr10236842lfc.212.1633535293714;
        Wed, 06 Oct 2021 08:48:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633535293; cv=none;
        d=google.com; s=arc-20160816;
        b=JCJHhic20Okga5LMdNZYUo23o+mp8zmTKHHXM0ihWRuiKPYZHAfA6zmQfqr+yruUpY
         WRfq8jW/YUzA2I4bVzZpxrlTziPyQGgikUmnNP2MrnORQi3yGLMdQ0vbGoX3aWsyghxb
         lafc7OBNBNq9+tKvCobnqJfp1X3zjqR+xjOAHJVnROecAnn/YD+hg4Of1gYagum40OXf
         qtJaZo6e+bJTHRHcoPgKlMbuAVFB9oJPPt/70Pd2Nkn27CGL53jVmU2EZfb/jxoeMmxr
         OAdCc+l7ipv5jX1jUHKb4BQSzGbW4NcaDFWxNMHLaOXcjJ1tvi4MtoS2RUq/h3lyBOrJ
         9rFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=mwMK+tugggfJrHBqQICAXoXSpdC8c8v+lFAZrdUZqRc=;
        b=EmjMX8u6oiZT742DsBArriY74VC+Y5X+uUpqmF4kmma0GpZwdPeaxSlF/9w0uh7nJW
         9EH3EBmCDIyYJKuGh8knOjkcF6E7eDMRlE+zvpQchLPhYTsB/IZUr4lxtmrXrdUdsLY0
         k8GEwbOT/GhWUWFAAM53X8XujtylFoPNJaSliVoJPr+zwbLpIRf5ZMdSiCHSug11auQb
         JFuGo81mU67LN/rM5AQUG65cHPrlS+AB/Q5v4hbESzhHOHKlM5Y6lDejfcx+CJvLPkNP
         4qzmaYoevGytcTHjyQj5AdaiuJcFayujokYnm6LJm4+bV6wOYGzbHo/XJbBAEmWGdHyM
         HhVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b24si166602ljk.5.2021.10.06.08.48.13
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Oct 2021 08:48:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B6F526D;
	Wed,  6 Oct 2021 08:48:12 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id BBA7E3F70D;
	Wed,  6 Oct 2021 08:48:10 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v3 5/5] kasan: Extend KASAN mode kernel parameter
Date: Wed,  6 Oct 2021 16:47:51 +0100
Message-Id: <20211006154751.4463-6-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20211006154751.4463-1-vincenzo.frascino@arm.com>
References: <20211006154751.4463-1-vincenzo.frascino@arm.com>
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

Architectures supported by KASAN_HW_TAGS can provide an asymmetric mode
of execution. On an MTE enabled arm64 hw for example this can be
identified with the asymmetric tagging mode of execution. In particular,
when such a mode is present, the CPU triggers a fault on a tag mismatch
during a load operation and asynchronously updates a register when a tag
mismatch is detected during a store operation.

Extend the KASAN HW execution mode kernel command line parameter to
support asymmetric mode.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
 Documentation/dev-tools/kasan.rst |  7 +++++--
 lib/test_kasan.c                  |  2 +-
 mm/kasan/hw_tags.c                | 28 ++++++++++++++++++----------
 mm/kasan/kasan.h                  | 31 +++++++++++++++++++++++++++----
 mm/kasan/report.c                 |  2 +-
 5 files changed, 52 insertions(+), 18 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 21dc03bc10a4..8089c559d339 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -194,14 +194,17 @@ additional boot parameters that allow disabling KASAN or controlling features:
 
 - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
 
-- ``kasan.mode=sync`` or ``=async`` controls whether KASAN is configured in
-  synchronous or asynchronous mode of execution (default: ``sync``).
+- ``kasan.mode=sync``, ``=async`` or ``=asymm`` controls whether KASAN
+  is configured in synchronous, asynchronous or asymmetric mode of
+  execution (default: ``sync``).
   Synchronous mode: a bad access is detected immediately when a tag
   check fault occurs.
   Asynchronous mode: a bad access detection is delayed. When a tag check
   fault occurs, the information is stored in hardware (in the TFSR_EL1
   register for arm64). The kernel periodically checks the hardware and
   only reports tag faults during these checks.
+  Asymmetric mode: a bad access is detected synchronously on reads and
+  asynchronously on writes.
 
 - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
   traces collection (default: ``on``).
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 8835e0784578..ebed755ebf34 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -88,7 +88,7 @@ static void kasan_test_exit(struct kunit *test)
  */
 #define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {			\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&				\
-	    !kasan_async_mode_enabled())				\
+	    kasan_sync_fault_possible())				\
 		migrate_disable();					\
 	KUNIT_EXPECT_FALSE(test, READ_ONCE(fail_data.report_found));	\
 	barrier();							\
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 05d1e9460e2e..39e34595f2b4 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -29,6 +29,7 @@ enum kasan_arg_mode {
 	KASAN_ARG_MODE_DEFAULT,
 	KASAN_ARG_MODE_SYNC,
 	KASAN_ARG_MODE_ASYNC,
+	KASAN_ARG_MODE_ASYMM,
 };
 
 enum kasan_arg_stacktrace {
@@ -45,9 +46,9 @@ static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
 DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
 EXPORT_SYMBOL(kasan_flag_enabled);
 
-/* Whether the asynchronous mode is enabled. */
-bool kasan_flag_async __ro_after_init;
-EXPORT_SYMBOL_GPL(kasan_flag_async);
+/* Whether the selected mode is synchronous/asynchronous/asymmetric.*/
+enum kasan_mode kasan_mode __ro_after_init;
+EXPORT_SYMBOL_GPL(kasan_mode);
 
 /* Whether to collect alloc/free stack traces. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
@@ -69,7 +70,7 @@ static int __init early_kasan_flag(char *arg)
 }
 early_param("kasan", early_kasan_flag);
 
-/* kasan.mode=sync/async */
+/* kasan.mode=sync/async/asymm */
 static int __init early_kasan_mode(char *arg)
 {
 	if (!arg)
@@ -79,6 +80,8 @@ static int __init early_kasan_mode(char *arg)
 		kasan_arg_mode = KASAN_ARG_MODE_SYNC;
 	else if (!strcmp(arg, "async"))
 		kasan_arg_mode = KASAN_ARG_MODE_ASYNC;
+	else if (!strcmp(arg, "asymm"))
+		kasan_arg_mode = KASAN_ARG_MODE_ASYMM;
 	else
 		return -EINVAL;
 
@@ -116,11 +119,13 @@ void kasan_init_hw_tags_cpu(void)
 		return;
 
 	/*
-	 * Enable async mode only when explicitly requested through
-	 * the command line.
+	 * Enable async or asymm modes only when explicitly requested
+	 * through the command line.
 	 */
 	if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
 		hw_enable_tagging_async();
+	else if (kasan_arg_mode == KASAN_ARG_MODE_ASYMM)
+		hw_enable_tagging_asymm();
 	else
 		hw_enable_tagging_sync();
 }
@@ -143,15 +148,18 @@ void __init kasan_init_hw_tags(void)
 	case KASAN_ARG_MODE_DEFAULT:
 		/*
 		 * Default to sync mode.
-		 * Do nothing, kasan_flag_async keeps its default value.
 		 */
-		break;
 	case KASAN_ARG_MODE_SYNC:
-		/* Do nothing, kasan_flag_async keeps its default value. */
+		/* Sync mode enabled. */
+		kasan_mode = KASAN_MODE_SYNC;
 		break;
 	case KASAN_ARG_MODE_ASYNC:
 		/* Async mode enabled. */
-		kasan_flag_async = true;
+		kasan_mode = KASAN_MODE_ASYNC;
+		break;
+	case KASAN_ARG_MODE_ASYMM:
+		/* Asymm mode enabled. */
+		kasan_mode = KASAN_MODE_ASYMM;
 		break;
 	}
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3639e7c8bb98..71b1b5d3d97e 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -13,16 +13,29 @@
 #include "../slab.h"
 
 DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
-extern bool kasan_flag_async __ro_after_init;
+
+enum kasan_mode {
+	KASAN_MODE_SYNC,
+	KASAN_MODE_ASYNC,
+	KASAN_MODE_ASYMM,
+};
+
+extern enum kasan_mode kasan_mode __ro_after_init;
 
 static inline bool kasan_stack_collection_enabled(void)
 {
 	return static_branch_unlikely(&kasan_flag_stacktrace);
 }
 
-static inline bool kasan_async_mode_enabled(void)
+static inline bool kasan_async_fault_possible(void)
+{
+	return kasan_mode == KASAN_MODE_ASYNC ||
+			kasan_mode == KASAN_MODE_ASYMM;
+}
+
+static inline bool kasan_sync_fault_possible(void)
 {
-	return kasan_flag_async;
+	return kasan_mode != KASAN_MODE_ASYNC;
 }
 #else
 
@@ -31,11 +44,16 @@ static inline bool kasan_stack_collection_enabled(void)
 	return true;
 }
 
-static inline bool kasan_async_mode_enabled(void)
+static inline bool kasan_async_fault_possible(void)
 {
 	return false;
 }
 
+static inline bool kasan_sync_fault_possible(void)
+{
+	return true;
+}
+
 #endif
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
@@ -287,6 +305,9 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #ifndef arch_enable_tagging_async
 #define arch_enable_tagging_async()
 #endif
+#ifndef arch_enable_tagging_asymm
+#define arch_enable_tagging_asymm()
+#endif
 #ifndef arch_force_async_tag_fault
 #define arch_force_async_tag_fault()
 #endif
@@ -302,6 +323,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #define hw_enable_tagging_sync()		arch_enable_tagging_sync()
 #define hw_enable_tagging_async()		arch_enable_tagging_async()
+#define hw_enable_tagging_asymm()		arch_enable_tagging_asymm()
 #define hw_force_async_tag_fault()		arch_force_async_tag_fault()
 #define hw_get_random_tag()			arch_get_random_tag()
 #define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
@@ -312,6 +334,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #define hw_enable_tagging_sync()
 #define hw_enable_tagging_async()
+#define hw_enable_tagging_asymm()
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 884a950c7026..9da071ad930c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -112,7 +112,7 @@ static void start_report(unsigned long *flags)
 
 static void end_report(unsigned long *flags, unsigned long addr)
 {
-	if (!kasan_async_mode_enabled())
+	if (!kasan_async_fault_possible())
 		trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211006154751.4463-6-vincenzo.frascino%40arm.com.
