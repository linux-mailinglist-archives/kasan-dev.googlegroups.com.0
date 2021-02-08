Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBQG2QWAQMGQEDLXM4HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 38997313A2C
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 17:56:34 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id k17sf2189911qtm.13
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 08:56:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612803393; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cx/CJ+y/Tdo2bIV9oN80EYmu5WXcZRpO6rW39mdYE9uqlpM3ld+zp5e/PoOyPaSbbr
         EBTZ4kLuM+DooatSawPwYOu6ce7jJqQHgFOKdtJSscoqgWoiCS98Jf4AEZAkb8V4KA+N
         c1Qw9ikpj0bleF9SSW/Bq34LU/4bCyF7qWbMrnDpwCZYzu/l2qpf6EwoRV7zZ2cgPmy8
         AxzYqu+UxJzRaAn+JofYtx7oqjKmk1K8YaSeyRqItmTkq65GcfAJIgIHtRcC4sK5gCAN
         HNVqkaZyS85Nz/IbqhtEHFAGAFLstWpBbjGmvncenR/2/vuJxVTyHPNzK5yp1Y/vQzKU
         09hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qUkyqHs/XsG2/af8cw+0N34RTiDAwbOzS+J4z0bgoOQ=;
        b=Vl3EZiW4ZJgvXg1RSqNy7m34t+pAN4nkactv80AYif1C1uMaAiSXzH8ZXOMgFtdr7d
         Oz55PkuvQ229FNynHD4eCS9Lvj9ixqobKwn5O9ILJzH7/yrm3YfC/KPzr4R8Vng5KWEN
         nu/pqWKCwEGlHuO+7QhGTWcuT8kUOkJ5B432R4yhRUb5LOhGwgyZUPk2Wgx796pC+AB+
         /R3zFo74qCNdfGqKG05X5MXXYKTYCuHZu2oBpPvbPWTX9pA+M71p3yFm/DJK+C7+IIvG
         QL+O/+iWzGAtC5qBefXAmavOefUTjzsvpKdi4uuPanmuBxHkwtS+sZnQD/I+8GneA1cE
         DQZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qUkyqHs/XsG2/af8cw+0N34RTiDAwbOzS+J4z0bgoOQ=;
        b=brvQxQl8k4EorkWW/cd5ujevWvwF7kKEa5PewPfBv80PM1sEh2UzmblRXgf4Kiuo2I
         9rSZpng9cjN2WlQPbY/LuDn6HHeKrdYU56hmEETENnOZVsxUSx0kbOo4Ml5d3Vol/Lir
         1VobShbwEy6EuAIR9dovH/ehX3f4uRPBIaq0jIlQH96gSea93mCknHX2ukRsK3gPZ3IX
         0EQ4zT7fC4/Aeltq365R4/5Ku3HRKdViC+OHNq2xZeU9NtMmufpEMTxVWLhKyKVgb93g
         qj3qfz10ehy+SI62otIM0c6oTdhnZIplKPMWgZt/mA2csxGHYYSKu3Wuq7xnhHljKKlm
         x9Iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qUkyqHs/XsG2/af8cw+0N34RTiDAwbOzS+J4z0bgoOQ=;
        b=qcY0UNJiE4ZKk/TNrUK0SNTzySDZfnZnztHDhu91q8Hkc85Vaq8/zOuGjLhcAkAPPY
         3Att2ZwrEI4CF6m7HmGAGDLCB1AkSyIB1IeRzbyRSAZUzu01+Ub9HGREzjV/3ZmoQsp7
         85m9o/ZOMbF/H3mqXcv5VGfOAaa4Bdhy0x8FmdWn/eZ3+UVffY8pi/+CiVPVcZgemSSk
         DjThyxfmXYG7rue5i1ovbi7AJ4kmTKTt1Qrvi0i62qba5NRkITf+7yK18928jBNdTBQH
         0iEeLtgSLkFzlzGvwuaam+3Ij1KvCS8fjGF9pvsaNEWlEOxgGiZECc/oWQZE+Ulx+Z9q
         expw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530EFZsZQzpVw8ZxDlQ0j+iRBXEpwd3PPqAYQbUdXYuQWeMOzO1p
	chTqn/ppsCYAbjCWXlgd4lI=
X-Google-Smtp-Source: ABdhPJxoik/KBCxbZamkp5itgkc4B4336mDo0Aqgl+qaClxRARsjSGev5LQ7moXG7SBE1w0ReWtkrw==
X-Received: by 2002:a37:7fc2:: with SMTP id a185mr18549262qkd.202.1612803392969;
        Mon, 08 Feb 2021 08:56:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1c91:: with SMTP id f17ls6525185qtl.9.gmail; Mon, 08 Feb
 2021 08:56:32 -0800 (PST)
X-Received: by 2002:ac8:13c4:: with SMTP id i4mr4682710qtj.383.1612803392592;
        Mon, 08 Feb 2021 08:56:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612803392; cv=none;
        d=google.com; s=arc-20160816;
        b=d4ghkTEn0eJn2md1/8CIcBFO1pRkqolW6vwSFQCw91CbUn8f/v1mCqSH2vFfHkoGFz
         yfMM3MyLzuVV8HCpAPVXd2yjQnCA80+dx+shvTzHP/y6zIYq3/ksBZIjFkv6ORC6a42j
         mFTSt+Yex7M3/RvMfEJ1nIlC/rwqB2ryQRowtLrxzIrFsc7uWvRyOsxwohVs+pk2wqNR
         ElB9ZK6qldQ5jUkKIC2U/6QKn5ioBXG8Ug8iMDUG6ZnfUntkAwtjcHS9sSKs3LLr7y13
         am+fZE+maiW+s5w7uwU/mLzhainqF0V6rkqbc+fZPAdapFgMo+zUvOaNWoK1/pXbbllO
         0fNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=UXXrbZBfD+YY3SNsPNzLip/gLYy1sP2zdXEILAa0VtA=;
        b=T0krXz9vMIXm+2pmVOXbD4zN8rdRpS+aFxaBWpNv8GY9ackIeZDrR7ch6zdfkeAsrG
         HN6uwcYpvgDs1jBqQ8Z9FkB1uhlfhgdTPRHQJnF9CAuBFoG3sStSydN206hUZJTVHiKN
         8UKl5KSRF3e3KpGBQqZHm0CMoB6WHg3Y51bs5ln6NbBpgLwgXBcZSNL5xehkWorkq2zw
         iVQpZ68YLaXXNpOd43mo6i/kPdGITRHHTIElzKh12bdGbjNzBMTDDh+vM078uqZhJB12
         43BipxFm8KYPuXtnhVbuScZLUb/TIWH03Ezy93A4dVCkZ1jTQukN0B6srCu4Ke07pbuB
         zZTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m8si1229009qkh.4.2021.02.08.08.56.32
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Feb 2021 08:56:32 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B38A11063;
	Mon,  8 Feb 2021 08:56:31 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D1A563F719;
	Mon,  8 Feb 2021 08:56:29 -0800 (PST)
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
Subject: [PATCH v12 2/7] kasan: Add KASAN mode kernel parameter
Date: Mon,  8 Feb 2021 16:56:12 +0000
Message-Id: <20210208165617.9977-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210208165617.9977-1-vincenzo.frascino@arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
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
 Documentation/dev-tools/kasan.rst |  9 ++++++
 lib/test_kasan.c                  |  2 +-
 mm/kasan/hw_tags.c                | 52 ++++++++++++++++++++++++++++++-
 mm/kasan/kasan.h                  |  7 +++--
 4 files changed, 66 insertions(+), 4 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index e022b7506e37..e3dca4d1f2a7 100644
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
   traces collection (default: ``on`` for ``CONFIG_DEBUG_KERNEL=y``, otherwise
   ``off``).
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index d16ec9e66806..7285dcf9fcc1 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -97,7 +97,7 @@ static void kasan_test_exit(struct kunit *test)
 			READ_ONCE(fail_data.report_found));	\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {			\
 		if (READ_ONCE(fail_data.report_found))		\
-			hw_enable_tagging();			\
+			hw_enable_tagging_sync();		\
 		migrate_enable();				\
 	}							\
 } while (0)
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index e529428e7a11..f537d2240811 100644
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
 
@@ -68,6 +79,21 @@ static int __init early_kasan_flag(char *arg)
 }
 early_param("kasan", early_kasan_flag);
 
+/* kasan.mode=sync/async */
+static int __init early_kasan_mode(char *arg)
+{
+	/* If arg is not set the default mode is sync */
+	if ((!arg) || !strcmp(arg, "sync"))
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
@@ -115,7 +141,15 @@ void kasan_init_hw_tags_cpu(void)
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
@@ -132,6 +166,22 @@ void __init kasan_init_hw_tags(void)
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
 		/*
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 4fb8106f8e31..dd14e8870023 100644
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
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208165617.9977-3-vincenzo.frascino%40arm.com.
