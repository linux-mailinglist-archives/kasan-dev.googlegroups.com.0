Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB444SWAQMGQEUA3SGBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 82F7A318EB3
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 16:34:12 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id v25sf5814018ioj.15
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 07:34:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613057651; cv=pass;
        d=google.com; s=arc-20160816;
        b=EMSn6m8qJIBz6NssDaxJoUCi5/+uF6qNr8dhfqRUzU6/x4CMgSdmvoLq/lxbbAHwZB
         Lt8EvOljkO2J4D9pdaY4v6NLHRKcgT6BnE/JQ/DRHrlGRl0MsWLTUlyu8nqPpXAeRBx5
         FOb/Lcwu6smavJ29EuqFtrSMhZ/X1JzS+VorxStm1uC41uY0Ni0s7yvtDRB1vloFu/Kv
         ro/WKHViecyTe0wrMmc6VbE0Z+8AMobZBPYhpedcV4Q3DZEaq0JSU28Xm9vU18F3YSdL
         v845wGm/0XChE9nIvPnVWSarGQhTIUkVjZlZNqpMD4fll4By0PkNxV75tn2nM24e0kGk
         Hj9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rwusrCCB261CHD0+no/S4oszvXcn72Twylez9hoOw8A=;
        b=E3RInklh1LTpXY7QyT5Nt49wWoGOGjoE3sUMltVIMvPBhWxgT/soeNmzucuW6N79yT
         zHQST4U0zXdwXWCxdV/wTNrj0bZASV4aClscx3GvHOKK7W2FawyFoYPC0Sy2O4E5LS97
         AKjV0bdiyThf8tdS8P47vb2To82JcuColiBhcNzHoApwVd0meeiEh7vFvbBSl6Jo8+QV
         Ah49UqkMnIiS3sjvmImcH61IrsUnjES3dqFVrWmy8nxT5GsJqprE91nLz+bM9B7gI3a3
         bfNHBL0TI6WIdjUQlnSJKAE80E4Wdi8fpGiZOAS2ioifs5xuxMk7PbtjGJ2qYnqeIkVp
         TmSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rwusrCCB261CHD0+no/S4oszvXcn72Twylez9hoOw8A=;
        b=n/9UAWT+sx6kUc8muWhxyD8389PFhg1V/+IcGA5e1YGLkTWQ6mzdqaCU+IkvyoA3XW
         //opcP8RdtEGIfz7g3iOo2EQni0s0M5bwlbgvfuDdZxuXp9SW8S/LdbqVyK/o5t0to/Z
         pdjC94ZPsarFFRRjfczpNd2LoVdJ5FEhtY/Ec9CiwN9RvjWwQwih+PI0LJ1XpLsQCX8/
         A9qpHkAp0RP8IRlG2rLXlZTrUiT/naOcl89nzvKNADWJYzEb1tDiAy/ZXeVsVfgH434L
         KxfrYuQQUHveeGsowFwcT2DBBk2Ye6jo/mWAeZWsPfk6HUEbkFBqwcXP5JQO7QZUWPs5
         UlEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rwusrCCB261CHD0+no/S4oszvXcn72Twylez9hoOw8A=;
        b=jj6AY5sMGepfTmpCQdAbr/tkrVr8A4csJPAaO7cq2PrFbCKILtB4PPRK258QlGC3f0
         4EA6zzerPgcCpCKO3DMIw027uX7ItJcor6j0kmz4yIFmEoc3D/HwX769s5OFMr/z3E2Y
         h8ZrEouMES1yqabSYcRwGfnXnE3HDlEU4ORNEEp+CcjllT1IQysRM4snbmM9iCTcitlG
         gTEutydzyH6sXBaKNTLKkc2fg+XcTCZ5aJIHXkdA/6EPFKa8RmU3SXjnooeibIeFjgll
         pS4FoPgFQzeJ8CMTMJ2myynFxMlXyNK5ltUzgmWyaj+poU9ueh1LEoN4ZjYewmtOL+Hq
         eu+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PhAVnUfFNz0ARpVfOBFpNY6GMvCSAgmLIB6rJmQIVtLcmgwGh
	JOPphXgMj6Y4eKMp1+JslhU=
X-Google-Smtp-Source: ABdhPJySfMFma95nMuiRk9NkMNQqYi99LTaOwM67sFL/ek1X1neavupNJ8xTyntRxgep/jEEcVVNMw==
X-Received: by 2002:a92:7307:: with SMTP id o7mr5740022ilc.266.1613057651604;
        Thu, 11 Feb 2021 07:34:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:b44:: with SMTP id f4ls1602738ilu.6.gmail; Thu, 11
 Feb 2021 07:34:11 -0800 (PST)
X-Received: by 2002:a05:6e02:1a49:: with SMTP id u9mr6125025ilv.140.1613057651157;
        Thu, 11 Feb 2021 07:34:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613057651; cv=none;
        d=google.com; s=arc-20160816;
        b=Q5ON4PJvMdcjbgcgSQuHkkwP62qxySSI8iYQNoCiYTvyWI2z8N1FV7/EdIFuYbUUXe
         rWxLFmUynpglUPsSpy0aJ9vCtW8kfN6OVgRbCj0zyeNJ06hYmcYxdFK4CSEouLoA6CqD
         ImGnTqnAhR2spaSLXY6BJg7R+2hFMaglFXVjhrIzt3T6wMpk+H19SX1y0w+ixJmbdobV
         Gg8Q/VttW5joN6uSvd67x/6gguhDdJXfMolrSftjIFmUegoamuXDKQxlEjOdbr9z7jvK
         5iE5wnHES3FkjoFjuKmFsQgTSDMlB81xXSeJd/KwnPsjPVTo3kIh2+iJKld3kX1/sv3t
         Beyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=75pN0AXoTzUhnS6g5qXMCdw2qP7PB5E/lDowe6PkUtw=;
        b=f+oh7PU+ksMDtSZDQWNd1z0jHi1yO1W0DXJQkROr2wc+JZt/XfJBO/N9ggi0tQiNa8
         kk9whl6YqpLb+oQef+ZdmRmJvaAahDHqygjbI4osRBkMe8HXMdD24pcbr6FqN3Z5/pPm
         OrbKt/C2KyeuTJzKR94iuLqPm9WcFNXP8Bin+vhTFtv2xMl6R/eZWus/NMVRlGezsPHx
         RgRyRIODTowVAtMw16dOxxXhhhaQB5I+1ugIcV56OvACXzaXVJiGiB9bQPDPnmU3hXPw
         S9YBnwgSdolkpoA9ck9YpkVz5IURdWA2a297dcWl/2fovT4HeN1yxNCQcu48geXxZtf3
         MChA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o7si264629ilu.0.2021.02.11.07.34.11
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Feb 2021 07:34:11 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id BEBA51396;
	Thu, 11 Feb 2021 07:34:10 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D23C73F73D;
	Thu, 11 Feb 2021 07:34:08 -0800 (PST)
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
Subject: [PATCH v13 2/7] kasan: Add KASAN mode kernel parameter
Date: Thu, 11 Feb 2021 15:33:48 +0000
Message-Id: <20210211153353.29094-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210211153353.29094-1-vincenzo.frascino@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
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
index 1328c468fdb5..f8c72d3aed64 100644
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
index 1dfe4f62a89e..bd249d1f6cdc 100644
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
 		/* Default to enabling stack trace collection. */
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index cc787ba47e1b..98f70ffc9e1c 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210211153353.29094-3-vincenzo.frascino%40arm.com.
