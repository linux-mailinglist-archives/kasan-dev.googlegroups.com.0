Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBXU522AAMGQEXDXVJWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id CCC143096E8
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 17:52:47 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id k33sf14201377ybj.14
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 08:52:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612025566; cv=pass;
        d=google.com; s=arc-20160816;
        b=wW6hTUbasqtblYAkDmmiANKZqRGYfloM+04i2Sp+kYRdHi41pbXJ8lACc0fCWpiA34
         KTTCiZtRi+ynMLv3H06XZT5H3wuil74RLuWW6fQ7/48Q4AxuzxlXS654o3LahNZWbx25
         WKkyhVua5Y1iVzICYzE/Ty+9cYP2CgJHkaH0E+A5Yt+HAAAilGFOYrjlEEAl6zBr3TqB
         JhUj5RX+FEY2iiW3sfzawaXpnJK8NScljdgo8ELC0AEsw8qM663mrHG8d8O/pks1iidL
         x5fS0X0jx0EWvf/X+pJ4zW8pfZwEpDXee6hUPEsjjoaVutNCW8rqftXtLRgVym9qCkil
         omkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=43ri9WGBBWKdb4O+Rj5C2j4kYsyYeGRP6xuJvQ71vg4=;
        b=EApY9zYiXZOKIFIwDg7MRzenH9JsLXnOjrnUTBqS0miXGT1SHc7Lj1BEqGoDnsvd9F
         2X4ITtht/OuzZYK7Lh1UbC/c/OwAHEW1I8kM/aHuXfgcDSXKmgUsroPPgHCJSp/4DJBH
         DNBNhcQ7zo0T5Ah9rRzHcF748mC3psbT1AIQmErpJD2fLqbVH+Hs2e2Y0YLXHvNxB5v5
         PR9+A9UnN1E1gqr9g4nEmYT4C//OrCBW2V3X/qx/czz0/roSswcBA4K+vgzN0gXjjLPJ
         vk4t3SpPFBt27NbPwQ+Os30cjbYb0TrrHpFUGSXDMFG5nATfXX/ezvCwYjR7tjakqbXK
         PzuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=43ri9WGBBWKdb4O+Rj5C2j4kYsyYeGRP6xuJvQ71vg4=;
        b=jkL9i78MgiWDdWvW9NGVHOCF3HaXwtw8hSraBaYQqK0rwGZZnSP6VpwSRMk/fYGzr1
         13N1eITPkao/MKgCXU09VBsXlJjIld4pEAGPBe+oSKnZXjmLCPu+aCvXuzw8MmudvuFG
         5Xz4vEccgA7XpMzF0ZixqkXX8/xu10+7uEBeRmfL9TFR9KMPLF75nLBjV1x3+kQdNG4t
         VSnTko35apZyrPfXSniIXsapj16uSqj6sbu2WlMz7LElGLhzR/D/aQTnMJHRT5WmMFQM
         o4rXq3Eup4ohZ/BH0JFOvpu6d6vYDthbtDPUcUN+AjGPpF6pYryFq62HaXOr+8iqZ27B
         6mEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=43ri9WGBBWKdb4O+Rj5C2j4kYsyYeGRP6xuJvQ71vg4=;
        b=Ry6hJGCdnjacIDIpjdwmAvraCUxaqi96FQt5mgqq4TbumXJDAPe7dd6/3RLUgg8I+w
         CYW9W2BKyD/A0XjMXFGLqvCCiPG2TX/f6ru3PYFusCa/XevhWg5OU2hnpB9ghzu9dCJd
         +i0hdtLEaFoGYtmNhej+K5fIdPpn5HbkN7d3fvkDzd9OaFWQRoF0ykB53P8y1lNot33d
         lThH4nNdoCCDCgBDGaVboehIvnWYT0PSa5ER2NerGGNi6qeZqiP1DK2GpdOUtX/l41ep
         lOec5rxFTTfCXtz6f+WfapRLCDJSG/aGWSo2V5xgicbPxywoUkP5G2nxlxdlE6x7BWEg
         B3Vg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328Wki5zfj3Vq/hLBj6x5BkG+67tlYUaLUhhtGeM9bFvSmsKO+d
	AbbwoZSPSp1Mbe5epfaI8X8=
X-Google-Smtp-Source: ABdhPJz/9IJ0SlN1NCAWhJYrZu6UY2qR6E4/dSKhdpa+okzW5IAOIZgdSB0dEBlCoNKUkFmqVXR2Og==
X-Received: by 2002:a25:bbd0:: with SMTP id c16mr13444476ybk.23.1612025566615;
        Sat, 30 Jan 2021 08:52:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:41c9:: with SMTP id o192ls2105736yba.10.gmail; Sat, 30
 Jan 2021 08:52:46 -0800 (PST)
X-Received: by 2002:a25:34c3:: with SMTP id b186mr14808613yba.325.1612025566276;
        Sat, 30 Jan 2021 08:52:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612025566; cv=none;
        d=google.com; s=arc-20160816;
        b=Z8XTFIzZ2oRTlWjlpyvaH1JirKdupQPK4gLYZQqEUUjlHZtRJOyG0iJhDI96IZzrYj
         8luoRc5kBgRFTZdq1r70Laa9/+dma1q81Y7iI62DilThRVWbmjwkgaVajFVa5deuE15U
         ICnBX0sjorqBxq2fNmR91+soV5weXt8J61QeHTL59Up4OtLnNhnFTkWzXjqPB0TXNoDR
         H3otJfNcRCyTYJLgp1ECH/njr6f+EcuufHo9nEBKRpD5CjjNZ0+e+dpeOlTpi/j9BbK5
         eowEMdzPB582DAOIwQYWI94XGPe91GJY2LQ8Gi2sgf8DpILSZHyBcjrDBU8kRTzr/ZqC
         Udww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=85GcEN/4Ibk06/whJLRXyPWK/DuTpKuUT8ULitK/NeE=;
        b=aGH3AYryAlLczw6aJNY7pnpgWsKMQc5vlEr3ua7P/7ErTkQmk5sxLmV1MJJYfCU/xG
         tWdxrMMg0mYK5+oB4DsjEdVRA7H+INgm2LDnb5qZY4j3tOc+cSAWwVF8Np2gUnYvhKNT
         yYTbHM6c9TvSkM6Dr0AuRmDyL7wa8fSy8zy/Olew/DcfAWQCBIcjLHx4GFeClvP+SB2P
         EAtHzaElxqBZzI7aA+a7wK0Jg1TnplHvEHROpHugL76NtNWXZjj4Y9O08nD+05V75qd/
         MmHYJKgpk1oxvMiLcZIRegXC6Vkg2IKUw4RcTdv4BQk2iljdgKMjFbmzVgOE/DSBBZk5
         8ymg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o71si261047ybc.3.2021.01.30.08.52.46
        for <kasan-dev@googlegroups.com>;
        Sat, 30 Jan 2021 08:52:46 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 82FB1143B;
	Sat, 30 Jan 2021 08:52:45 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 966133F73D;
	Sat, 30 Jan 2021 08:52:43 -0800 (PST)
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
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v11 2/5] kasan: Add KASAN mode kernel parameter
Date: Sat, 30 Jan 2021 16:52:22 +0000
Message-Id: <20210130165225.54047-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210130165225.54047-1-vincenzo.frascino@arm.com>
References: <20210130165225.54047-1-vincenzo.frascino@arm.com>
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
 mm/kasan/hw_tags.c                | 51 ++++++++++++++++++++++++++++++-
 mm/kasan/kasan.h                  |  7 +++--
 4 files changed, 65 insertions(+), 4 deletions(-)

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
index e529428e7a11..e8a5f5da2479 100644
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
 
@@ -45,6 +52,9 @@ static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
 DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
 EXPORT_SYMBOL(kasan_flag_enabled);
 
+/* Whether the asynchronous mode is enabled. */
+bool kasan_flag_async __ro_after_init;
+
 /* Whether to collect alloc/free stack traces. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
 
@@ -68,6 +78,21 @@ static int __init early_kasan_flag(char *arg)
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
@@ -115,7 +140,15 @@ void kasan_init_hw_tags_cpu(void)
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
@@ -132,6 +165,22 @@ void __init kasan_init_hw_tags(void)
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
index 11c6e3650468..b82f8bae1383 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210130165225.54047-3-vincenzo.frascino%40arm.com.
