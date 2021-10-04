Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBOOF5WFAMGQE4S3SUDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 65FA6421861
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Oct 2021 22:23:22 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id z22-20020a7bc7d6000000b0030d5c26120fsf299810wmk.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Oct 2021 13:23:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633379002; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qsr49/i+TmWXDDLeqD+EfUjVzn85csA9vTmJPFw+xO+ePhDA1Y6YdNv/FOdBDnuwwi
         e+1xASv9DFHWywXEeZwbGJBYkHGpsAM78azFyZcjxELH/lJ3lkc0zGZFqmpr0eBrOm5t
         gBJ4jd/fSj05DZNG9AtJmKihopyuLymQFOle6TmXUZni4AgGUf63vptP0tZ+k530N1AK
         9nSGkfriP73APShVKwUX52YrkwVNCrZc1K6ufsW03vyo8QAby6GiRSvynoMZUKwzzUw3
         DqQ8IJt6ZZlNpR2yWK6Sg14nLiygo9BoMPG1folvz9tWUumWmj8qrAV5Ba9CM+jx9sEM
         onAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ldN3AzpFW8qGZJ/Uwm95QG/Y1ZUtYPDrMVn0sCzbf4U=;
        b=KOimfmnMibnkIQoidZGphSENx6c80VrI8Phs0dq/QZrY5HCFXXMjblIKN+YVmg8SGN
         PWsPasyjlcHb3/JoAPyXoa2CxehlDj+aBr9tMX3GcnCLET5vhB4+SC+8+LG9H0RO1e5B
         J+Hz2qWo/wnwAEPPHXzL6wUDmoiMOZKb3wdpANfMZFrHu+L1kC9eGk0AYb2J3iq+ynQW
         TgFZCfbSUh64EJ+E9r2pmBkvlByd0TZdJTF3KNAu6+/MiHxg38Ei0eC4xR8E0+IqpISg
         jxtGUNhrl9W7iznkJG5Ya29ikgxs5kUINtO/dqYrd7pdOBtqh+pOUtpXoWLHmhWzYXGH
         rTqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ldN3AzpFW8qGZJ/Uwm95QG/Y1ZUtYPDrMVn0sCzbf4U=;
        b=GRfWQ5ywTJox2r3579fLu+0lN1i7VwLxAn4vC4wiHGtwp89P8ylPo6Sqa/mw5tYttJ
         LIXnPK4E7Q9wX5MDs/UiSALKJ347jyffCn3zNq2/dwlqepYejAG/xJzycHlidqhsOFcP
         IWlmL482DMdZX2gxMg6wSRF54bfkkNnX2zHc0Z4W9g1CsB6U1X3R+PURRdv8LrMj7sLx
         FDC/OiGpIP6oRhORy3kZ/5oC8mMYhZJU8wLUhBkQxCFibtFhKdWfJZs/rGqkE0BksUWt
         /xRiZ3vUx2i2bUpqU3Q7RzJihFdzyYwELAjbwYkm8NGJnxcOzzmYFAyvhjjs1Qp5VzYS
         YfpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ldN3AzpFW8qGZJ/Uwm95QG/Y1ZUtYPDrMVn0sCzbf4U=;
        b=Q/TW3BsgZNMVTcmvDNqNqe0Z2SYFRW1oVW4TFkbo70AssWQSkR2Z9v3rF+PW62ZWlr
         kMcnQljTXMbiMPUcM/ieP9rLj94jFIITW7tcqHINUdKLiodmQyy/c3su+FDoS+9yAXlC
         dSik/amErKorJ9i1ecC4OwME+g6sXJAdN+qmjQRugSQf2JE7qCro56kqd6AdxnZvR3aL
         m1FqIZ0W8Zojr9Qr43QElkJ1AMqDqVGRGPGCQtRkIkwBBnBPebHpZctibnsWEqR36y0v
         FiCRvd6WEzrOXg4pYwin+8D7E/A+W3eM7CXej7nV2fxii45VXH+jCReadzAkoCBB1Lns
         MLjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532vVw+mpMN/2Qc/32HafTi9SHJPnvLN/omacNPkzivHRG1fZYzY
	KvO8Gs9ErFoebtTTEgTiLfs=
X-Google-Smtp-Source: ABdhPJyT/NDqqc3ehNr3oDqKf321xAqsVrI03F4w8j+SO/60dlCJPVbhS3aKE+noXJPw71k6g3pL6g==
X-Received: by 2002:a05:6000:1c9:: with SMTP id t9mr6159982wrx.389.1633379002135;
        Mon, 04 Oct 2021 13:23:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c4c3:: with SMTP id g3ls10346719wmk.0.gmail; Mon, 04 Oct
 2021 13:23:21 -0700 (PDT)
X-Received: by 2002:a7b:cd82:: with SMTP id y2mr20385582wmj.106.1633379001316;
        Mon, 04 Oct 2021 13:23:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633379001; cv=none;
        d=google.com; s=arc-20160816;
        b=Bj+YqZQ56ZpQ0QksXBbmY4jFmulNJ6emVY7jDkPUzrZpNcDTH2YkprNC6bFTFVxyX5
         dShjjRLixMeCjXdg7fVsyW3fYcIt1dffCkzqW8Y6dubTSq9RQWsop+r9uRTpfKRoSRm5
         m9IFqlKtcL46UngOt4sqGxsl1/DQYVEX02sGr55q2EHDAl+tNbiiRBaUxb0HtPJ1I/Fq
         EunBjhtZHSKI3w16mlDMN+j7aa+78MvJDIMYvNHM/norOo4kHIqEPVfytcsPhh9rBHXk
         tY/M9Aq5hCG/Ff1Ns7yCYpBcuvsDRb9KEsGE+EhdBYJwMs/CpAiSjXAPlUVxKv57gy5z
         cOKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=GXg6Xh8H1TQWAMVpwijzqfRGqasqm+QHiQJY8DVwWbg=;
        b=M4PTN2Auifj0MBpuQ9W+dK584wkxyxZpR6QIPS7z+nPyi6tmOYi4d5sfYsIRD0+pym
         Gwo359qdd55doPuSko41SOivorqawU89yWj2Tzv+u1z8G49/BsSUtjnR9kX0325oZrJX
         t2LkivnY+0/Fvc+DmYijLpzBCe9bhy6TJVItpbboFoh5XVmYsihCVT1S3NULApVp0gZ8
         r5kZB1RReT6ur5WXc1Sl9mO16fU3YBHVgcBmVOW6dOaDE2/Tjc/vZxS89FVuPwInLUbj
         DxTa93XMSA7pIAQHY3qHRFQ6Y3n5P3fvzVw6VL+dFVD+2abU+Q3JD0J8YHaJ8rimwDT/
         A9yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s194si430143wme.0.2021.10.04.13.23.21
        for <kasan-dev@googlegroups.com>;
        Mon, 04 Oct 2021 13:23:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 82065113E;
	Mon,  4 Oct 2021 13:23:20 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 7F6253F70D;
	Mon,  4 Oct 2021 13:23:18 -0700 (PDT)
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
Subject: [PATCH v2 5/5] kasan: Extend KASAN mode kernel parameter
Date: Mon,  4 Oct 2021 21:22:53 +0100
Message-Id: <20211004202253.27857-6-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20211004202253.27857-1-vincenzo.frascino@arm.com>
References: <20211004202253.27857-1-vincenzo.frascino@arm.com>
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
 mm/kasan/hw_tags.c                | 27 ++++++++++++++++++++++-----
 mm/kasan/kasan.h                  | 22 +++++++++++++++++++---
 mm/kasan/report.c                 |  2 +-
 5 files changed, 48 insertions(+), 12 deletions(-)

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
index 05d1e9460e2e..87eb7aa13918 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -29,6 +29,7 @@ enum kasan_arg_mode {
 	KASAN_ARG_MODE_DEFAULT,
 	KASAN_ARG_MODE_SYNC,
 	KASAN_ARG_MODE_ASYNC,
+	KASAN_ARG_MODE_ASYMM,
 };
 
 enum kasan_arg_stacktrace {
@@ -49,6 +50,10 @@ EXPORT_SYMBOL(kasan_flag_enabled);
 bool kasan_flag_async __ro_after_init;
 EXPORT_SYMBOL_GPL(kasan_flag_async);
 
+/* Whether the asymmetric mode is enabled. */
+bool kasan_flag_asymm __ro_after_init;
+EXPORT_SYMBOL_GPL(kasan_flag_asymm);
+
 /* Whether to collect alloc/free stack traces. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
 
@@ -69,7 +74,7 @@ static int __init early_kasan_flag(char *arg)
 }
 early_param("kasan", early_kasan_flag);
 
-/* kasan.mode=sync/async */
+/* kasan.mode=sync/async/asymm */
 static int __init early_kasan_mode(char *arg)
 {
 	if (!arg)
@@ -79,6 +84,8 @@ static int __init early_kasan_mode(char *arg)
 		kasan_arg_mode = KASAN_ARG_MODE_SYNC;
 	else if (!strcmp(arg, "async"))
 		kasan_arg_mode = KASAN_ARG_MODE_ASYNC;
+	else if (!strcmp(arg, "asymm"))
+		kasan_arg_mode = KASAN_ARG_MODE_ASYMM;
 	else
 		return -EINVAL;
 
@@ -116,11 +123,13 @@ void kasan_init_hw_tags_cpu(void)
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
@@ -143,16 +152,24 @@ void __init kasan_init_hw_tags(void)
 	case KASAN_ARG_MODE_DEFAULT:
 		/*
 		 * Default to sync mode.
-		 * Do nothing, kasan_flag_async keeps its default value.
+		 * Do nothing, kasan_flag_async and kasan_flag_asymm keep
+		 * their default values.
 		 */
 		break;
 	case KASAN_ARG_MODE_SYNC:
-		/* Do nothing, kasan_flag_async keeps its default value. */
+		/*
+		 * Do nothing, kasan_flag_async and kasan_flag_asymm keep
+		 * their default values.
+		 */
 		break;
 	case KASAN_ARG_MODE_ASYNC:
 		/* Async mode enabled. */
 		kasan_flag_async = true;
 		break;
+	case KASAN_ARG_MODE_ASYMM:
+		/* Asymm mode enabled. */
+		kasan_flag_asymm = true;
+		break;
 	}
 
 	switch (kasan_arg_stacktrace) {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3639e7c8bb98..1d331ce67dec 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -14,15 +14,21 @@
 
 DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
 extern bool kasan_flag_async __ro_after_init;
+extern bool kasan_flag_asymm __ro_after_init;
 
 static inline bool kasan_stack_collection_enabled(void)
 {
 	return static_branch_unlikely(&kasan_flag_stacktrace);
 }
 
-static inline bool kasan_async_mode_enabled(void)
+static inline bool kasan_async_fault_possible(void)
 {
-	return kasan_flag_async;
+	return kasan_flag_async | kasan_flag_asymm;
+}
+
+static inline bool kasan_sync_fault_possible(void)
+{
+	return !kasan_flag_async | kasan_flag_asymm;
 }
 #else
 
@@ -31,11 +37,16 @@ static inline bool kasan_stack_collection_enabled(void)
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
@@ -287,6 +298,9 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #ifndef arch_enable_tagging_async
 #define arch_enable_tagging_async()
 #endif
+#ifndef arch_enable_tagging_asymm
+#define arch_enable_tagging_asymm()
+#endif
 #ifndef arch_force_async_tag_fault
 #define arch_force_async_tag_fault()
 #endif
@@ -302,6 +316,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #define hw_enable_tagging_sync()		arch_enable_tagging_sync()
 #define hw_enable_tagging_async()		arch_enable_tagging_async()
+#define hw_enable_tagging_asymm()		arch_enable_tagging_asymm()
 #define hw_force_async_tag_fault()		arch_force_async_tag_fault()
 #define hw_get_random_tag()			arch_get_random_tag()
 #define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
@@ -312,6 +327,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211004202253.27857-6-vincenzo.frascino%40arm.com.
