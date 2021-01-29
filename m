Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBMFR2GAAMGQEMR4324Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 42225308CBC
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 19:49:22 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id a12sf6471046pfh.19
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 10:49:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611946160; cv=pass;
        d=google.com; s=arc-20160816;
        b=C+Dih3dBQ1Xah2fKVv32Vftbq76d8JT2ifjWWCKK4D/+8JyK3XKIHNPIq8RmhGhjvv
         PWINnoaSF9fUs2LkpxPc2/BbR8THpdSChkGx1ePUZ0+k/8yUiGwhEZjUL1YAa2U27eQR
         JDWPFJtg5rfEr/BF/5YHQeRAeqa4spjniVqCAEZlFQAfqRu6eApoJS59rju/oCFMr0R8
         w3m+P79dYL9hh8Qpxbm5D0iMcoYsiLuThKtJVmcSEYWdE9pq6ide7lruqG9VOwxkNxPY
         YS1HamgCvNIb3TeV3/dgfEbtv36vG3IQf0wCOMrlAMX1Sp+ohXQ2xcAq+7A7RDLv+TnA
         11gQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NVH/RYvpNxs6MqgLJlCtldoaxo0VExsOwfXfBC81iEA=;
        b=SptS5qgpjILuOBCTS5W/vDe1EDKY0By4xJq6EGKOXOZqMc/+2VwLRymfDmWwn70DKc
         eJ3Hgxhd3pTvqLKbbu2FInkK4wF46HCeELcAuixA0Nk7Uu4+FmHxZCBIEqW8Qnubqvrb
         UzZ5qzk6o7M4M2GoqZLuzrR9wQ5a2CAmd0NH3bUC5XzLHftEUGUQlQOaKazr4IeYPHzi
         9FVH91NkdK0xKYPUitgYflmZKJUtPiahVzKnbQaRBx+1ThxOjITwUKkt1E3OSL1wpCy7
         kpayYu1zDRUGVspUScHBKBZFlmFQT9xMkSPHx4v4xRtF3aX8HP+16Ccf8Fwyr6uxz3fG
         Bkrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NVH/RYvpNxs6MqgLJlCtldoaxo0VExsOwfXfBC81iEA=;
        b=nt72mGqcpSmq/yRqXegd7j/F2ocFTmxngTIJ7Z3mhZMWqXjldFN3mc2pfPHluxLT6W
         Km7BzgqLJuHMTtXHsymCQf8vEc4Jh/lKd6L02wpi6OqWkY+JfSvZs/fgZuIXrH4GNUAg
         3QIVYuolbdI9/0VXBUj7JHJwwUpvF0sKNudXNfXuIsFS2HvuYtUgcW6Ux8p5aAqNtOJB
         tPgAOznLMZ0FUQCBxraJPccmEcZIgcpzOdYWxjJqEd/molRHok07Y8Qld2X9rXe7GndJ
         2tC5wVARLdPptKBqZ7Rg93I9ONsATuRBJvaKdPFPvrmOBoO8wkKi5rTBYwMlEu6L/MvT
         yKMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NVH/RYvpNxs6MqgLJlCtldoaxo0VExsOwfXfBC81iEA=;
        b=nvjYNdQtzv/AVYr8jP2nfMd8sQ7F0wWJQ8V29J+8E8FJDUl1WoMMeg8eZNUQ+2Kba8
         kDnJHYQ3XjaZWzToy+ZN2futauWDLYO1aFStN2G+KsDGpVqStvl+CVXXNEHW5FP7tzTW
         4b+QoEh46piXmYPq1sXwfLDWhEzHIqRSJM1gKS5PPPcx/B0myav/AgW11d1B3ZerE8vV
         0qvqK+s7B/UjYQU2vpP6j+aos8q57Kq1iz7aci8Kqcd7zTbHRqMHV7TXDjDOCtVLXFyA
         oWVhwYJ4oy+uoPYNTLs5X3VbJsnF45m4yutJNQxJds0Jpw2+CHxgXMqeTHy41Vla7B2z
         gyIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531NLwug1DJrhs/8+Rg6EMIYkI96vbEMeLa4TqUL6WWApNiZ1Ab6
	rd+MM9xLG9EbA8P+74TRPyU=
X-Google-Smtp-Source: ABdhPJzox2+kLJ7FWVGXC2gCEuyG1Tp1scnQlWvAtWWWn/B1sY2SHvs81rc5M0bQdTYUE7FkwMx6hg==
X-Received: by 2002:a17:90a:470f:: with SMTP id h15mr6069963pjg.179.1611946160666;
        Fri, 29 Jan 2021 10:49:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:550b:: with SMTP id b11ls5093023pji.0.gmail; Fri, 29
 Jan 2021 10:49:20 -0800 (PST)
X-Received: by 2002:a17:902:503:b029:e1:82d:bd4f with SMTP id 3-20020a1709020503b02900e1082dbd4fmr5772550plf.28.1611946159895;
        Fri, 29 Jan 2021 10:49:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611946159; cv=none;
        d=google.com; s=arc-20160816;
        b=JYEPvzTbSQoXSD6ZLjt8tUZrrFx9JJ3EJUEAILC9UbH3WH4sZR8FykvlLlPNOeDIAM
         NNqy0ywclhmOrPZoG/s6myXGYmx8Cf7sokq7Cw8DwSEjgX9qlurmVw7pFwjunHrkDqb4
         qy5z06sl32zwxUuKNVfDjVjtLOeAjO3e1+jVTx4g9PyXOgnxPSSzUEKxrJOasFdvB4aa
         0l24ggDuLQSNP2lbkTjGDmNQOYb5I3duJ5sEnFAs8DFZbRHrHsCFTJvlz2b3r+BONtyJ
         PSW0r4/ZnyEefAhmmjx8IpddsHSnm9eXHAUaZH17AE9WhXS0r/ons+Kfjyrhv6hK3YWI
         EqLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=jmE8KSryT2mdvoKK4HYXg9xfx1e/2OPX7Um3+rQE69Q=;
        b=vqbtE9yrXDw+53gFIQSlhp/hZUDMZ2EKx1RPUmkUGxkVQTbYcVmUxylzB/1L6iqLgt
         B4/21xE47FRv3ENCeW1o4nZ8pgw5dhrHwQI1JFMYSYZ6LW2/3fQIa0qKuG7DgIFlpS1I
         kt1Mjeu7j0rstcJL1qOXnHOyrNhpuld154HDMS6PvrEIyXWlWcx3S046rg9wqzO8BhDc
         honWdexXYaUFccmlu9cnVJ/iO/NBMOCXET5BRG7+UQIlfGzo4ZOeycH01HAP3QAur7km
         vhnHiYqOHBn6wqJ/x//l9SStyOHA7nksZskJ3rWXlfpDsbuIq8JeLJFsmZKN60EJzF1q
         WC0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r142si558888pfr.0.2021.01.29.10.49.19
        for <kasan-dev@googlegroups.com>;
        Fri, 29 Jan 2021 10:49:19 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4D8541509;
	Fri, 29 Jan 2021 10:49:19 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 86B5A3F885;
	Fri, 29 Jan 2021 10:49:17 -0800 (PST)
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
Subject: [PATCH v10 2/4] kasan: Add KASAN mode kernel parameter
Date: Fri, 29 Jan 2021 18:49:03 +0000
Message-Id: <20210129184905.29760-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210129184905.29760-1-vincenzo.frascino@arm.com>
References: <20210129184905.29760-1-vincenzo.frascino@arm.com>
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
Tested-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 Documentation/dev-tools/kasan.rst |  9 +++++++++
 lib/test_kasan.c                  |  2 +-
 mm/kasan/hw_tags.c                | 32 ++++++++++++++++++++++++++++++-
 mm/kasan/kasan.h                  |  6 ++++--
 4 files changed, 45 insertions(+), 4 deletions(-)

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
index e529428e7a11..308a879a3798 100644
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
 
@@ -68,6 +75,21 @@ static int __init early_kasan_flag(char *arg)
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
@@ -115,7 +137,15 @@ void kasan_init_hw_tags_cpu(void)
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
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 11c6e3650468..07d5cddf727c 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -294,7 +294,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
 #endif
 
-#define hw_enable_tagging()			arch_enable_tagging()
+#define hw_enable_tagging_sync()		arch_enable_tagging_sync()
+#define hw_enable_tagging_async()		arch_enable_tagging_async()
 #define hw_init_tags(max_tag)			arch_init_tags(max_tag)
 #define hw_set_tagging_report_once(state)	arch_set_tagging_report_once(state)
 #define hw_get_random_tag()			arch_get_random_tag()
@@ -303,7 +304,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210129184905.29760-3-vincenzo.frascino%40arm.com.
