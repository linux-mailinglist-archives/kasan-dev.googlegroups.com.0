Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB2NUVOAAMGQE5CWYYGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id BB03D3004AD
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:00:10 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id u8sf3863695qvm.5
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:00:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611324009; cv=pass;
        d=google.com; s=arc-20160816;
        b=1HGi2yn+7kC2vlkVKT92Y3PkyINJADN5f7aeHgNfFd/qT54s9ICTY8kOcQ8GhWdsO/
         kg98wfv31UodQlF/yBsXqy3P4yRhtLe7vfCHkuwrilLqQ/zqnZFtmY1XQyjDY10Bg3IP
         mvV84zTuHOdhdFS8pneVVxe8ezr6naXt1FjEy9SPBg4SlsvUhBBRr192OXxWQ3WeQuox
         ynLOBVkKrO5Ix5JDFC298gcsHvnr/TZD7PNnGvsCamsyBRuTI1YRiyqb5ehao1FernbC
         X6CmKaxN1dCLG0fvcMaV7IB70VtRJuOi5zR5cc1c4vbcQzX5R+/+UD/247cB2z8WEEcs
         L52w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+vJZa8KrdfWIAuayZ4eVffmdLLYcovWY/eRGm40xhXA=;
        b=honE70u7bnlethAETAEsKVqodm6XA7bfuEU1f04wkAlElte/qXFUJwleC56BTZkJ+f
         koZqiOHopUF+gjlwHqvSvQsKfdJUsQz85KnihkgHV4sWFTIi9m+cNhhlVWQzK4NaiivK
         tlBA2eNI1Ec926b23U+BITPIq2zVQRxRSwR5K1i4LEUtMDRBDT7YBV1Avkyh/Zdw+7q3
         ZsPnnKAZSu/xDKb2PjcHeO4BZz5ceODe2gyZrwAbHWeKlcorgrGfHjg9aDCvfKyAd5UD
         4cash3eJIpsFG6E7u4/jUjAsExni8so7PHJ8o39T5eVpgRWbNe4gQXGPKTvDwr3sD9Sj
         9lJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+vJZa8KrdfWIAuayZ4eVffmdLLYcovWY/eRGm40xhXA=;
        b=SkRNw7iA1ZBy/brEIKZGqJzlHPZTw8PDP+L16G60TK5XTA32eHhGfeTsMsdZvLBL8v
         Tw4rlVuhdW77/vu6NWkSXhag2Bw2gIqC82+3IWrHyFA23c1Nnb+ccyr4HusRjw2dDrF0
         ZVcU9k3c/NmSNE62p4unjzpbILnzF5wnXo6FktdKgmnngVvSQ8nUJaLvJjkhYr6RmAwR
         bJyXK66mBrOKkvtrpSxpqG4XgW4HuFmLY17PUmdgfO9tLV7rnpdAkofW7fcrdEBrVzkL
         +PU02yh8iNXRoPg+tvvWOt6iY/WPN1Hpc/US7J2dYdkGMRLEjbWu3eMiOY6cftEkkTFN
         0fbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+vJZa8KrdfWIAuayZ4eVffmdLLYcovWY/eRGm40xhXA=;
        b=cQN89RDav2SZGIl5T0yhQQzTATplwEJMAGdAUteMweIa1kTnDdyg6mlz+aQPzVOzW+
         tjTS9gwOuM6UV4Vsk2qF+v+03d9c6nL/h5F9hevJZc4CwS6dAGn6gxCUDf7HpvH81kRG
         gJB63FhjdtNUkqOpiCQbgIZFQVqGS8AI2ZIR9KQq1wH647k4wp6/WqhnA7cJrUHEvI6B
         AQuxRHkjpK8S6ozdl1+jGMCGE5JzwInDv9k6OOrBLxzqXZTnY+2BBeolmQV8Jw8GftAw
         0tR4lB1vFxQVtzQKnq/nF7jF2KMxraFe0QLQ5yY8APvFhDFixp1LV//ypuquhBKkfltz
         gSlA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531vgXCnWqnvvPioIra/C+yhNxZxwFzNfA9ttebxXzw7CzP35Lwa
	9jqgR7hhNbtIA82Y6vRLG9o=
X-Google-Smtp-Source: ABdhPJy/GJzEef89kxzF0GDbMdC9Ma92inrIKZNqhZvfu9RhcVO2+iZjRhi0Nne1PCYGXrWgOFIWVA==
X-Received: by 2002:aed:3284:: with SMTP id z4mr4391379qtd.17.1611324009425;
        Fri, 22 Jan 2021 06:00:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:f501:: with SMTP id o1ls2856717qkg.6.gmail; Fri, 22 Jan
 2021 06:00:09 -0800 (PST)
X-Received: by 2002:ae9:f70a:: with SMTP id s10mr4701221qkg.416.1611324008914;
        Fri, 22 Jan 2021 06:00:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611324008; cv=none;
        d=google.com; s=arc-20160816;
        b=mvfRuHcYoV5hX1JP7o6DBFZ4zyzQTphcGMOenOkRyCu/fQnxA+NiUOZRc4Zsr2Opq9
         exGWQMO7Pussq8Fa5HsXu13KcjEB8HykGCsN3kI8rHXaMrrn1NAmp/Hh6DTCE/WZr6Gy
         k+cK+yWvKv/IqjPhNuf0l+ctNW18E/40UlFZ/cOcShpa8swcjeq/H0O3jd5cz30hPx8P
         PNVBvG4XoMAMTmi/D/gjxOd/zntt14Vro3SZIxe71XGQKuuL+AmHnjfUnb3jRLu+fG7h
         z6FAcCCHxn2I7ehMJk3NajEHyf5/IaVeyQXAflC5xj7bLB1WF57IeYy13aM6uNjJFN6r
         r5Bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=bT/eY64hTk8N8T7E6ls2cetFLFpcd1hei82NbuE+bx4=;
        b=jpRaRRr8uNPbpbc1ploUe0F+2EKrbPyWrg85n1iUzkQeTEqnYgGbgp0Yc6z6E4v788
         RMjpKBGR/mkpio04KEe2RT8FEOEAwbe2YCYMvK6HKMU0m+u1ZUAJF6y8pqOk+gj9+NBB
         9LduIx9MgxIjkKx8Csn2BehFlfgp6j5FiX3qjf39rNter+AoUPIooM6DE7XSU96d/n/g
         H3TF/FX0CVzgobJxn3PcEG33TIWbedBnfV3/xHo9iuYyVU311hvDu3i/JcJuRjLzpxlP
         4b/jrjh0JVRYZnXrtW2tTfGq1/IdxUo3E6pbZQsS7Rl5Zm4ErMGhaDH2QIlP3qRPPmrY
         1TjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h123si477733qkf.6.2021.01.22.06.00.08
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:00:08 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7B86A1509;
	Fri, 22 Jan 2021 06:00:08 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CF3A33F66E;
	Fri, 22 Jan 2021 06:00:06 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v6 2/4] kasan: Add KASAN mode kernel parameter
Date: Fri, 22 Jan 2021 13:59:53 +0000
Message-Id: <20210122135955.30237-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122135955.30237-1-vincenzo.frascino@arm.com>
References: <20210122135955.30237-1-vincenzo.frascino@arm.com>
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
index 07ef7fc742ad..3923d9744105 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122135955.30237-3-vincenzo.frascino%40arm.com.
