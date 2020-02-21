Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3FGYHZAKGQEU4TKWHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 227B21689C4
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 23:02:21 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id i123sf1511462vkg.8
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2020 14:02:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582322540; cv=pass;
        d=google.com; s=arc-20160816;
        b=mWK3PlMFpnErKKLLkaZ3jAaW0YllL3YaSlVILrRVoKlhVnGNGzoyZBfxa54B+DwX8H
         BOiTKcrdUorTpKZapo41J/LzOpO0dVzqg0OCnNiIATMQIYEyQ5JEuNJ6iLBypOIo2/UE
         SHcDtqVDBekR+udq2pH6GmP54WPlQbUchfjzJpllOkAL1RIlMA0EIqj0uxOiqmCyqW14
         2d3pHMVOsjeUPGyPfYBwC4D9aWOeXrTaIsR4oID5oi8u6P9OK/OEooSEFM1ZW5YEj1fC
         UsjIIzeARnbcDfpy2QS0Qrb+By0WrrDNf9/pN3OWMrIWgw2xNCnlBjIkOUpXdZyTNDe6
         0d4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Jw9jqjJd4+AfQzgJcWkqwfwjsGjirhCzBoD6prkVyg8=;
        b=T4ryZlCxtYuV1tPKD7O1QG7JLpAQ+HsyOsa0m90whbdGDqaVdDvyOM4yVEYZxXshTV
         7V3XNx1KAfRbhhfpDPIpTu/8mG/WqjnCmQgq2bxU2AGkbxmDzzwghoaCGip8+JjbNIuB
         lP3OCiVmGj5hi7D7qXpn0zCbQfJc9eiudRZVKR0HjyytvZttNPZ/DjVPu9tf1ow9E/Ci
         19B8sP5zf3RSpM7/5/qVtAAGPo6B26sRZJjIfNKEpF7VlTPW/x8T069UVPk2Eb1l7FPg
         igWmrjx6P60nBxbt0TKe09e1AunzOkSpLG8m1v0t9ShIJkzRjQO5jdSPy6CJ157xzY4w
         R0mQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZoE90Cpv;
       spf=pass (google.com: domain of 3a1nqxgukcuwsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3a1NQXgUKCUwsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Jw9jqjJd4+AfQzgJcWkqwfwjsGjirhCzBoD6prkVyg8=;
        b=Jub1zmOngMfgmLnNLRB6nGQZF/ZKpahmC5rgbBClqQBOKqoZi3biGsZJ4ueoVnhhhk
         g8mamCVg2XsHdsNzeI1WqegSDqsLnpq9DA8SLeTpOo5vqnNvGO4crc2NF8PWh38dHAYW
         gSc22qZ35Ke/7/g/yPpVzXGrXjwLC8eDi1KfgBOWTYmR4KD0nucpB1j4+PuJtAC3I4ha
         CF0wd60C/OQZmGWuK1l+7YKqZbvK4q2m9J6h22IQXuLH+9/fZ9BfseiBgkOOA2BBCloh
         +IwWm4kTrXRipuI5E/arV6vOgggSIdUzEcMCc2Mt5jBahfTfghq7AOx8qSZ5TRozGK1+
         Y9Rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Jw9jqjJd4+AfQzgJcWkqwfwjsGjirhCzBoD6prkVyg8=;
        b=bkuNHexrAm0MgVCV45r51eXNVsbkkefoOCM70f3KLGZ1vHOlTqmaadUVwm7ZJ9eoXZ
         BnfM9iv6mSEG8VPe81XiNtLeAM/pLJvlnEPGwKEjZBJhcZDD0CfcXrkVB21NOZqc41gl
         O4Cu7nu30zOaCQ/Rlm3ouAQPf20Sno8DOKECCTKS/ypRMBAUFd88ciocA77AYpB6Kw6R
         UBd+TooZm3ViTq63glVY/RMJgAYlutoTXuoN/YaXSbf4gZr+GVMG8KznehsxjtKU2PTT
         FeRgDsnPyy8doTRQ/Ao9XQHoaoEeCyxJ5SS14bdN7e8QYI+Bf+gmSs/82FOnia4+uhgx
         74DQ==
X-Gm-Message-State: APjAAAWcSdvxHpKT7niDiAHMqtTASqO48/0sj3wmXz7vKs2P+C0aSn4m
	+XbAHf0n+9QwlcLQq8MiDvY=
X-Google-Smtp-Source: APXvYqyt86EOk4JVWLK+47Ev7FjdhQbxCVYZ21IqiYZLIep7D6BQJCJQ4iE6Nqp6gp9f5MYlOESQaQ==
X-Received: by 2002:ab0:14a2:: with SMTP id d31mr20038579uae.106.1582322540077;
        Fri, 21 Feb 2020 14:02:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c805:: with SMTP id u5ls421113vsk.2.gmail; Fri, 21 Feb
 2020 14:02:19 -0800 (PST)
X-Received: by 2002:a67:f41a:: with SMTP id p26mr22033111vsn.222.1582322539634;
        Fri, 21 Feb 2020 14:02:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582322539; cv=none;
        d=google.com; s=arc-20160816;
        b=oYflZu9gQrH+Awo6wPJv0fA7qojB4icZlUHtrHTIiy8p5SzTwhfgLsGtMOA08e5mJl
         Dfd5SHpvU9+UnODu231jdG7Ba7T+q9VHHQD95G15o/0aQGiWls/hTYPBH6QdtjhhEO2i
         mww2tS6Aqi1qohBe7iVH8VIgHwW3DGqhkaB13lF3RaoNBQ4XNhaGXkItfW68gwUP87Fs
         l2rD9MfBcKBRCSZlD7tl7X1QtsvSv6DGSnsHMQuwo9XJb7xo2+0z88Nowao4xxM6vDk5
         ZnEmh7AgnFG2KRN662zrmkTn8biIcBXxDOddfVN1Jo3WFMY/72GOxx+0ktxWkhHv5kAP
         osrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=qAY3yRNcz+SqxQcajuyksWGgOqqD86eoH5VmlhhevrM=;
        b=FsxC2cAauyndCl0JI3Kp8aavor6Ayp21T+0er1BOMBWkuKnH7PHxqSTQB3AI2lSL02
         QAZkISJJusNiMjfIW/7vjdGleQe8AZ4bigYgqcF0krDlxESgvuY5lITw71MM7ISxkOn7
         56J1mwUsqcPlKPt0DO8yERhXyOs7oAy89JGfKDLv+ZkiibaMXTEoFefxqT7AGKn7GcLF
         6O+mr6LRAxXTlW/2JuZCuj0Oq9xce3N1bsXy+Rxf4p1ZJS4LnEeKnHq7uEkrJKs1M6K3
         7bRWmYGlZrHNhws0GHc+kUT5gQvfCc6A9x2APnLzRzohwJm9QOMRwqAXjY3kqeonS1wK
         getQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZoE90Cpv;
       spf=pass (google.com: domain of 3a1nqxgukcuwsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3a1NQXgUKCUwsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id o19si290240vka.4.2020.02.21.14.02.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Feb 2020 14:02:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3a1nqxgukcuwsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id m8so2798381qta.20
        for <kasan-dev@googlegroups.com>; Fri, 21 Feb 2020 14:02:19 -0800 (PST)
X-Received: by 2002:ad4:446b:: with SMTP id s11mr32028833qvt.148.1582322539123;
 Fri, 21 Feb 2020 14:02:19 -0800 (PST)
Date: Fri, 21 Feb 2020 23:02:09 +0100
Message-Id: <20200221220209.164772-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH v2] kcsan: Add option to allow watcher interruptions
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZoE90Cpv;       spf=pass
 (google.com: domain of 3a1nqxgukcuwsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3a1NQXgUKCUwsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add option to allow interrupts while a watchpoint is set up. This can be
enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
parameter 'kcsan.interrupt_watcher=1'.

Note that, currently not all safe per-CPU access primitives and patterns
are accounted for, which could result in false positives. For example,
asm-generic/percpu.h uses plain operations, which by default are
instrumented. On interrupts and subsequent accesses to the same
variable, KCSAN would currently report a data race with this option.

Therefore, this option should currently remain disabled by default, but
may be enabled for specific test scenarios.

To avoid new warnings, changes all uses of smp_processor_id() to use the
raw version (as already done in kcsan_found_watchpoint()). The exact SMP
processor id is for informational purposes in the report, and
correctness is not affected.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Change smp_processor_id() to raw_smp_processor_id() as already used in
  kcsan_found_watchpoint() to avoid warnings.
---
 kernel/kcsan/core.c | 34 ++++++++++------------------------
 lib/Kconfig.kcsan   | 11 +++++++++++
 2 files changed, 21 insertions(+), 24 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 589b1e7f0f253..e7387fec66795 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -21,6 +21,7 @@ static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
 static unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
 static unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
 static long kcsan_skip_watch = CONFIG_KCSAN_SKIP_WATCH;
+static bool kcsan_interrupt_watcher = IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER);
 
 #ifdef MODULE_PARAM_PREFIX
 #undef MODULE_PARAM_PREFIX
@@ -30,6 +31,7 @@ module_param_named(early_enable, kcsan_early_enable, bool, 0);
 module_param_named(udelay_task, kcsan_udelay_task, uint, 0644);
 module_param_named(udelay_interrupt, kcsan_udelay_interrupt, uint, 0644);
 module_param_named(skip_watch, kcsan_skip_watch, long, 0644);
+module_param_named(interrupt_watcher, kcsan_interrupt_watcher, bool, 0444);
 
 bool kcsan_enabled;
 
@@ -354,7 +356,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	unsigned long access_mask;
 	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
 	unsigned long ua_flags = user_access_save();
-	unsigned long irq_flags;
+	unsigned long irq_flags = 0;
 
 	/*
 	 * Always reset kcsan_skip counter in slow-path to avoid underflow; see
@@ -370,26 +372,9 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		goto out;
 	}
 
-	/*
-	 * Disable interrupts & preemptions to avoid another thread on the same
-	 * CPU accessing memory locations for the set up watchpoint; this is to
-	 * avoid reporting races to e.g. CPU-local data.
-	 *
-	 * An alternative would be adding the source CPU to the watchpoint
-	 * encoding, and checking that watchpoint-CPU != this-CPU. There are
-	 * several problems with this:
-	 *   1. we should avoid stealing more bits from the watchpoint encoding
-	 *      as it would affect accuracy, as well as increase performance
-	 *      overhead in the fast-path;
-	 *   2. if we are preempted, but there *is* a genuine data race, we
-	 *      would *not* report it -- since this is the common case (vs.
-	 *      CPU-local data accesses), it makes more sense (from a data race
-	 *      detection point of view) to simply disable preemptions to ensure
-	 *      as many tasks as possible run on other CPUs.
-	 *
-	 * Use raw versions, to avoid lockdep recursion via IRQ flags tracing.
-	 */
-	raw_local_irq_save(irq_flags);
+	if (!kcsan_interrupt_watcher)
+		/* Use raw to avoid lockdep recursion via IRQ flags tracing. */
+		raw_local_irq_save(irq_flags);
 
 	watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
 	if (watchpoint == NULL) {
@@ -507,7 +492,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		if (is_assert && value_change == KCSAN_VALUE_CHANGE_TRUE)
 			kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
 
-		kcsan_report(ptr, size, type, value_change, smp_processor_id(),
+		kcsan_report(ptr, size, type, value_change, raw_smp_processor_id(),
 			     KCSAN_REPORT_RACE_SIGNAL);
 	} else if (value_change == KCSAN_VALUE_CHANGE_TRUE) {
 		/* Inferring a race, since the value should not have changed. */
@@ -518,13 +503,14 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 
 		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert)
 			kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_TRUE,
-				     smp_processor_id(),
+				     raw_smp_processor_id(),
 				     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN);
 	}
 
 	kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
 out_unlock:
-	raw_local_irq_restore(irq_flags);
+	if (!kcsan_interrupt_watcher)
+		raw_local_irq_restore(irq_flags);
 out:
 	user_access_restore(ua_flags);
 }
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index f0b791143c6ab..081ed2e1bf7b1 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -88,6 +88,17 @@ config KCSAN_SKIP_WATCH_RANDOMIZE
 	  KCSAN_WATCH_SKIP. If false, the chosen value is always
 	  KCSAN_WATCH_SKIP.
 
+config KCSAN_INTERRUPT_WATCHER
+	bool "Interruptible watchers"
+	help
+	  If enabled, a task that set up a watchpoint may be interrupted while
+	  delayed. This option will allow KCSAN to detect races between
+	  interrupted tasks and other threads of execution on the same CPU.
+
+	  Currently disabled by default, because not all safe per-CPU access
+	  primitives and patterns may be accounted for, and therefore could
+	  result in false positives.
+
 config KCSAN_REPORT_ONCE_IN_MS
 	int "Duration in milliseconds, in which any given race is only reported once"
 	default 3000
-- 
2.25.0.265.gbab2e86ba0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200221220209.164772-1-elver%40google.com.
