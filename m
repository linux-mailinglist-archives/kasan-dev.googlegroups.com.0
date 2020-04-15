Return-Path: <kasan-dev+bncBAABBJVH3X2AKGQE7SJYMLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id A33891AB0C5
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 20:34:15 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id d7sf675560otc.14
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 11:34:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586975654; cv=pass;
        d=google.com; s=arc-20160816;
        b=NTaHPYKEPZ3T1/IFDPd16fuTODdnqzfZbt4L/Lk8D8Wpuw97PoeD41ioN4bWEAce9W
         BUONKDehzEkDmJRsbVVvcvfC6H3RL75w/lQ+D798MWnk3rc5r5YNTs60MoPVj7R874Wo
         8987csdsB34lIhQqR07Wr6P276qdVAPzWg2Kq9PC6ByIYt8N0UJ4HR5+8On8TNuXOu1F
         bYVYL93FZQyIjTu01hw1gMicG6s5fOf22nA8nx6qxweHCKIOVjGLemYUCRFJ6KWb/ymn
         kXZ873YHQ2oGzdjgBTANbOOPxcrtEzukkoqpXoY+TOgJU9yZSyGOOiD2NwQ6+FBlYlzZ
         Osiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=GEPLOaxDS1LCDrJdsIBTmFmpmWXCUi4H6oghstRryAQ=;
        b=VWxU4b/j7e2jr9i9zDA8P0Sklc3WKaz6qJYYPMH8ypiomwxErPPSpexE1usc6Yqifc
         MWV2SKvSzXk3VQsYQvIJPse/iQu1I/hCrMCauHtp9ZqjDVrEf734fC7+8YZTK7ZQmnu+
         msB2gkk1KpcH8j2PiSvveJVzJdwfKQJK83RV+pBE0C1/VGjskKUrtSQ7Jw2gsWTd1xJf
         nDuWoo1L7dEqnsksmkNOfTJWFMcQgPYUwoeZZtXYdhD0fhle2yjbBoZoipLjsE91l0K0
         jX/VE3iL706ioMrgsuogO+WDGk7mdu3Hm12pKMFbDsk9jH5odaV4HJhPavyan6RzXNGc
         ZbvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=h9oCWi+W;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GEPLOaxDS1LCDrJdsIBTmFmpmWXCUi4H6oghstRryAQ=;
        b=eTY0OVzR/8bgOnpkDjDV4Wwl0FT3zCKw534EECy056LYAErXptgTCmSwpgN97xR6O9
         AMGh4ww4/HdKG4d+y92zGzhyYNSCBV2Gk4n37ZUwpi2GPP4EPcWLdOdTUu3VccGSxrVB
         BILLiPczM9GTQn7/Ol60FkU2uKSeqEsASG31f/ZxOJHSjsRJEQ1KDi9LahnKE5N215Fs
         MGhg8tGNA5kxWZhhQ3fL5EOgwA38QOdcaNx/7ZmbVqnMOnPm11F8CgxG5+fIyAgILjtg
         zFrox8Zb55bBzFlo2csi87EL+2mBQaSMyzFtyhRRAElzPgiaYG5QTRzJqYT5AVfU1WoJ
         fGhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GEPLOaxDS1LCDrJdsIBTmFmpmWXCUi4H6oghstRryAQ=;
        b=SDQ7dIXO/9Mfa4kGA/7wuw0tjHdg5iMeWljIdpVSnk7sDjvhMsxFHTpbJleB0hRcao
         7I4pFEiejc631AKIc71TWaZcbIqc1gyGIThurFxwjR0gZXTa0oUWiJrv7TtlH4uZPrq0
         mvmopsb8k5ja3U1jLNvsubnPSPO81ILRhtbJt3HfeVxbyVAUGQZ6P1E1o4jGuZPqoMMc
         tXRqPzinZRNOVCL2vwg7xfEfZW6mvM7/v3d6aF2MMLuT61gP607lYoGwMaeJGyT7712V
         nfzRKmHgdS24bkiRwLtWjwzuR749UNVmNGpS36cQepdwtL0bUFFFwElPJA18pRX0K6v5
         aYTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaSa/fKaOfJb+NmYi/ci4Hn/wtpNhfumN11xPnsXlF7eqL+2m2i
	O0kyThK7/mYlG8nGyDDDf2Y=
X-Google-Smtp-Source: APiQypLxYHWBEQsYfpeXcp0r2TLrDVGWCkIOzul5Ap675uYylKJrITazhfMRWZBaNaxoDDHc4QMs7g==
X-Received: by 2002:a05:6830:60b:: with SMTP id w11mr21197596oti.96.1586975654504;
        Wed, 15 Apr 2020 11:34:14 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d485:: with SMTP id l127ls1630741oig.9.gmail; Wed, 15
 Apr 2020 11:34:14 -0700 (PDT)
X-Received: by 2002:aca:31c2:: with SMTP id x185mr437801oix.45.1586975654051;
        Wed, 15 Apr 2020 11:34:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586975654; cv=none;
        d=google.com; s=arc-20160816;
        b=eTCUjSTx7hyUTsMPOWB67K5SqdYJB0+0TwfgXSnyOBDEgMj0NWLiM8ZmKsjSUEM4Fa
         u5T6ppY5GnNogM60flAC0Knu7LJxxXONFPhyZg12Ntgl5x8uYRdh1CemdD/f6IeQ5E3c
         XUTXxN+iwrnMJUcipoxuv7jImvUhyAE8CiisOPZSRdAvNDKY5BQd923ptLwpM1AySadc
         VAVqJ7p/UiTHlwv2vYHnVY7hWX75lIwTbLa8taL0VGxWjg0KgFmsRcCP7WWUzoohGN9Z
         iCR/PL5Q4Ho24jSz3akfzT4557NpHBJSDpsRTYMYqV+sbO95RaSzNTNFiW2fjOL6UwrM
         Cwiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=eWGBcE001Nfqh1Kr9iZ9lJurjyZZWLCAUfrneNwABTI=;
        b=nipOdyEDUFc/K2GbNAyQ0ch/iorhtc2zNnJfcFsF+EZ7dJG9Q1THKzeVqcMqqvIPC1
         InLgMXRujR1nn/Ava+6WbPJYbs9wLBvkokByqikLVjFhEVHuO5FQ3PgyIgubThK24ys8
         wZSMIo9zIouUSOKBFypJQI+ZKjwP33pcS2ENqgqSTti7ke+vq/23HazorFO+8MqQT001
         O65I8AMClq+BSyRzeL50ZhM2rg6SO1knGb57ynWybij+bi3HVFLzZ2NU4IX0VLM5JrVq
         FKziB0w8ii4gTUV2d3P8LMS9LODwsyBk7+kLD8gatrt0ufq8IYVVeFTKEeMB9w3IOMEr
         Xy0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=h9oCWi+W;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x23si1164414oif.2.2020.04.15.11.34.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 11:34:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 197A320771;
	Wed, 15 Apr 2020 18:34:13 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH v4 tip/core/rcu 01/15] kcsan: Add option to allow watcher interruptions
Date: Wed, 15 Apr 2020 11:33:57 -0700
Message-Id: <20200415183411.12368-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200415183343.GA12265@paulmck-ThinkPad-P72>
References: <20200415183343.GA12265@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=h9oCWi+W;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

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
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 34 ++++++++++------------------------
 lib/Kconfig.kcsan   | 11 +++++++++++
 2 files changed, 21 insertions(+), 24 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 589b1e7..e7387fe 100644
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
index f0b7911..081ed2e 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415183411.12368-1-paulmck%40kernel.org.
