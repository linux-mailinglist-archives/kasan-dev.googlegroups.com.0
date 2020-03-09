Return-Path: <kasan-dev+bncBAABBPVGTLZQKGQE2HH7G7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A57A17E7DF
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:31 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id s126sf6225535oih.6
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780670; cv=pass;
        d=google.com; s=arc-20160816;
        b=gb1bSR/av72fH20cqIXiFcJEw5u+r2Wz0lcQSA8TaryMtA/yvYf8ajrZ+FJHJ7LZ4S
         Aac1nf5LUOWqU+TYAJcRNVxEV3AJPDxLcETcg/DhBFWf6tglzm0N8JIVUudUc8IaHMN5
         vf5X4TfwdUpGeN18X5NVii/kfjXb26jdUOladJo6EPaR1/hgvFl4cxC1XX3eyRmjAIZV
         Q+kbZ096qiYVurg3VHmvZ9U7+fmei8w59xhlFTheDbIXBhZaM2FflPHJ80tpi7hLD/4f
         VtAoBLD5gINf5A4mieges5GirS0f/StXikJ+mXkT0pG/7teWrhlyHfR8TO4Vyaz0QK9I
         At4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=adxuLFMut1mnq2BKD6SA/nMwoHkmAlPBYdo75RWsOtg=;
        b=M/QoCvTRlp6cRD0PSiyxWLCstJCpMiA1x6ROlwW5XVSuVruHwJMJScTgZD8jPZuWhX
         N4tIjAdEmgelBQ4bTfuWk5VhqIAuqkQYp/d9PbygK6uuX8uh0vPfA7WPEzFD9wq2CJjG
         +VefhJN1pnFKPXuVf0KVtBEQAwEYU0E85rilQCR9TCxTuxl7T+7FvS7Hfp2rvIZXKmko
         eM/AzTdF2hGV7g8uaTlRd3yOI2BANl+9vwoAk9wtXbJ+KY7LsepjyYfu1pEnkiR8S2g2
         zgrsSdaPYZbO+6OhJPRUewG2Cw1sPc83GewV5ls23k5Gmaah3tdG5hGqcsm8aS5wEaYo
         guqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=mKc4vzID;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=adxuLFMut1mnq2BKD6SA/nMwoHkmAlPBYdo75RWsOtg=;
        b=QXmknJbITHzY9GoqIp1mCuBNz8IvAhbfq9t0lfFPZpA031uMiLMwLj2OTnw7p+0EOy
         s+XMsMjND2XYIfQA7ntmtTikqkc2wC3OhJ3GmS5vqTCRny8QvYrigOh5RVbWTS0nvbnw
         4PVHKF1Cm+89y1zioO0RQJGlz4e4NQJCxL5YRg8L8jcogsh7wioBgZ6t8yJtpNMvnTZa
         bo2dybiJ4sQoCV9gc9rQAHwLwosc93+yQxztL5Ay+PvMBc9OJMB9huwPZyEXagPzYmTm
         SCySCu5DMQmD/BMFNQ/pL1aRxrIURnOeX0D3b4ezAIwKSh6/sdCq889eV+KJaeHwtEfM
         vsvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=adxuLFMut1mnq2BKD6SA/nMwoHkmAlPBYdo75RWsOtg=;
        b=j02blS3FaJNu7zkNajX/fAooYvDBzBeNQAUEaQvSBSF3M50IgelAb7KZzyUx0JRFAD
         9pUI+z7VUIKhUyO0z42/rKmVtNAsGaekp7orPbypuLp+44PlJGlctbFvVEgdwQ15gq71
         inoq/AuuVOFmgd+LKREa+9Uf6kp2B9ClttRMW5T+blOnNtsU69VZRUTKhXK/EUSNdT3W
         AfKypVS611UBIeGxrPwPicz4E55FoNohToKC0UMm33XUUDVpUdL8Mje+zdruVg1XyDk+
         wkvz5JAEYoeAFw+D9aBIeguJPwUTquMdwv/y2+Sc1iUCFU2GFE9B+9Y4r36hWbGT/xur
         AavA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ36OtZhY+ArjqAXZdkWKZ01mwmKMKNkxh01eVmMshrBrRkXvhDg
	71cq/fXFQjICDYDtYiCD7iU=
X-Google-Smtp-Source: ADFU+vt6MWqUspi9c4+L1QivGlBH2koG4xY8/ZdPvRoLP7TupWl4HstDivEejCPxMnnB/z3blqzjHQ==
X-Received: by 2002:a05:6830:114f:: with SMTP id x15mr13920410otq.306.1583780670191;
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6143:: with SMTP id c3ls3554323otk.7.gmail; Mon, 09 Mar
 2020 12:04:29 -0700 (PDT)
X-Received: by 2002:a9d:7c97:: with SMTP id q23mr12524930otn.78.1583780669791;
        Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780669; cv=none;
        d=google.com; s=arc-20160816;
        b=IaDHHnqiOa9/+yM/0OCDS1IOufJ6T7sAAYjbggF8MkqufNG/rSB0S3dGI/osH5qsJu
         ZwWMT8aHMB4ywMlVmlU4xoJqe9j92Dn5Yv0x4KKwlTTmLkjnHUwiZ4Z0OH0FBRQpCBRn
         dIdBktltmlc1mF5XcQJ8KMUGhRNXGE3mq+JNOViOD3z4NsBIi+47Q0gFpdEQIQc/0JKu
         Zmf7FnQNSnk6QBKjc8tR78ZoRBcC2LZVfVJ8+Au+80MBG0kTQEyJetWGetp46JSyMv09
         zxzUQGQERw2ib4PTy4u4rOifTL/Ts/GFdcVMGTVxrXJRJl5Oq5/3USF1AKqV81RHOO40
         eIFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=eWGBcE001Nfqh1Kr9iZ9lJurjyZZWLCAUfrneNwABTI=;
        b=t+8Fm7bni1q5HhrYFi5vBJv628Mu4huIUkYfZxh26KqC0W/bVIIY/yipiT2CXkVsBi
         U8NmzU3+MuRI9vZpdX8ERVr4XEmrUZr02veLw5q9bShfzNQMqDPYJkqm7e/1U8660Pjc
         aWKVZO/LwJtAyIRjJzr0kZcFYsiM1OpxpPar9c2ah5OPWRt/pyBkBQEmM621eLA3zjBE
         i6TFTj80Tso3O5bavpS+MqgzoCkN4z1RMseFhht5/5vdfsV/5EfCSv1UAs7gmv8ov8GP
         /CC7XCh7ItYg3LvUeREIrEc4GpJ5YoiglQGknW2Nkjz2dB0WbGykOOzLtArGvFk+x6U7
         mTxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=mKc4vzID;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z203si361175oia.0.2020.03.09.12.04.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D8D882465A;
	Mon,  9 Mar 2020 19:04:28 +0000 (UTC)
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
Subject: [PATCH kcsan 27/32] kcsan: Add option to allow watcher interruptions
Date: Mon,  9 Mar 2020 12:04:15 -0700
Message-Id: <20200309190420.6100-27-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=mKc4vzID;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-27-paulmck%40kernel.org.
