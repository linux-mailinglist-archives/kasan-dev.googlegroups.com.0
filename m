Return-Path: <kasan-dev+bncBAABBLUBV6QAMGQEGYOM6QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D7406B55DD
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Mar 2023 00:43:43 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id y23-20020a05651c021700b002984904d871sf2120521ljn.6
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 15:43:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678491822; cv=pass;
        d=google.com; s=arc-20160816;
        b=G+9cV1j+4DANTOh9NPgVcHLbl7aIRxRAglEnxZxML3KwBKuh+8QTiIxuadm3Wmp530
         2MnokGc+OXFaOVBynZbu1R3Bqx+Xx6osor4280W/L64maIv6utTD/89gSCs8jTd/Au77
         xbJKniKzQ28SnWILO7VaTEZcNq0M6SaUd9Js0STeFDKsBCL1BbngTjT42k1o3Yd3/+t1
         rc6bcpZBiPms+AFfJSpLDNHYMGMAvZ/w3tw6lyHJazOCpRw+eut2jtdz7DDLjZfnbQUd
         5fMbf9YWr3wj+W4LMKKm6pBrb7ZBpLsc6AjgoHGMBNAc1xrTPU59CMBhnyJBdLorq+RU
         urdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oYHbWQp4dl9TxS0qZ2UGaVK0bcp0x67/o0+YIXCzda4=;
        b=frOzWC9RidvMFU9XzEvB24Mfc52yvR5wKAH8qW+VRHxCXHsYrfqc9/3+2IbT3ZTefs
         kEXnDDCnFAhPXLV7HsfNaVjvep6Ljpvi3JjT8pWv57yHRRmLmGoD62vx9Dv1xiuvsJCa
         o9r9E7CQwpzmh0cZZW/qUClzUlEMwlDakzIYFIQN2yP68Xe4bYnJM66e6IZxR0JDBdcO
         QUo+7WPaDnL0GKTQjcPZtgfzoQOGX76gtv/qwhNEQmpjaoXkcS+5vJuxpqhjXZxxFJkR
         mVOTjMHPjUaaPe3YQwYF4QuHJYeEDmSMFDf975hFuWRCtI9cl0VSMDrQsA+aQiJaBdjl
         a8gA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qTe147Js;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::31 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678491822;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oYHbWQp4dl9TxS0qZ2UGaVK0bcp0x67/o0+YIXCzda4=;
        b=K7mzluVczIPa+viPiuw4qMwjwT3kbYsppz/DeM+xk0BRy9U63Gsr8DUhR6xO5VZFoI
         naJIaFzMK2HpbhCU3X4xWP7inZs3UnDRbihdfE1EEp10IrfBBRztvnoOSCrLliXJ6IsX
         K5v+RLex0oZHuhP5Y3cCYHL6HIgtclWgIgkZBC4g5TCzpHkZOGPhYF/wP087eM+H7Spy
         6Sny25mywRUu+EhW1FpJR3CPFhjb9ksSpjtCeuqSyDSLUpyMz1VOKXHa9FR5BVyCJwk/
         aPNVlLxa+05vfzS1WIIOEN/2sStGxvCaqUijpgATGBnrES2wIisJNo1TLqdn++jV6lbl
         rTlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678491822;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oYHbWQp4dl9TxS0qZ2UGaVK0bcp0x67/o0+YIXCzda4=;
        b=XSjD/zRKXsUnVdqtWEkIRgrE/2AuIQhlRd2+KR85PVRDvQAsXBs6hQyeGG6Xvhisgl
         z/HV/909g3G/PA4KY3OofdZIA4lPD1J4Gl5PxB4fgVYFAyO8esWdBeG+S8ZiCzdEHJks
         Pysog13NqQvGPOi79m7xedpxnj/mlO6Sc8VwfI+QdOrOykfhRqt5grF1DVfp9OjprEKw
         XgShWNBaQsL7rwBikPldMX0nsk0EGbJtxTfOfIkWie2tHCyeEDu61VNBfC2ELdGZhPll
         qwlqvxsGGqj74IaWYXuU/HoBaNMglDaIVh9AU10NKc8jysF0olUM5phlFHl+oKXVcKZL
         X/Xw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUvkzoDms2EzQpuCmcyvjZ9XFVlo1aamq8/v7vvclp0VFjHH9Mb
	1CkMarDg6kwVJlynui/mxoByIQ==
X-Google-Smtp-Source: AK7set/A3TcLN3Zhh+qQYFEXVKwb8ojGa/cSNGQvdKpv/Jejl9WfbuhM3iWMtoQGBUcbKA8tIZKGCg==
X-Received: by 2002:ac2:5459:0:b0:4e0:979d:56e9 with SMTP id d25-20020ac25459000000b004e0979d56e9mr8395633lfn.12.1678491822423;
        Fri, 10 Mar 2023 15:43:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e24:b0:4dd:8403:13fe with SMTP id
 i36-20020a0565123e2400b004dd840313fels1837657lfv.3.-pod-prod-gmail; Fri, 10
 Mar 2023 15:43:41 -0800 (PST)
X-Received: by 2002:ac2:523c:0:b0:4e8:77a:f894 with SMTP id i28-20020ac2523c000000b004e8077af894mr5508737lfl.25.1678491821309;
        Fri, 10 Mar 2023 15:43:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678491821; cv=none;
        d=google.com; s=arc-20160816;
        b=Wf8FJGego3UuehyLHsuKW4RRR7SwUkqYBWvqvL1XJzTX0hTvCZcAe1YWa2y5qAE6Bl
         pzP+6GmfPcqFF2F4qTzV5hgSxSfZ+XxVNiBJFBHBvB2d5IusYl/PQOglQhTe7qqk3xQO
         fWA9sf26uCU+QUnwujqOGZrPPgaazy5FyTUt/8eNhOx8bJEA8iByrbz3G7V4FLrrgTvz
         /vvzIXguPNpbWYSrqKkweXQaH31vN9WSmeAAJEgYilhQhTrm3bKVZlDFtqxawBYaBLdH
         Hi+chJcTFIBEW+U9LQBWg81RY3PKcys9NKiYcksGVt6rI2T+OsRAC8NaxXLU/K4rzzkD
         zAMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SSBGLO0ZKcc5jSLq3xLNP5yCcA0qlKOn3pEju7Cd7ZE=;
        b=u0T+PQGEbt72uoJsV65cd87K4jsttT5uSY6ddcpHHnO7EoY8JHcPDjybPjDAsAyXrM
         lW1EGK1w+L1u0ZXc2tsoxUqBpDFkaJienWBA4ym6QrHTsMCXqLRqpvg3p15HdoaTZtLj
         1fDId9hyNCxoqumxb75Vd1zfNEbKNEpD+dxusFFo6SKwKwBOZ2mBzG6xT9M4ph5E5DBw
         njt/Jp3IK/uj1iR6vbMVx1L7Yi4KPkAYaRXxnDc+kdhG6QhgzRZZVhe9qOJUAoLeWT4h
         GrHz+Pq+yMmqOyCKjFJjeWSoAipZChlZgvvgyqyo1SkTkajfbGDbxcEzX6r6NVvXQjQ0
         U5kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qTe147Js;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::31 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-49.mta1.migadu.com (out-49.mta1.migadu.com. [2001:41d0:203:375::31])
        by gmr-mx.google.com with ESMTPS id k10-20020ac24f0a000000b004dcbff74a12si80628lfr.8.2023.03.10.15.43.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Mar 2023 15:43:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::31 as permitted sender) client-ip=2001:41d0:203:375::31;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Weizhao Ouyang <ouyangweizhao@zeku.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 5/5] kasan: suppress recursive reports for HW_TAGS
Date: Sat, 11 Mar 2023 00:43:33 +0100
Message-Id: <59f433e00f7fa985e8bf9f7caf78574db16b67ab.1678491668.git.andreyknvl@google.com>
In-Reply-To: <bc919c144f8684a7fd9ba70c356ac2a75e775e29.1678491668.git.andreyknvl@google.com>
References: <bc919c144f8684a7fd9ba70c356ac2a75e775e29.1678491668.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=qTe147Js;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::31 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

KASAN suppresses reports for bad accesses done by the KASAN reporting
code. The reporting code might access poisoned memory for reporting
purposes.

Software KASAN modes do this by suppressing reports during reporting
via current->kasan_depth, the same way they suppress reports during
accesses to poisoned slab metadata.

Hardware Tag-Based KASAN does not use current->kasan_depth, and instead
resets pointer tags for accesses to poisoned memory done by the reporting
code.

Despite that, a recursive report can still happen:

1. On hardware with faulty MTE support. This was observed by Weizhao
   Ouyang on a faulty hardware that caused memory tags to randomly change
   from time to time.

2. Theoretically, due to a previous MTE-undetected memory corruption.

A recursive report can happen via:

1. Accessing a pointer with a non-reset tag in the reporting code, e.g.
   slab->slab_cache, which is what Weizhao Ouyang observed.

2. Theoretically, via external non-annotated routines, e.g. stackdepot.

To resolve this issue, resetting tags for all of the pointers in the
reporting code and all the used external routines would be impractical.

Instead, disable tag checking done by the CPU for the duration of KASAN
reporting for Hardware Tag-Based KASAN.

Without this fix, Hardware Tag-Based KASAN reporting code might deadlock.

Fixes: 2e903b914797 ("kasan, arm64: implement HW_TAGS runtime")
Reported-by: Weizhao Ouyang <ouyangweizhao@zeku.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Considering that 1. the bug this patch fixes was only observed on faulty
MTE hardware, and 2. the patch depends on the other patches in this series,
I don't think it's worth backporting it into stable.
---
 mm/kasan/report.c | 59 ++++++++++++++++++++++++++++++++++++++---------
 1 file changed, 48 insertions(+), 11 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 89078f912827..77a88d85c0a7 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -72,10 +72,18 @@ static int __init kasan_set_multi_shot(char *str)
 __setup("kasan_multi_shot", kasan_set_multi_shot);
 
 /*
- * Used to suppress reports within kasan_disable/enable_current() critical
- * sections, which are used for marking accesses to slab metadata.
+ * This function is used to check whether KASAN reports are suppressed for
+ * software KASAN modes via kasan_disable/enable_current() critical sections.
+ *
+ * This is done to avoid:
+ * 1. False-positive reports when accessing slab metadata,
+ * 2. Deadlocking when poisoned memory is accessed by the reporting code.
+ *
+ * Hardware Tag-Based KASAN instead relies on:
+ * For #1: Resetting tags via kasan_reset_tag().
+ * For #2: Supression of tag checks via CPU, see report_suppress_start/end().
  */
-static bool report_suppressed(void)
+static bool report_suppressed_sw(void)
 {
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	if (current->kasan_depth)
@@ -84,6 +92,30 @@ static bool report_suppressed(void)
 	return false;
 }
 
+static void report_suppress_start(void)
+{
+#ifdef CONFIG_KASAN_HW_TAGS
+	/*
+	 * Disable migration for the duration of printing a KASAN report, as
+	 * hw_suppress_tag_checks_start() disables checks on the current CPU.
+	 */
+	migrate_disable();
+	hw_suppress_tag_checks_start();
+#else
+	kasan_disable_current();
+#endif
+}
+
+static void report_suppress_stop(void)
+{
+#ifdef CONFIG_KASAN_HW_TAGS
+	hw_suppress_tag_checks_stop();
+	migrate_enable();
+#else
+	kasan_enable_current();
+#endif
+}
+
 /*
  * Used to avoid reporting more than one KASAN bug unless kasan_multi_shot
  * is enabled. Note that KASAN tests effectively enable kasan_multi_shot
@@ -174,7 +206,7 @@ static void start_report(unsigned long *flags, bool sync)
 	/* Do not allow LOCKDEP mangling KASAN reports. */
 	lockdep_off();
 	/* Make sure we don't end up in loop. */
-	kasan_disable_current();
+	report_suppress_start();
 	spin_lock_irqsave(&report_lock, *flags);
 	pr_err("==================================================================\n");
 }
@@ -192,7 +224,7 @@ static void end_report(unsigned long *flags, void *addr)
 		panic("kasan.fault=panic set ...\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	lockdep_on();
-	kasan_enable_current();
+	report_suppress_stop();
 }
 
 static void print_error_description(struct kasan_report_info *info)
@@ -480,9 +512,13 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
 	struct kasan_report_info info;
 
 	/*
-	 * Do not check report_suppressed(), as an invalid-free cannot be
-	 * caused by accessing slab metadata and thus should not be
-	 * suppressed by kasan_disable/enable_current() critical sections.
+	 * Do not check report_suppressed_sw(), as an invalid-free cannot be
+	 * caused by accessing poisoned memory and thus should not be suppressed
+	 * by kasan_disable/enable_current() critical sections.
+	 *
+	 * Note that for Hardware Tag-Based KASAN, kasan_report_invalid_free()
+	 * is triggered by explicit tag checks and not by the ones performed by
+	 * the CPU. Thus, reporting invalid-free is not suppressed as well.
 	 */
 	if (unlikely(!report_enabled()))
 		return;
@@ -517,7 +553,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	unsigned long irq_flags;
 	struct kasan_report_info info;
 
-	if (unlikely(report_suppressed()) || unlikely(!report_enabled())) {
+	if (unlikely(report_suppressed_sw()) || unlikely(!report_enabled())) {
 		ret = false;
 		goto out;
 	}
@@ -549,8 +585,9 @@ void kasan_report_async(void)
 	unsigned long flags;
 
 	/*
-	 * Do not check report_suppressed(), as kasan_disable/enable_current()
-	 * critical sections do not affect Hardware Tag-Based KASAN.
+	 * Do not check report_suppressed_sw(), as
+	 * kasan_disable/enable_current() critical sections do not affect
+	 * Hardware Tag-Based KASAN.
 	 */
 	if (unlikely(!report_enabled()))
 		return;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/59f433e00f7fa985e8bf9f7caf78574db16b67ab.1678491668.git.andreyknvl%40google.com.
