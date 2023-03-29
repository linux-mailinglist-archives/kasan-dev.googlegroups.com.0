Return-Path: <kasan-dev+bncBAABBCMLSKQQMGQELLC66NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B09C6CF23E
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 20:38:02 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id p1-20020a5d6381000000b002cea6b2d5a9sf1685929wru.14
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 11:38:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680115082; cv=pass;
        d=google.com; s=arc-20160816;
        b=0h9gmaQferOnKAcfJ3ypAnKAD8OonmIkcY8unSzvfGN7VoP0Qq/eesnPw2JY9ikmCS
         ybrex6RRGZKPG5rxNpu2uGrH0YtpU+r7siVnqvDE6s8yderHShg5G/45D2aA/wplYSU8
         aa3cOfUZsCVhpJftdk4ZGR0Jk+6TMlbwRX+IDjc/uDfLcnuBznr83atomKHnY1NOydzn
         D67xwez3Ow2cpnYtKxer3mCqVlz9nr4E+hpXiwSVfqc3SLvu4jV1md/SXElm70Lg2Auy
         anMFW5+vb6lRpf2k+Chh0pNwKP7SNRR1gt6FxAHUFSEQLkNAhs1jLwucL9NEPcLmqSk9
         C3lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/8/IDVNcABtvzWAjA208Y0hipkwBkjn5NVfdgM3ugHQ=;
        b=L4YH/QPriAiqyThPkpCDIKnAQWrg8haf4aNvzceqlBpodqS0l7dBdG3n8z1w4T/JG3
         bms+0s1XogwB9woTHheKX/JksE5v2faZnCJdJ+KsHhM0LDOEQVj1vUcrp3hxwjNWiEJ8
         Un5T7WmQn5d/iFCdtph8WiX/s3pZ3b6cl/ZfIFSNWDubEqDlEezfMQT4vyMCyDjZuVss
         T5afMBo2kEw9MgaFu2Nt3uo0Ofk1zkzQVhnK+30zhWBQ3xWktXx7jzCdKgwemwsuOC/x
         rLgEimBNVXtxQadBxSigblmFor0DuY1yyfg5li3J7AnGWyKnxKLYIOaXg6XdHDTfo5MW
         1MQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=agGDWJ9x;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.53 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680115082;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/8/IDVNcABtvzWAjA208Y0hipkwBkjn5NVfdgM3ugHQ=;
        b=eg5Y5zQX6EFutU+f5Yv/0XGoeitXbY6uIdlQaS7+KYDGvrm69X2ndJexAcopX0IJJP
         3TmqHKPlw9zNGZ076DyzZRtygiXyt58Vv0oZ+oh6OrbOyKLBtpmeeJVLr3VoMoFO1KIE
         iiV2eowR4QIQLCuKfBTnFWAZO+NeqGq9VagRY1BDLZLDEChvq7YI2SrebatzYNKY9EKn
         QBggQpCg71q6j3gOldQ1HcRseVGPPZiGz3sOHdF3nPNsRjp/1ZhtqfY5HNqfsnY/36GV
         z03b2lZIxxBeNzY8fhWk/bzsfKG8A/V+nRZlCkPp23vDbSqc4W0sGC953cXK7L7t3fxd
         7Spg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680115082;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/8/IDVNcABtvzWAjA208Y0hipkwBkjn5NVfdgM3ugHQ=;
        b=sE5jIW9EUZCK2eslIpzLz1+m1BiXjFBES+RZVKsP+4QYNRbN5JaUo5CrerxpFK0wh/
         ERUH7fRokbCGqORDMpaKtb6lhhNyjhVs4x37pTB6a4SvBjfbR+l6Ac68zoczkaEzvDBG
         yqtlJhqNMyxXfsMQ/ST/lee0+fG+pT+7MguB3zdlM4GKGxB4aT1M4giSERK6t8ygVfoX
         /DcPKjIh0mA2qvP8zmUs1istfZVDDgcyLHaFovmlLIIjeL/sSDstTAF0LN3G34B0J7qQ
         hn7LsohYowzAI4l2rG32CnBUkdlGLMANyhnuKqDk0BAkYomlYJyJj1mkEmCq1L5Vyfzt
         TUxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWXaBIb8ImXi3vecZ50XmlJVlEAUZ9TPeUb1Q0cNpeTo4zpZVKr
	+SLX5E3s4c4bWIQWQ6bzl1c=
X-Google-Smtp-Source: AK7set82Q/rBxDg4UmsT30R9CJ8vscFUvzY/K7ub7BJ8tmq2IoVnfsPM5/MNzeUSTvoIG4qYyAv36w==
X-Received: by 2002:a05:600c:3791:b0:3ed:f221:9a49 with SMTP id o17-20020a05600c379100b003edf2219a49mr4575102wmr.7.1680115082152;
        Wed, 29 Mar 2023 11:38:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:993:b0:2c5:557d:88a3 with SMTP id
 by19-20020a056000099300b002c5557d88a3ls24979133wrb.3.-pod-prod-gmail; Wed, 29
 Mar 2023 11:38:01 -0700 (PDT)
X-Received: by 2002:adf:f04b:0:b0:2d8:57b1:db6c with SMTP id t11-20020adff04b000000b002d857b1db6cmr15130412wro.9.1680115081290;
        Wed, 29 Mar 2023 11:38:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680115081; cv=none;
        d=google.com; s=arc-20160816;
        b=UO+ZrjrK+46kQm8L9if30fgfc044r8UVgfd1E2TxUSBH9epJO7B5crr4OpJ4nnyYsP
         o0eP4BnBWk/RGdp1EmLuVPPx1+QsVL2ebS5dzhdRKpIiJL9n/3/hKhReBxQt5G2tePnq
         /zVIqaICqxcY4itD77ix/WdvgLrk/GI4MymiHIw+EQBK0DgYdUNXA+0TTiZNjeVNHl8O
         nEJIAifspT2fi5ZEtQe4Fy2R8uDcBYIPrrLeJBOE6+Hcmlgtv5T9MZAFPj2LjZT3YSFp
         RuHLxDfUjn2bWRX1Cnn118dKS6aKKZ5MFVJ7mIiAXlNjP1UAM8DyLg1NBrD9QSG6X2kk
         Hxsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KXwl8tO7n70VCzS+2Z99ZqyN4ebAwCoCQirv2FwloPQ=;
        b=YMtlrXkMBc7UQ9VO8h4v1i/Jioz3zGHsNy6bmhlcpmb1/+qMOJhgG/BsRSpaYK92Ps
         4UTMYHDX4QM5L+XevBu3RMxJz3G0ecJmpdaAsRj/i/akvcCvkiFfaoxtHEl3LCtrAIr/
         P86/JFtw4BU9L4jyyGAngXDurwpSsuByDnBhGXvOOsz61sf+Ijf1HynE516J1xPFEhV/
         d/Dd0mwZT9DkWUAw4ExvTCeTu3NgZSxIs2jfzX+zAHlvCUMGLlgMPvT6SrXijeHpPn1L
         VhiQ70J9i9uH2YF7CEsPP1BDdEagu8OmlaIk1voFiFoY3ke3JUSIGc+J/bH3UAC/5LUO
         aN9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=agGDWJ9x;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.53 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-53.mta1.migadu.com (out-53.mta1.migadu.com. [95.215.58.53])
        by gmr-mx.google.com with ESMTPS id bn30-20020a056000061e00b002ceac242c41si1700595wrb.4.2023.03.29.11.38.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Mar 2023 11:38:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.53 as permitted sender) client-ip=95.215.58.53;
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
Subject: [PATCH v2 5/5] kasan: suppress recursive reports for HW_TAGS
Date: Wed, 29 Mar 2023 20:37:48 +0200
Message-Id: <d14417c8bc5eea7589e99381203432f15c0f9138.1680114854.git.andreyknvl@google.com>
In-Reply-To: <dc432429a6d87f197eefb179f26012c6c1ec6cd9.1680114854.git.andreyknvl@google.com>
References: <dc432429a6d87f197eefb179f26012c6c1ec6cd9.1680114854.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=agGDWJ9x;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.53 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Changes v1->v2:
- Disable preemption instead of migration.
- Fix comment typo.
---
 mm/kasan/report.c | 59 ++++++++++++++++++++++++++++++++++++++---------
 1 file changed, 48 insertions(+), 11 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 89078f912827..892a9dc9d4d3 100644
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
+ * For #2: Suppression of tag checks via CPU, see report_suppress_start/end().
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
+	 * Disable preemption for the duration of printing a KASAN report, as
+	 * hw_suppress_tag_checks_start() disables checks on the current CPU.
+	 */
+	preempt_disable();
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
+	preempt_enable();
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d14417c8bc5eea7589e99381203432f15c0f9138.1680114854.git.andreyknvl%40google.com.
