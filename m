Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBBVD36PAMGQELHT5N7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C47F6811F9
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 15:17:43 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id x44-20020a2ea9ac000000b0028fd85f2e0asf1903626ljq.22
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 06:17:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675088263; cv=pass;
        d=google.com; s=arc-20160816;
        b=g9gmie1mIplWhWO27qE25gvhHpx4uVfevzNxBtCoqpZLHiaAf/PT0nuCo/depHwmCG
         U8HMv9bJracz4Rlg+XXuu+NbXbWeBqzqqR4pNwPeZ2/jSDc+2EWFV71tPLJh8rLVMKcO
         gXf58VQ0YPZIaoG56sJDT0DWMWDEyMRGe1ld18vuKUbW5rC9FjBdaOzojgJuQafPgNSZ
         xX5UGVB6/KOigUEf2E3yzBRSpMT/0dOZr+gVYPhGpbCVkSAG+psup2Yo4oX4O+pE8b08
         nIiwKkgbR52+UgGiqfIZKIrbktn6h6C6evl4fGPiaRHH3UT9l9NE8KrfJca8c++BU/PI
         Ojow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=AL17yy7K89HUXsWJIQVu6Q1gUHLEWeCpyB10lzdJB3Q=;
        b=qYpPAXdsGjeuegN6hPIkCDG2ERbt6xYBR5iZPvEHRqcuo52uV2yRXcX7cnLLGcuPWC
         bAwZfrr1WPPbu1lU+h7b9X2Abz52wx4drIEA/Fm3rV+paADBvJsywfS5wUqELRanmCJj
         LIlZFOcnvDvr2cHqEPD97HPfD6DxWQJCcPNibXKZFJnp9NMJxFfhvpQKYk4Cvj3UHmYg
         cgeSH+OiccOR6gKI2S7gb098c+1MLT3XJxiL+VatGFoaDcxGnCtQWBTCIRC4nIXqphVS
         xkTgNN3EoDE8KgklJuuNxvtbqMh1IA/4rpQG7wM7RWpTqCbjYqOYBvye44K21inl6t1e
         tl0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=c2Dn+EtM;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AL17yy7K89HUXsWJIQVu6Q1gUHLEWeCpyB10lzdJB3Q=;
        b=iN/2wHWwZokmKpBPR5jSgVqTSpdux9DJBl+vl5EsO5kml1LZlLXzYeHbv+HGg5ZmdN
         T8PKE/Z8uCK7qI3ixw/T5ROz5hMlqChQuAsc3qv/+fNAYE2WRsfayNfzkpRyaA3358wF
         hPAIBtfitEXHUBbRsWqNMzudF0XD4UbzGKwhJ5t2b+s/wX5+lkr/Ca5m9zu+/KAnMTqO
         Y+9zDpF4c3wUpH9APwvLYlyaUbxYWaTuLQHlhWGPzUEbpcAH13vrQ2QahoGoqLXQVNgK
         xbm2JtZjXR/bUpaNfHZhp0xplGBWMweU+WUJIaqqX3o6gQa6ZLC0UjcSCKXfBjUh0Atn
         ag/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AL17yy7K89HUXsWJIQVu6Q1gUHLEWeCpyB10lzdJB3Q=;
        b=Jrg2dg51q0xJ1VAPixUGoEkH1ERxiimZlFmxjgyAMMf0g0UdAmhMcYLMBZOp91HoIC
         Z6MLcWpaotHo3faqV0PnlH2gHMx7WHgw2kGtqLqbgkLvCeP0dnoWALdu46s0B7El6PvC
         oCp37QkpIrPeQ4SPhJ0PeBhxLcBXAkXXFIV46avu6cXk7AK4Ow43bKI9Du28mGXYMhv9
         mQMqF/PFIsUAA+9bSWo5ys04nBWGKWQEehXRWxEmL0ZOYBEBcChamb+yRF//F5pCUPmF
         4dv7L2fm02SUhkTI6T2uZJuNPY5i3W+O919/4HFe9+Qwp6mKwdVh/ab2yP1XBZwF5W0E
         A6oQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krt1hCexj5611MmwwLkrpGz4v1YCvX+fMP60P2TGJ7pWa/v73Bb
	Eh2vvLJcESZ/4I0Fv+Xznwc=
X-Google-Smtp-Source: AMrXdXuHoPjtMBjKdzWJdj71sFGE8q1tHi3f4ecVnIbhwTAFW4fp/RUT5yC71vT7FT5GS3CFaAONpA==
X-Received: by 2002:a19:771d:0:b0:4b5:3f7f:f9ed with SMTP id s29-20020a19771d000000b004b53f7ff9edmr3487122lfc.177.1675088262683;
        Mon, 30 Jan 2023 06:17:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4f13:0:b0:4d5:7ca1:c92f with SMTP id k19-20020ac24f13000000b004d57ca1c92fls2161092lfr.2.-pod-prod-gmail;
 Mon, 30 Jan 2023 06:17:41 -0800 (PST)
X-Received: by 2002:a05:6512:3f26:b0:4a4:68b9:1a0b with SMTP id y38-20020a0565123f2600b004a468b91a0bmr18581410lfa.51.1675088261200;
        Mon, 30 Jan 2023 06:17:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675088261; cv=none;
        d=google.com; s=arc-20160816;
        b=l1FSYgK9exE2ia4ex3y+2yESu/h17k61lg5v0a/gS2iJSCoDwygjPJ7yYooRugyzfd
         XsXFxEriKLAA95wlKmVbEibfbdM+f7X7kAp6akkGNoZSSoub8+NSP3m9EXPZM2Y1ENAm
         /03rWTQkyXTA//hl0aVB39Bu35fVxQKGx1CiC/SZhd1UwiY7T1bNf2D04PQ7GC5Pl9DU
         BuuJDaMNFw8KT9EbyaSdZAZQeFbLrq7kv6UnG0fAZk9Rmcr8In7OGuqg0EFkeLdGFR7e
         E1BgLf4+3+5SKHUulqE7YZJVVZWK5v6w0TI+VMZWM1F/PbTTQLqrc3YKurHie4jTuFu6
         fiOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=uyluDYmPAg9Fe3qpUBDneuVPmLqYruUbSAd4ixKVj0Q=;
        b=Zr+FDZuoyNFNBE8ckchqqSrdIHtJm/rar1xX4Kpf8VA71EAGyDVi7pQr+lFQBUZLn/
         rM+DjMpT09Be9Y72cUNNabeMfvHf429asY8e8UXlt/TcK2Zs8uYpo7UKg9GooVtlAzNI
         sd6tg2KAm2SwgPTSNylolIR/0GVq56bMJwktGUWCOFcmsVN2WNeBg72b3SICS5vGOZYj
         3OTt327QV/3CZUwva6K/+V01ZQTT6u8J/hn4ryG6uTgberx2351pp2ilK8tUxZABsRis
         VAfAMtk0RPJyoXxbPv+8jmiB0YqSoN80kJ0yb/V3etAey+pJOBXzso3VJLeLn8PvWv2s
         UU/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=c2Dn+EtM;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id i30-20020a0565123e1e00b004d5e038aba2si634335lfv.7.2023.01.30.06.17.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Jan 2023 06:17:41 -0800 (PST)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 9ECB9B811D3;
	Mon, 30 Jan 2023 14:17:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6C96AC4339C;
	Mon, 30 Jan 2023 14:17:38 +0000 (UTC)
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: stable@vger.kernel.org
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	patches@lists.linux.dev,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Mel Gorman <mgorman@suse.de>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Gow <davidgow@google.com>,
	tangmeng <tangmeng@uniontech.com>,
	Jann Horn <jannh@google.com>,
	Shuah Khan <skhan@linuxfoundation.org>,
	Petr Mladek <pmladek@suse.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Luis Chamberlain <mcgrof@kernel.org>,
	Kees Cook <keescook@chromium.org>,
	Eric Biggers <ebiggers@google.com>,
	Sasha Levin <sashal@kernel.org>
Subject: [PATCH 5.15 138/204] panic: Consolidate open-coded panic_on_warn checks
Date: Mon, 30 Jan 2023 14:51:43 +0100
Message-Id: <20230130134322.600948088@linuxfoundation.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230130134316.327556078@linuxfoundation.org>
References: <20230130134316.327556078@linuxfoundation.org>
User-Agent: quilt/0.67
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=c2Dn+EtM;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

From: Kees Cook <keescook@chromium.org>

commit 79cc1ba7badf9e7a12af99695a557e9ce27ee967 upstream.

Several run-time checkers (KASAN, UBSAN, KFENCE, KCSAN, sched) roll
their own warnings, and each check "panic_on_warn". Consolidate this
into a single function so that future instrumentation can be added in
a single location.

Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Juri Lelli <juri.lelli@redhat.com>
Cc: Vincent Guittot <vincent.guittot@linaro.org>
Cc: Dietmar Eggemann <dietmar.eggemann@arm.com>
Cc: Steven Rostedt <rostedt@goodmis.org>
Cc: Ben Segall <bsegall@google.com>
Cc: Mel Gorman <mgorman@suse.de>
Cc: Daniel Bristot de Oliveira <bristot@redhat.com>
Cc: Valentin Schneider <vschneid@redhat.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: David Gow <davidgow@google.com>
Cc: tangmeng <tangmeng@uniontech.com>
Cc: Jann Horn <jannh@google.com>
Cc: Shuah Khan <skhan@linuxfoundation.org>
Cc: Petr Mladek <pmladek@suse.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org
Reviewed-by: Luis Chamberlain <mcgrof@kernel.org>
Signed-off-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Link: https://lore.kernel.org/r/20221117234328.594699-4-keescook@chromium.org
Signed-off-by: Eric Biggers <ebiggers@google.com>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 include/linux/panic.h | 1 +
 kernel/kcsan/report.c | 3 +--
 kernel/panic.c        | 9 +++++++--
 kernel/sched/core.c   | 3 +--
 lib/ubsan.c           | 3 +--
 mm/kasan/report.c     | 4 ++--
 mm/kfence/report.c    | 3 +--
 7 files changed, 14 insertions(+), 12 deletions(-)

diff --git a/include/linux/panic.h b/include/linux/panic.h
index e71161da69c4..8eb5897c164f 100644
--- a/include/linux/panic.h
+++ b/include/linux/panic.h
@@ -11,6 +11,7 @@ extern long (*panic_blink)(int state);
 __printf(1, 2)
 void panic(const char *fmt, ...) __noreturn __cold;
 void nmi_panic(struct pt_regs *regs, const char *msg);
+void check_panic_on_warn(const char *origin);
 extern void oops_enter(void);
 extern void oops_exit(void);
 extern bool oops_may_print(void);
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 21137929d428..b88d5d5f29e4 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -432,8 +432,7 @@ static void print_report(enum kcsan_value_change value_change,
 	dump_stack_print_info(KERN_DEFAULT);
 	pr_err("==================================================================\n");
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("KCSAN");
 }
 
 static void release_report(unsigned long *flags, struct other_info *other_info)
diff --git a/kernel/panic.c b/kernel/panic.c
index 0b560312878c..bf0324941e43 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -193,6 +193,12 @@ static void panic_print_sys_info(void)
 		ftrace_dump(DUMP_ALL);
 }
 
+void check_panic_on_warn(const char *origin)
+{
+	if (panic_on_warn)
+		panic("%s: panic_on_warn set ...\n", origin);
+}
+
 /**
  *	panic - halt the system
  *	@fmt: The text string to print
@@ -628,8 +634,7 @@ void __warn(const char *file, int line, void *caller, unsigned taint,
 	if (regs)
 		show_regs(regs);
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("kernel");
 
 	if (!regs)
 		dump_stack();
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 2bd5e235d078..c1458fa8beb3 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -5560,8 +5560,7 @@ static noinline void __schedule_bug(struct task_struct *prev)
 		pr_err("Preemption disabled at:");
 		print_ip_sym(KERN_ERR, preempt_disable_ip);
 	}
-	if (panic_on_warn)
-		panic("scheduling while atomic\n");
+	check_panic_on_warn("scheduling while atomic");
 
 	dump_stack();
 	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
diff --git a/lib/ubsan.c b/lib/ubsan.c
index 36bd75e33426..60c7099857a0 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -154,8 +154,7 @@ static void ubsan_epilogue(void)
 
 	current->in_ubsan--;
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("UBSAN");
 }
 
 void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index bf17704b302f..887af873733b 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -117,8 +117,8 @@ static void end_report(unsigned long *flags, unsigned long addr)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
-		panic("panic_on_warn set ...\n");
+	if (!test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
+		check_panic_on_warn("KASAN");
 	if (kasan_arg_fault == KASAN_ARG_FAULT_PANIC)
 		panic("kasan.fault=panic set ...\n");
 	kasan_enable_current();
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 37e140e7f201..cbd9456359b9 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -267,8 +267,7 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 
 	lockdep_on();
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("KFENCE");
 
 	/* We encountered a memory safety error, taint the kernel! */
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_STILL_OK);
-- 
2.39.0



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230130134322.600948088%40linuxfoundation.org.
