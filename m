Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBQ5LWWPAMGQEQSYFP4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E1A7676FF3
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Jan 2023 16:27:00 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id r10-20020a2eb60a000000b00281ccc0c718sf2106985ljn.0
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Jan 2023 07:27:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674401219; cv=pass;
        d=google.com; s=arc-20160816;
        b=suR0W4PwurhonJrV7GrssLMODpjh9zLnER018rmLeEorjj/+P1BDBaaV1OgCHr3iMO
         8X/h3Du95PoOsSWyDOW9gn1cHCj22p+spvKpo7ELzX9jFXgZuMB3oUWvzDxPXsYTOV0J
         v334pC+vcM0aVCZBLa1GnGQdYW209KO0sSyo4q4NrKh1KhRRdURWIvdjW96GoilIbTs/
         FmKqpkmRY6IgdRk0ftIfso0HsrPNNtJIk6BFPBHA/N8qXZ/TvY5eN29c9L42pb2d1JUW
         c50ijFJ5A4EprDUeKoveBgVbtIxBHeisULhJeiLDeUi5nOF2qbx4BULXYGD3kFDAcGvr
         OT5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=8SIBj3xj164T1TwqNuUg1zUtl2BRTB71fAS7U2s/ROg=;
        b=MlCfc2IdjCSNFYTluUHmfgnNg+THJmwX3Y1B+7BQOFRivYLXEUSq+tPLgVaoCjTlR9
         YYCcNbrpEQCGYkhbMEWIy8IXUoHN5xtXkg2qGcP3wJbmUEd+adeyFVkbAKhXzYug+G4f
         MIEz1SAXzaxo4BM3TOafpdz0McLRYuqimTdbyaqo4s2skTMT5Js5ZdLVIT/cTJXu5QrL
         58ytwRXKgm5T+2O2Cd5wJGKl1gNlzOs4M3dzcd8ZuXgb7QaqKR5ZxU+XlROh/lCQtwrS
         CNuIkohsU2BiAAr3FWAkJBJIaSiPnpuj2LNDioVBOu36UXRBPoXoLd+9otUHTj4W6hTh
         Nu1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=PiVNOgoQ;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8SIBj3xj164T1TwqNuUg1zUtl2BRTB71fAS7U2s/ROg=;
        b=lTd/sk0+ALIwnd7xohCYsCUpbMRMhkjspIDXrbxGNcK7oMg+4BEhQTtoBwlh4QUmd7
         mlXf5gYCTvWhpmb6eC8hrrMNMvxikUavcP857txtRRg+M3zxdrlHHz4HGZgzkl8Fb0CZ
         lKIWWaS8gBtX+r3dXxCc2ZiFUwIFJTsy4rWyr9b4mKoKm3OlrsA1hry5kBZEWxRQTv73
         Ya2RcQpGk8I6SRRzd+vIiOwVcJhTSXZbJekwrLeUdgmlIb7h2vwjQf0RD87lm4MCQHpv
         rDtGeaFsA7IC3kX7CVlGCez+tQcegYN+ujsqgNWAtzgg4Vl7TtWEzTl4OZU6oOtbgnVv
         rFnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8SIBj3xj164T1TwqNuUg1zUtl2BRTB71fAS7U2s/ROg=;
        b=KFvrORnhB2ZFiURR7obNAfRPQGUWiCKHtIiVlfGVD/U5yN9WjRl+yz2NCJ76L/FsEq
         kEJJWsfsCh/B+MfOEQy+KS+y8onNvSFUPMbl1+gfZx8OloSaNzoMXyDh6kPQaPaWZAa4
         y4rEWSrr0DKciWQ0/zZnu+QDXFhqCiJJ6mbppR+mjM+1tf8u2FLcAB3IKTo6nV5t3X2m
         e0gbcvbBeuqwzM6k3td1vjR9B965v5g6N4WJo30J8fD58LdpAjgfHVt7yU2vcORNifM8
         rCTzb/X10wMjc/Pv5pPEJs+jN50C8xe5BhUzDw4x2MI9eo5H/ge4D/7gGHsk9vcg7WR5
         qJFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kofx1klWiq/y3Yfuy54MFH4vFDZ0qhP3ecINH4cFAvXrbsa28BV
	b+jMatv7DV+qB9bbiih72LM=
X-Google-Smtp-Source: AMrXdXtE7PEiyrRRO5xvTAPBT6wlHrdcxH5PwvIwR8jKlXX7HjD0iNbJYxS65Vo2MHpDroL8HaTubA==
X-Received: by 2002:ac2:4bd4:0:b0:4b4:eb69:10dc with SMTP id o20-20020ac24bd4000000b004b4eb6910dcmr2491264lfq.552.1674401219503;
        Sun, 22 Jan 2023 07:26:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:368e:b0:4cf:ff9f:bbfd with SMTP id
 d14-20020a056512368e00b004cfff9fbbfdls3088429lfs.1.-pod-prod-gmail; Sun, 22
 Jan 2023 07:26:58 -0800 (PST)
X-Received: by 2002:a05:6512:308d:b0:4aa:7821:8021 with SMTP id z13-20020a056512308d00b004aa78218021mr7631242lfd.34.1674401218292;
        Sun, 22 Jan 2023 07:26:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674401218; cv=none;
        d=google.com; s=arc-20160816;
        b=VbpH8a5Qipy5E2tGy7kbw1GRDjZqURgTJHVbs9BdgP2Jxf9LCxZL+mbYxydtJ2MaeQ
         0OgRPZ3zXEO9yza9SKH1f6KL2Tm7qLlvIyK6TZLbj5SudmPIBoI5dyT3fd8epwp2tYCf
         x3zlz6kaJGlA+OsvP47f0R6oa32dpY6tAwXoBqx1zO/IohlPqku4vppKNLSo3XiUOF5L
         Nl7ehCwWNJzgCCamQJE+FJPvqMRuQQDUUaiK5iwG+7mSAmrSDdBNzYfQxF1RRrFKubDv
         HYJcVrW0nL4HoZoIT/sa0IaEVQ8kYWZctE1HnSCQ/BzUKmFxocMOUzAx7oyzcgjPsUHz
         PeZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=5svZGXzpRpEeF1fzdip1Pbs9ol6JvBAXG3U9qbuqc6w=;
        b=dk5qv5pZu5BTI3nNnEnxmUX5QogVbaA/WQ4ddU7SeVG5tVHCLYHTYN2HoCeyv6abzG
         o93DVs1+026Xi0/v8v3Zparj8aU++lUHwTrx458Y1l2eetRESG2rsqNggU70T3D/nYLj
         xLMdf9BeGpel0XitLbgVGnrDxgLnnM1RiH6LVCR2oyKHLIXl0Ik4SvYcFW4woXzwsnGX
         sm3wHfoQnuEgujXWITPgcnRrTUJYfagxXVhXryNLVFCHfsAGHWRHUo02+S7Ps1+QGgax
         1I2U7FToOP3hcCDhr0D0ltmqojUl7Hj69VlotKBdRV2CrICAhvjNIWlkVL5z9RfCuAQa
         +thA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=PiVNOgoQ;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id u5-20020a05651220c500b00492ce810d43si2081236lfr.10.2023.01.22.07.26.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 22 Jan 2023 07:26:58 -0800 (PST)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id CFAE0B80B1D;
	Sun, 22 Jan 2023 15:26:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 09FFDC433D2;
	Sun, 22 Jan 2023 15:26:56 +0000 (UTC)
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
	Kees Cook <keescook@chromium.org>
Subject: [PATCH 6.1 154/193] panic: Consolidate open-coded panic_on_warn checks
Date: Sun, 22 Jan 2023 16:04:43 +0100
Message-Id: <20230122150253.432742379@linuxfoundation.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230122150246.321043584@linuxfoundation.org>
References: <20230122150246.321043584@linuxfoundation.org>
User-Agent: quilt/0.67
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=PiVNOgoQ;       spf=pass
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
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
---
 include/linux/panic.h |    1 +
 kernel/kcsan/report.c |    3 +--
 kernel/panic.c        |    9 +++++++--
 kernel/sched/core.c   |    3 +--
 lib/ubsan.c           |    3 +--
 mm/kasan/report.c     |    4 ++--
 mm/kfence/report.c    |    3 +--
 7 files changed, 14 insertions(+), 12 deletions(-)

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
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -492,8 +492,7 @@ static void print_report(enum kcsan_valu
 	dump_stack_print_info(KERN_DEFAULT);
 	pr_err("==================================================================\n");
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("KCSAN");
 }
 
 static void release_report(unsigned long *flags, struct other_info *other_info)
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -201,6 +201,12 @@ static void panic_print_sys_info(bool co
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
@@ -619,8 +625,7 @@ void __warn(const char *file, int line,
 	if (regs)
 		show_regs(regs);
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("kernel");
 
 	if (!regs)
 		dump_stack();
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -5778,8 +5778,7 @@ static noinline void __schedule_bug(stru
 		pr_err("Preemption disabled at:");
 		print_ip_sym(KERN_ERR, preempt_disable_ip);
 	}
-	if (panic_on_warn)
-		panic("scheduling while atomic\n");
+	check_panic_on_warn("scheduling while atomic");
 
 	dump_stack();
 	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -154,8 +154,7 @@ static void ubsan_epilogue(void)
 
 	current->in_ubsan--;
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("UBSAN");
 }
 
 void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -164,8 +164,8 @@ static void end_report(unsigned long *fl
 				       (unsigned long)addr);
 	pr_err("==================================================================\n");
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
-		panic("panic_on_warn set ...\n");
+	if (!test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
+		check_panic_on_warn("KASAN");
 	if (kasan_arg_fault == KASAN_ARG_FAULT_PANIC)
 		panic("kasan.fault=panic set ...\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -273,8 +273,7 @@ void kfence_report_error(unsigned long a
 
 	lockdep_on();
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("KFENCE");
 
 	/* We encountered a memory safety error, taint the kernel! */
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_STILL_OK);


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230122150253.432742379%40linuxfoundation.org.
