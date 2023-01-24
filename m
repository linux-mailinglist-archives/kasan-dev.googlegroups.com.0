Return-Path: <kasan-dev+bncBDEZDPVRZMARBXGRYCPAMGQETV7IDZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B84867A1C5
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 19:52:13 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id c66-20020a1c3545000000b003d355c13229sf11664747wma.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 10:52:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674586333; cv=pass;
        d=google.com; s=arc-20160816;
        b=y0EhA4VYnhi8Kfaz3Lg4vx0QUVaI5ie1TDJGmeTuCP2EFlWThs9z+XisLbYk/vSKhh
         xMTCajCOkzlU9hSxdUMO9AL0rqU0O1Wzd2y3CkdjZaTGPCyZ92bDs6kgoUAdGDIKunnA
         GIwi+owxc7nvS63GIu7GYigYxq0goLxgQijjZK4f5Mpfy8cyab7XZ2iIVA89Sz5qFz7N
         PVoZ5ZsRro1z6shyGRGjqZv5E0/4YfGUc/+ppW9aEXfwZnNkkjCymlKgfEUpTD3jb/vh
         6HMGYysLBUVfM39QM5d05McXmLrxNwmMytj3YErk+sk0MTwY9+bZ2bE3Wo8Im3FsezCz
         gy5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CFZw0c4Qya4SYQsDT8ZKWj3uefZCzt5RV+xx6mb5kxU=;
        b=KTqpza3C/y1hKoNHPzI35p5+UYM63bUHWejRhKYZMu35i3eH2JNP15yLLwOR4jsOv3
         kFrdeOINNyFL+viX+vV1d5rmHmRcljDvEE26TmYJ8twQ1mr9UvPBwNc9btecHV5u5c+x
         Q25oHCKhkuAccaNo08RjPXhu1z5sj/yMJP3nL3gH36hHM6gMpK6sX98Tn5+q1omhp/kK
         5JF8MO3Ljk8lsxgOWwHnLK1wpnWoQMmNDBANAHJym6WpJeT6iM1AnFsqCPL7ZDdHjOsg
         2Jd9XTL4XmxM77SEI8Vo7g7t2BHx3atS+c8F0j5rNha3/ppj0ydR/KzOtvy5CDw36DLC
         OsUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GqXJ7TZ4;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CFZw0c4Qya4SYQsDT8ZKWj3uefZCzt5RV+xx6mb5kxU=;
        b=Z3aC2MKT11j2z8APzStlDMtFBYAJ8yui09ummiHEWfYKf5LAQyLUwZ3I07ehOPEFdG
         5N8O1i/TVpY+ZPMuH32TwbFCZvF+T5eZX/6zEXCwtHNjGKA5u2jeSTaN+71PeqoJBTiW
         rPcl/cK9F8IeXmOUVU77wbGddUu/zFkaer6DT+MlVBoIidjzPiMKOvnC6F56NHb29nvV
         e4fCSu1gC3ttPww1t/uaX+F4LHUGgvENLGRU0DpY741vFy0yyP0vK60oD4Al/vgZb0xj
         dreAK69bfbD3qK5QAt0eLSKS87d8BtNWGT59uRvnDfscusnMOnY7+LJSRx3PE3kf5P+C
         XpdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CFZw0c4Qya4SYQsDT8ZKWj3uefZCzt5RV+xx6mb5kxU=;
        b=odXDb1KwTqTCRU+i9URTa14hTaP08J2Be55L9CVxfrc+ZhEQB6LGEChXHbOuCrHDmB
         BaiD4hjBoo7uqR2vgl8tlLeKd6mxZEaPghES5WL0NFMqBQRYkGdMNCGOhvaAfcBI8PEY
         zSnshj/5RMM4CvHCM5E1pWE0icMFTNPX/9K0E3vo6C3fOyyAIp8oUuA87sxcTc7eCZMY
         h2T5rff7lQf1rWsRDeNRdvfehvaeDCnKVTOZ6OMgBdokcThY4z3e0uhH+WIBce+mQ7rS
         c6jMP8VAdty9LN4vtBSTf1H9cccIDAjJGM/BMhDAw5z/7WU056Z/xZiVQDAR5ObzNW/n
         dd5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqDjMTUAbSwoz4VbmVHqmFcbvvFBgAx8acw9UsxHSBrWCL0YCJ9
	Pt6Pevr1Q1y6+m21+jBW8OM=
X-Google-Smtp-Source: AMrXdXvifKeIcDo/VjTw3tvFYW+4cGrN+Rb2lJ8/0CzB3a1nQB8ysHio2FXDpVOYoi+TJxbHf64eJQ==
X-Received: by 2002:a5d:4841:0:b0:242:1f22:df3b with SMTP id n1-20020a5d4841000000b002421f22df3bmr842049wrs.679.1674586332831;
        Tue, 24 Jan 2023 10:52:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c5c9:0:b0:3cd:d7d0:14b6 with SMTP id n9-20020a7bc5c9000000b003cdd7d014b6ls8821531wmk.1.-pod-control-gmail;
 Tue, 24 Jan 2023 10:52:11 -0800 (PST)
X-Received: by 2002:a05:600c:1c1b:b0:3d9:ebf9:7004 with SMTP id j27-20020a05600c1c1b00b003d9ebf97004mr27613957wms.29.1674586331889;
        Tue, 24 Jan 2023 10:52:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674586331; cv=none;
        d=google.com; s=arc-20160816;
        b=QhhrmaXR2AMJV90ve/aWRC46l1ousY4EFfzJPbUo7rRbchbhC8gIob9AiZEdVb0hoK
         GNYHwPr3MJ/hcaunVXaFDqIqJd1n57wlL5VJ4lW2C/MXOrG4OVtJ2JSDJP04xOUXPUXW
         sV9VrM9/tR0hsjyVQpCbg+0NTKV/WFN1w6NJYgDjiCjpGha0fooX/aU8OeyAAV1YGNNq
         pVpSIy7i8zt5cM4Eu7YiNvwZ4Jdnm8vu+vlC3grerJfsbpe0w7lSd2QBoG5yzMYW2WI6
         kp2lbXrof22vqvQ5NqtN3mPCTB8QgeYkKgTiqRJh78WaMqSzIwRht/rZYn+FyGtSQa7s
         MeTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xJNGcJv2h2UR3BQ3maAHJ6jpbT35hLIku6WgjRekH1Q=;
        b=BWfo3Rcc4bHyATJ4rQoRPas8Sn856Y9hQYAW+sZphZ/jBTTzi/9sRbHUvq/h1eXVUA
         0snxLMGGiqbleMwmgw02pqbfL53jCuF0sj7sD00wu2XDspnB93PDCGY73ku2qPhDt/1L
         2R0+fSbC1fvqIb/6i/hGAPstwgIR4i68w+y1v5LhT1SZLlo3AP/HeT1hlCNXy1Zj+Kbf
         TudCJw3a6xHiU/6r3YJYeyimwRvoLJ3sU0M2QlOmCbCPLtNb3SQ3yCCAj8X/vXcCOA+v
         0n8UpCusE6rv8SDFj712iFB2nE1lCGbqGxvo+R2Z0jrznkRWnghzhiXueuSJuTFYAZuw
         pxIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GqXJ7TZ4;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id e9-20020a05600c4e4900b003d9c73c820asi158233wmq.3.2023.01.24.10.52.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Jan 2023 10:52:11 -0800 (PST)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 8BC55B816C8;
	Tue, 24 Jan 2023 18:52:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 21498C433A4;
	Tue, 24 Jan 2023 18:52:10 +0000 (UTC)
From: Eric Biggers <ebiggers@kernel.org>
To: stable@vger.kernel.org,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	SeongJae Park <sj@kernel.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Jann Horn <jannh@google.com>,
	"Eric W . Biederman" <ebiederm@xmission.com>,
	linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org,
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
	Shuah Khan <skhan@linuxfoundation.org>,
	Petr Mladek <pmladek@suse.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Luis Chamberlain <mcgrof@kernel.org>
Subject: [PATCH 5.15 16/20] panic: Consolidate open-coded panic_on_warn checks
Date: Tue, 24 Jan 2023 10:51:06 -0800
Message-Id: <20230124185110.143857-17-ebiggers@kernel.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230124185110.143857-1-ebiggers@kernel.org>
References: <20230124185110.143857-1-ebiggers@kernel.org>
MIME-Version: 1.0
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GqXJ7TZ4;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass (p=NONE
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
index e71161da69c4b..8eb5897c164fc 100644
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
index 21137929d4283..b88d5d5f29e48 100644
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
index 0b560312878c5..bf0324941e433 100644
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
index 2bd5e235d0781..c1458fa8beb3e 100644
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
index 36bd75e334263..60c7099857a05 100644
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
index bf17704b302fc..887af873733bc 100644
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
index 37e140e7f201e..cbd9456359b96 100644
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
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230124185110.143857-17-ebiggers%40kernel.org.
