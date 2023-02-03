Return-Path: <kasan-dev+bncBCUJ7YGL3QFBB5GE6OPAMGQEYSM4GUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id A2AF5689608
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 11:31:19 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id oo13-20020a17090b1c8d00b0022936a63a22sf4395159pjb.8
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Feb 2023 02:31:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675420277; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qs7P0NxTF/rVg9MXhcejjuYuG+7JNYKXYLun0lkR6fvZ0W03B5I7RrRR2h/ByBtP/V
         K7KcjTjcW/HYVeKKU9T5Nq7WB2OupbFP7aRDO+bdO4jgYM0CMARD6r8SsTpl4S7jPk8C
         WA5xuCm46oYu/MAAi+vp+99w8QAYsU5dOOLYaIIw9iUHGvL1qUQ4vVLrx8yGWUSLzz2e
         VAJKZO08OY8oCZqdp5qLvSs7ecGpGjeJH+H2+0tEbv9n2X7Yn1S6LAO59ra5sUUsiu9c
         YHdxtJo8SUiIIK6g+tUbRXpS1Kc5UQTzFYFOAmbP3QI8D0+waef2Qp677P7ECEAUp1TV
         vFzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=D5jrPsTD9ETjPYxt1WZdlG2eVV7FxVbj/hsa5O6Qfqw=;
        b=wadAftmYg7KGQW4mZY9uq/cluJRUgPycoAvhwjlaJjQIHTopnZ1Thi0TQeFrlrtp2v
         R0MhWAS5B5QFjq+pwFLOo/djghZW9RHNnt3zKUF8jtpdhr43XsUNAaZ00NnPJWMHmDdP
         Cmx5M5Mx7m4ssU0KogBbae6S2mGcZtfgjgaiInjnSpa3WZehS4hLIYmIfXgPB97Dp/2c
         Psno87KtUZs2badxJPCOoGtxiCpRv9fiYi5FJv836JoYHVqx07wHHAYjIQks2RnqTokr
         2jVDLDwMMfhgGHA/KAGhwO1iLChxYsv9RTEDp6ob7EAB0LMAfOX0VPWjg5VVTEd/pxsa
         zoOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=H7JXghOe;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=D5jrPsTD9ETjPYxt1WZdlG2eVV7FxVbj/hsa5O6Qfqw=;
        b=e1wPOoNgu8PskKkQYijazhpvqG6XUp2uMP1vncn4+x/P+JRsDeeP6MIm5+zmoycNos
         0Lim2CONz9mL9b479Au35wG7vEsh/rk0Q6MHxGI+fv+3IMLg3P6v0TWhMDEYlHKpC2C1
         BUgEbkm3ABzCxcW/MEKlgHdx7ysVQ+qMzrm7wzqFXpL6JKs5WV+9CC7fQ+uiFu2H0Ixz
         njdgelqOFac0gJa4ZcCbiRAzxQgrD0lJyPy2vjUCsqzni0TwctHDzObl/ESEtocMrTy9
         9MCZUxlumFF3Dk0adZrBBFNM2CQARC4sirHYEqsjTgtnH/8GCCvgTJJ9h3lqt4dub3Xp
         8uAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=D5jrPsTD9ETjPYxt1WZdlG2eVV7FxVbj/hsa5O6Qfqw=;
        b=PZVqL67J6f1cacMcUkyLtcpUvybP3CdLZ8ddeUF5uz4CuNRYUXC+FT1libZ1NZoCpi
         zPA2ltPGM1FQznMuHKL4w8k3xcgy4RjefPmENsqsLALmdu+fWsQLH9gAM6bb2vbgvgzp
         j7pa2M2hIo5jvISpJG+imwv3h0dLc73N3G9uhkoKOJdVfEjBxW1ibQtqIzwAeVX6SS8G
         Z0fLKP3oJ86ezhNKFltTLIu52o6y/KmTMcQxj6bSFw9f0AFdm5SF/lWlvY/eLCCrVO0X
         D/vs7E7bKgA2iZO+As6AfxEj91UAnI+sancMpKWagP1jURX5ykiwq9nbp3DS6Pxnp1fO
         a9Zw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUbOym6kT5cc1I/CbQpbuT+qmV3A1eiFueP1CSqVEneS4xEQSdN
	PfbEV1uJKp+WrstVIMECiv4=
X-Google-Smtp-Source: AK7set8KL5BPtMZVh2g0dq3t1M0HjwsYu1J1r/50KPTHsXQzwFtXOCPOSCANtj6PiqAPt8LoqtPN3Q==
X-Received: by 2002:a63:e14b:0:b0:4de:8208:afd7 with SMTP id h11-20020a63e14b000000b004de8208afd7mr1727388pgk.87.1675420276666;
        Fri, 03 Feb 2023 02:31:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e212:b0:196:2e27:844e with SMTP id
 u18-20020a170902e21200b001962e27844els5030678plb.7.-pod-prod-gmail; Fri, 03
 Feb 2023 02:31:16 -0800 (PST)
X-Received: by 2002:a05:6a20:c128:b0:bc:44b5:b4fe with SMTP id bh40-20020a056a20c12800b000bc44b5b4femr8838987pzb.33.1675420275893;
        Fri, 03 Feb 2023 02:31:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675420275; cv=none;
        d=google.com; s=arc-20160816;
        b=ECROA9utXy/Rge7m1v+f0skpG3bQA5SG2nYCsSNSjvQvmTDZXzKk4b7f5ORmeojDki
         xhay+CUQCOoMMlLzF8NeMWuaRFFL587Ea/BRKLI4X4RuIYjNvK+4wQddqNlNJ0iskoTK
         D+gHL6G0gSBpgvoILwdxpDpJXCg1NVdx/aHW4Z9ZNJJZCso4KkVmxFgC3KVnQxYCAeFm
         JYOuXMwcpndA9UDnsv7erRA/xGdx5AIi9GVCZBVoNQg1d6K4XuADkbHojdpp7pOz8vdg
         +edMom+vQMnmjlvKDdXUK59hbfL54GDG0dWLE1ZxvIBfNncZUqrkwYpqXVj17Ewiy2sg
         rp1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=n06JNxPjI5ymotOPhoBg5x2sqSBbrn1ILvlu96Zr5uY=;
        b=pf9egVYFwcIiCqgEtCIAyOg1DJqa6tc/IvsHYovgRMOYKKBBycutjM2tw2oUtaQaXV
         nftF9RjpNvMlbntNk9iA+ahXQHFAVTGrlcmtqVR0AAOFsLUZKQWb8wAyKPcH0/o1IlDT
         gz8OPTywWi5pNTbqshE2pnDK9hA/XhPyXusqIlPSfy0Z55gTTcVIuD7iaQUJtUWbvAPG
         JeGSECFtidyt3wPk9bBdQBkJJfBR6pR0Jn2a0lpxhrTt3+Yoni8wApfa/9L9KPU7jtuC
         FBlxPEnjNufvMv6BK+QaqUorowo/hkLW4m4taTPKkCJx63XwzVm6YkleDM1Boe9ZyfiQ
         vuaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=H7JXghOe;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id e7-20020a17090ac20700b00230537ca394si277215pjt.0.2023.02.03.02.31.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 Feb 2023 02:31:15 -0800 (PST)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 5786E61E93;
	Fri,  3 Feb 2023 10:31:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C2602C433D2;
	Fri,  3 Feb 2023 10:31:13 +0000 (UTC)
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
Subject: [PATCH 5.4 126/134] panic: Consolidate open-coded panic_on_warn checks
Date: Fri,  3 Feb 2023 11:13:51 +0100
Message-Id: <20230203101029.481281149@linuxfoundation.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230203101023.832083974@linuxfoundation.org>
References: <20230203101023.832083974@linuxfoundation.org>
User-Agent: quilt/0.67
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=H7JXghOe;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
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
 include/linux/kernel.h | 1 +
 kernel/panic.c         | 9 +++++++--
 kernel/sched/core.c    | 3 +--
 mm/kasan/report.c      | 4 ++--
 4 files changed, 11 insertions(+), 6 deletions(-)

diff --git a/include/linux/kernel.h b/include/linux/kernel.h
index 77c86a2236da..1fdb251947ed 100644
--- a/include/linux/kernel.h
+++ b/include/linux/kernel.h
@@ -321,6 +321,7 @@ extern long (*panic_blink)(int state);
 __printf(1, 2)
 void panic(const char *fmt, ...) __noreturn __cold;
 void nmi_panic(struct pt_regs *regs, const char *msg);
+void check_panic_on_warn(const char *origin);
 extern void oops_enter(void);
 extern void oops_exit(void);
 void print_oops_end_marker(void);
diff --git a/kernel/panic.c b/kernel/panic.c
index 5e2b764ff5d5..7e4900eb25ac 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -156,6 +156,12 @@ static void panic_print_sys_info(void)
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
@@ -581,8 +587,7 @@ void __warn(const char *file, int line, void *caller, unsigned taint,
 	if (args)
 		vprintk(args->fmt, args->args);
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("kernel");
 
 	print_modules();
 
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 06b686ef36e6..8ab239fd1c8d 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -3964,8 +3964,7 @@ static noinline void __schedule_bug(struct task_struct *prev)
 		print_ip_sym(preempt_disable_ip);
 		pr_cont("\n");
 	}
-	if (panic_on_warn)
-		panic("scheduling while atomic\n");
+	check_panic_on_warn("scheduling while atomic");
 
 	dump_stack();
 	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index a05ff1922d49..4d87df96acc1 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -92,8 +92,8 @@ static void end_report(unsigned long *flags)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
-		panic("panic_on_warn set ...\n");
+	if (!test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
+		check_panic_on_warn("KASAN");
 	kasan_enable_current();
 }
 
-- 
2.39.0



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230203101029.481281149%40linuxfoundation.org.
