Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBGMAWWPAMGQEIFQHG3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 06B1A676D4B
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Jan 2023 14:54:35 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id s203-20020a1f2cd4000000b003d5b4915319sf3820838vks.18
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Jan 2023 05:54:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674395673; cv=pass;
        d=google.com; s=arc-20160816;
        b=mtLpmZSoEPHhqK6xxBdZti5dYORQ7TYSAQ3qu335XP2w2VaAEdyfw2LpgVjMillOZD
         kvL6Rj3qccbE8HsfTDeYghbXkXpQv3L73iEMoJXW2ft/RGpzIglCbLMqgADgxObDcYFu
         7c7mWc/w8+zg+mkvBwSYUJJLlf12U4bclIHCZSPnqDIxVK8zeYP40UaZUu9+cPdHmQJw
         ZT0zn2dqWuMtulK1U4U3tPYOFPk4kVmpo+Odh7u4DZvtBIBNp3yz4JWkK87zzbwlL9Mx
         2sS4Uraujsipd6ZBu07/2+Mf2kU7QuLv+TspeJvK8Acj0K/xsezKQEUpxNxsC2CZDZ8/
         RIbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date:from
         :cc:to:subject:sender:dkim-signature;
        bh=XtZFUNVfCNQ1WJ3mKDwLzpEi6fNaOSJqjl5iTeod6rY=;
        b=lUyTE8l5aSUoBzy0V97u+S/YtPXFIhS3nj40+rrtRlfpwEQCW6FmhdZL/uCVhRqgmA
         G/+RIg5Er7Wo14HSBPu96nVTKyfUdOJm2r49eVSG65HkwKCs7BKoMvYRJQMlJ2hGoiOb
         RwFtQGmiGXkG8ZP2ORoA1RACquF5VGl46A7n4RLrDqBjcmnDsznpa5ECudU/5OKoPp6W
         jwrWPPBeiJWBe6HEV6O8pmTsbVQ/yKQN1wj0cACzIuoc2hvbDWBVdXisw6kEgUURrXmH
         hS0QfMXzXmr7LniaGCeXX9HSmQafglJ3/fO6Sjc3L8xmCKA+SjXk3h2T7JnpiUDoN1Vg
         rOmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=dn2A8irw;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:from:cc:to:subject
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XtZFUNVfCNQ1WJ3mKDwLzpEi6fNaOSJqjl5iTeod6rY=;
        b=Tnc2Z6CfotmCFw5oN5ehg8ih1/QcioHMQGCCXAYsEh9e5hJsvCFY/3FO6tHf/IgGzY
         kLWfX/LwOpAx69hbq0vnT9vC7KdFppL+pBBduazHs9APNxg0R44cM0sFMtYAfkTWPEWX
         6VgHrb1jTZYy/hHV2zxxWVpMhN3KCoH3rD2a+aRjAqCCnGgnfjvkkySoM9nq4aHMKB1q
         BZxEdr5lrmaLqr1gGC8QVOnE75v+8N5h5MHSVNNpIJopL+iakRGkVo3LoM4tjq5XTDwl
         h5/SSee1bZ4Ufav52AYNgSuIPjZVkG8nKbEraK9tl7yJTRE0xRRgPXEnTOE8z6m8hwm+
         /8CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:from:cc:to:subject:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=XtZFUNVfCNQ1WJ3mKDwLzpEi6fNaOSJqjl5iTeod6rY=;
        b=D6jPH/NNKrkPG98IHIpYYmZU3Q5eJemG5WgKeRahf/JGeRqgDiDyCGMkks832D2jzG
         D4h40n0DHtnqM40xPBukGiOhUKYiOf+iOa+IJT75z/25othknTVPZIw1yp6NcNd56YTY
         1yWy/vyQD8rStq0Z3R/V7mXfvOA3JhXqYcqE/XIjWf8Et8mGq2jqS8pEsRvZ3T0AZB82
         YwRGq9vZGcRbsUt85QCfFNoXtGdSjFbmjBxrvNYQwljsYFfu9OzsOI/4kAS5cL6bbaFe
         3Kz5KXOtii0PPorafEprYFhvn6cj5NnYfXjI/dQxM1IYDZbAeG/qtxu41o9HvESlhGnf
         6WXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koLt/pikaxtkw3LT2zY+SVMwSwVB794iIaL4pqXLTnRdTUq0QIJ
	T8/2Dq6cTWbD3LOJoY9uS58=
X-Google-Smtp-Source: AMrXdXthBZUBpsC/3Ug2xZ040o4GpbZmBLEWQ5noQ9oIL62toFsDlrHAxDKU9MIFSykdJBBs4OjzAw==
X-Received: by 2002:ab0:1608:0:b0:5e8:e02e:f4bd with SMTP id k8-20020ab01608000000b005e8e02ef4bdmr1437514uae.113.1674395673226;
        Sun, 22 Jan 2023 05:54:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d488:0:b0:3cb:9ab3:81b0 with SMTP id g8-20020a67d488000000b003cb9ab381b0ls3297725vsj.7.-pod-prod-gmail;
 Sun, 22 Jan 2023 05:54:32 -0800 (PST)
X-Received: by 2002:a05:6102:1512:b0:3d2:3737:f706 with SMTP id f18-20020a056102151200b003d23737f706mr20295840vsv.26.1674395672545;
        Sun, 22 Jan 2023 05:54:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674395672; cv=none;
        d=google.com; s=arc-20160816;
        b=uNyHCLx4nUSJFP2vr3O645qZkbCM+rta73GmwNKaIZdNE/59oVBo0ARClJ3F393N5A
         kNuLQKqRS8y2BC8plPyyEGaDPW+6nhL4xK2f2nhfsAMTrQnAz8fBYzHApAJTBYpB2ZtL
         wFgbV7Ge9kr3Kf8s4PbNagJFW9FxBfC5pWO1UCpG5rrsOZETb69k/GsLnj8sBhohxUv8
         zXv7z8x1ou6YblhWUoA0JUJvXiAwW9MCmQxneJqZSCenHpUY4GxhTlmhd5ktW1P5APzF
         mdEzSbB0BNNtQ0TUYUOf8VEf/bzbi+Jlk02OJJiuJWR+/HPYEDRaV9+AtUa/FJIExtZ4
         c1Xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:from:cc:to
         :subject:dkim-signature;
        bh=SLRgZlL57wW8C0dqM1PoINtRmgX8oqd7dqFbX9mKpnk=;
        b=e8cEr5Dd8I35MdBo1IObwr6R8bjwVg6L9oTC6ELw9O3saqVTOxJZVE3EXFJgt9sP8x
         DbWwQgpgpfjYs+95thDrcAys2fF3lwLG5Kr0v1ooATjp7kUm3FxzKkiJkejL0OBzNE2N
         pGVWWxC39JCiTuEauUeRYKtz/S7CjzQCP0CpiUK6l5QraJhIQ86d7xnSqiiSXNeVKty7
         +9qULa8jbpA+7C29WB/G+z7l4BlP6EY+2jVz8kqjtXo72P9AId96xOdLwqttLAQevUyQ
         r8ss2MavXs7LYpbymjVyyBlEvNEVgWDzeEKO5WzLlTUIjy/OZ0vvWgTxkwLTp/r9mMew
         VFmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=dn2A8irw;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id o8-20020a0561023f8800b003d04209e4e2si11556vsv.0.2023.01.22.05.54.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 22 Jan 2023 05:54:32 -0800 (PST)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 075D060C17;
	Sun, 22 Jan 2023 13:54:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EC19FC433D2;
	Sun, 22 Jan 2023 13:54:30 +0000 (UTC)
Subject: Patch "panic: Consolidate open-coded panic_on_warn checks" has been added to the 6.1-stable tree
To: akpm@linux-foundation.org,andreyknvl@gmail.com,bigeasy@linutronix.de,bristot@redhat.com,bsegall@google.com,davidgow@google.com,dietmar.eggemann@arm.com,dvyukov@google.com,elver@google.com,glider@google.com,gpiccoli@igalia.com,gregkh@linuxfoundation.org,jannh@google.com,juri.lelli@redhat.com,kasan-dev@googlegroups.com,keescook@chromium.org,linux-mm@kvack.org,mcgrof@kernel.org,mgorman@suse.de,mingo@redhat.com,paulmck@kernel.org,peterz@infradead.org,pmladek@suse.com,rostedt@goodmis.org,ryabinin.a.a@gmail.com,skhan@linuxfoundation.org,tangmeng@uniontech.com,vincent.guittot@linaro.org,vincenzo.frascino@arm.com,vschneid@redhat.com,yangtiezhu@loongson.cn
Cc: <stable-commits@vger.kernel.org>
From: <gregkh@linuxfoundation.org>
Date: Sun, 22 Jan 2023 14:54:18 +0100
Message-ID: <1674395658195135@kroah.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-stable: commit
X-Patchwork-Hint: ignore
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=dn2A8irw;       spf=pass
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


This is a note to let you know that I've just added the patch titled

    panic: Consolidate open-coded panic_on_warn checks

to the 6.1-stable tree which can be found at:
    http://www.kernel.org/git/?p=linux/kernel/git/stable/stable-queue.git;a=summary

The filename of the patch is:
     panic-consolidate-open-coded-panic_on_warn-checks.patch
and it can be found in the queue-6.1 subdirectory.

If you, or anyone else, feels it should not be added to the stable tree,
please let <stable@vger.kernel.org> know about it.


From 79cc1ba7badf9e7a12af99695a557e9ce27ee967 Mon Sep 17 00:00:00 2001
From: Kees Cook <keescook@chromium.org>
Date: Thu, 17 Nov 2022 15:43:24 -0800
Subject: panic: Consolidate open-coded panic_on_warn checks

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


Patches currently in stable-queue which might be from keescook@chromium.org are

queue-6.1/panic-consolidate-open-coded-panic_on_warn-checks.patch
queue-6.1/exit-put-an-upper-limit-on-how-often-we-can-oops.patch
queue-6.1/panic-introduce-warn_limit.patch
queue-6.1/exit-allow-oops_limit-to-be-disabled.patch
queue-6.1/panic-separate-sysctl-logic-from-config_smp.patch
queue-6.1/exit-use-read_once-for-all-oops-warn-limit-reads.patch
queue-6.1/exit-expose-oops_count-to-sysfs.patch
queue-6.1/panic-expose-warn_count-to-sysfs.patch
queue-6.1/docs-fix-path-paste-o-for-sys-kernel-warn_count.patch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1674395658195135%40kroah.com.
