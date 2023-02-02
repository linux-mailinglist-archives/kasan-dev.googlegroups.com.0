Return-Path: <kasan-dev+bncBDEZDPVRZMARBDP75SPAMGQE4GPIQOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C50668747C
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Feb 2023 05:43:59 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id bp18-20020a056512159200b004b59c4fb76bsf406919lfb.2
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Feb 2023 20:43:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675313038; cv=pass;
        d=google.com; s=arc-20160816;
        b=mTLATFs0GRX0fz/u9u+tVuyZSwFDARP2Eqfmo3DyHVRJGB3DFUdR/qpQq7qV//UvCb
         5g1cNJ1ytNVJ3/xBn48QBIi3kqDPb1Z0MdlkOxYtE8wi0Gqh2iADmGEGDKDjaM/IkCyn
         R6RmmgFznT/1taessST77QWFxEGhmGhR8csCPbteD0R2tOMDUa5VNUrJfyCjxZxuibEW
         5Kb/Wufb9npN48yGGHx9GLZvjPi3EzRO05G+/3GLHBNxllY5dGYCALrZh5j0NI0O8+Nf
         3ZqxrDZnxvVz8g3m4wvtNVbpMNMqcLabJjKYThkdn+hCsitKPViJuoWWMwFvEcXG4dSM
         IzOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OJLK0M1I+IZzL1gwO4M8pfrYaaXtAQwsioBop10Oi3A=;
        b=qOghmiREHW7q7iQaF3KiMtF+MYH1zgxdI7le+PeBIKG2uwrVrB1BaFIkeeOq3Dv5io
         1nxtnre+MkbqEh5QzcOfVnyuRQAn6nJ1r1EYHgyXZv7CJrqELpj3vwyi12kEN48Dfn7T
         kFGb+IeOd2Y/zxmBGQK4OpC3kGNkP6EV5F/4MDCC2KBhxp/XB8sXCxtgimq3NCNDHwxm
         RfAoD7Cae+vMc0Y6AdfJ45H6J+mkshvblZZ5W7l6nPlCItYx8S5fJ6q5oAMOtV2TBtV8
         BZMc5/dpWwRCSdvJWi5WhoCVTSeXue/ZAgRt+hu/aGmV6fntN0jynTA6f/OCgTMrCH8e
         inXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Sf+IENLZ;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OJLK0M1I+IZzL1gwO4M8pfrYaaXtAQwsioBop10Oi3A=;
        b=rHb2Nlziv3YMMXPQCc4/E11gq8VzxilhZEBddlEP33uuStYJi1ZcZ//6FVN00oyWb7
         TYEzRdc/GsFQ25q2nVb1tVP2hFJ00ECIc4Pko3s+gJW9v27ISjYV3Vr+SRCHT851YVA/
         NkAQnrEW4MlUaF3BEJfnxybhXTnF0SuQeDDeIKD6CiLJJW3pl4JGuE7zqHVshrgRnnIX
         wfnBhujCqzYdlfngBfaBswXiomkx6PjwLutMJzOd2TIGlRQilMIa0qWa0pTisMOZ/4Ua
         coj7T8JqdPGZupoSCEUl5V8QyDLsb8paoqd9ycZRATYcDYyiP5w8TBIHdTVZGgZEwZ04
         NaLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OJLK0M1I+IZzL1gwO4M8pfrYaaXtAQwsioBop10Oi3A=;
        b=djxb6+CEjCN4tZ1AYtQEab8zt2JocZmL48XUpoum3Lez7nM83U1Y9BHDOg5yoDGCsj
         ASWdE5QPfbskZqHB50s+1mGK+LvGDehzYaYfN/28r1+eWEgJFkFMUQqsSq7siwdVxhX9
         Wh2aQxcD8zgyzv/RDuCGPTkBf4PERoiHe9zPGTIouOxoFoqBefpUJ92fw6Ocr3rt5+IZ
         05VGKrZXLrSXwMLWjH5nyPKc5Pe+OrxK9zTO2efmRfzO9UJMJ/zLiTaBo8l3W3N+NlUS
         vAUpxLf/VxpiTcNUkD/aN9NXblZCfqCfLyfc+WZSrWJY//i8vmAWt+uIcE6xcwqa/M5Z
         nN1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVt80HXdc87J8thQKdKPMuAslEemLH4RUgGXNumjdMx68WEMFTI
	bTtuDTuyxzFEjGG+u91ki6A=
X-Google-Smtp-Source: AK7set8cOxIhbkcKrLSeBnN7ukVfRIyDqhpz3VGPC+itcKZyGvC4Ty86c6SFaAhCVuYaeGDXxcs43A==
X-Received: by 2002:a19:4f5a:0:b0:4cb:41ca:184b with SMTP id a26-20020a194f5a000000b004cb41ca184bmr996069lfk.54.1675313038097;
        Wed, 01 Feb 2023 20:43:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:10c9:b0:4d5:7ca1:c92f with SMTP id
 k9-20020a05651210c900b004d57ca1c92fls418227lfg.2.-pod-prod-gmail; Wed, 01 Feb
 2023 20:43:56 -0800 (PST)
X-Received: by 2002:a05:6512:1595:b0:4b5:8f03:a2bc with SMTP id bp21-20020a056512159500b004b58f03a2bcmr1457377lfb.9.1675313036305;
        Wed, 01 Feb 2023 20:43:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675313036; cv=none;
        d=google.com; s=arc-20160816;
        b=bY1rqPOu0F2a/JNYD+1oeLn4Tt2EfUPtQ8C3unWkszH+ohj2NOqDmciFmdxSXsvXpd
         hc83diymd4ROrRJf4MhHIbmxRrnlHUauduCOk599DSknk7lfJJjpVL/xdeWYoh+wNv4h
         9M8ixMfk4lptpm69fDr7Cvlt/tM8AsNudKeobxaKB4Lx2M6a6QVpIMInoQS2h0sAnDEX
         hzGcw299a+2Zfi1pO/wPj2jB1RESxlAMhcbKTU4W133BSyOeVzat+CPuLS3sG95IhuwQ
         SuUwc+LI84jq1YPcJG56qRR+0IrV0Jp13qjH4oCk0D+cJMPeLuKhiXui5anjFz77YUWs
         wSVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1d6U6SvfkV1Q4VXNQw/YmTFmTyuRguphtqdsa72EubU=;
        b=y+eGv6ce77nN0ilaR9G5Tar6UlKWu1bqoLRg0ijzsU76aneHT6stGb7wqP8NPOsLJZ
         9hPLlXsqd9GWIWE1ZF+TZ+CduLO/zvE+T9rQv/8Ldbl5UjRY0X92mB1MkICREN/PvDzI
         Q9vwm5EYVsv5XOO6eqfK1ABJkz1lWTA+dKJJFEgs7tP9Tmul5EqOUuTyDvr/u/+wTUsE
         9PsUKbD7b1rXf7DThBb2RAIP0hyV+XUU7Z6TPsHkZKUKJ+w2psnVAGDfpktjCkdxEtTn
         lnG/7Oy8gLNtCJ5dFz3KxDIvkScYZFKwwuKchliXZy3WtzXyNXyh4UnytMmdAAVRd5wB
         O33w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Sf+IENLZ;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id i30-20020a0565123e1e00b004d5e038aba2si1084361lfv.7.2023.02.01.20.43.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 01 Feb 2023 20:43:56 -0800 (PST)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id B1ACDB82425;
	Thu,  2 Feb 2023 04:43:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 59556C433A1;
	Thu,  2 Feb 2023 04:43:53 +0000 (UTC)
From: Eric Biggers <ebiggers@kernel.org>
To: stable@vger.kernel.org
Cc: Harshit Mogalapalli <harshit.m.mogalapalli@oracle.com>,
	Kees Cook <keescook@chromium.org>,
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
Subject: [PATCH 5.4 13/17] panic: Consolidate open-coded panic_on_warn checks
Date: Wed,  1 Feb 2023 20:42:51 -0800
Message-Id: <20230202044255.128815-14-ebiggers@kernel.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230202044255.128815-1-ebiggers@kernel.org>
References: <20230202044255.128815-1-ebiggers@kernel.org>
MIME-Version: 1.0
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Sf+IENLZ;       spf=pass
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
 include/linux/kernel.h | 1 +
 kernel/panic.c         | 9 +++++++--
 kernel/sched/core.c    | 3 +--
 mm/kasan/report.c      | 4 ++--
 4 files changed, 11 insertions(+), 6 deletions(-)

diff --git a/include/linux/kernel.h b/include/linux/kernel.h
index 77c86a2236daf..1fdb251947ed4 100644
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
index 5e2b764ff5d54..7e4900eb25ac1 100644
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
index 06b686ef36e68..8ab239fd1c8d3 100644
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
index a05ff1922d499..4d87df96acc1e 100644
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
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230202044255.128815-14-ebiggers%40kernel.org.
