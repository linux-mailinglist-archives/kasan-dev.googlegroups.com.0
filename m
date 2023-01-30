Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBGNG36PAMGQEU55SCQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 84FDD6812B7
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 15:24:26 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 17-20020a05651c009100b0028f23beb02bsf2284812ljq.13
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 06:24:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675088666; cv=pass;
        d=google.com; s=arc-20160816;
        b=GBw/JkOuIlrj281IdsG0yhQ1NknK8CX16VwgeUNgdpKHLWJgfi6PIavd5rvcV8XPsZ
         j+VrdFXU/P3Ol2WXDiSFON8BV14ll53T8BJiCj8mJs6zTI1+WK01hgsqLxwoy2B07FsW
         sBOMb42BgsObIRUQiDb8AfKX78I4qAbenHS3d8lPjggwccBSY7g/XAC9ckrVjxWH8XwR
         /iD6u8KKTRIXPbKFiKWPdM4+hAc/EjxUpNPy5Usn2RLr1J+m77zvJe3rMkK2s7ko2z0J
         thGy67Q6KO3iEGrKl0n3J4AtUstSBX8TrCCyiXYM4uPK62DI3QM/a+kxBhTEeNWfP0Bs
         e12Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=qP3yro45xUYxV4FU5WT2LzBU571Uru4obRUubrM6OW4=;
        b=n9yanbHAF9ZJZlQgC5a4FM+tCRIfcGQKPlnZEUUYDd1+9gODID+WPuyNUg7fXBaVbD
         qnifoXXsdx/R3wfl/iRhPjglbOh/pZJAk5AW0RVUJ8JafzhdkaJRazVB2GC37YEIpP8q
         6YKi3c3EB0qyw2HfWY16cNt2+LZlcqAsMrMQmXlZIR+tc06vVRG7ecPLoX1tHLWEWPTT
         QSsVJtTRXHD4Nu9OwFF2+uvNd5LsGQam3qhS3XVfFXY2W0QlUYQ5FBtz3Tn7X664uKM5
         otIYIPQ2nPPS8iRHKcgySxvdSbxjoQ3mcsBnBGz3NZ+Z6qJCGQUZNidG7YvMCFMyqc9q
         MNVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=RATipVPU;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qP3yro45xUYxV4FU5WT2LzBU571Uru4obRUubrM6OW4=;
        b=j2HmQTLCTD1GLxXu31Kl7lryeL6AnO9v7QhJnSMRkxJRUHeY3+t8d8pcenUUiR9G3A
         GyZPKjI70/Y6MKZ5bZmT33HlGPkId7zx5BS3+jfsE9C0TCwzU38nC802n06IViplpXiP
         Iohw7TTheZLnMLVU0eRSslSVQDE5UV8baJD0d9afoeX0uFdbUbpxXido08AswnHC8ujY
         l0YNeAgOm1eRiVIsHJZPyU+vlBL4U2USFkFGWaH9Ftyf7q12NCpcIVKvlM0qQvB6Ufnj
         3Zp4aEBVWmkBb01G5yhIUEOa/v804hjRH20qVhqTSLCnzVZSmDKPHp8g2YoCmLK7qQki
         f1lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qP3yro45xUYxV4FU5WT2LzBU571Uru4obRUubrM6OW4=;
        b=ciqi6BBeKdeLVPTmWR4eZTNeaEi1SpNx0ppSsN2CoJyHZ6DX7dBIU27T95bKwmO4Dd
         4dTholMHvGDPKImV3J4xjaR7CSdB46ty6rHzF912G2RBsviME82K32j9x0cmRgYmeMCp
         50gPomvpvOUrpCcrs+7C7NsTKLQAUggWQJeoKlNzmtu5xk9WzzdgbdmY4T/LH5qApTXJ
         yeoy2YlfrFPQiN2wIIDLoIxswVfp1DkRjuZSMryMLRlKe+T06ptJiCYSW6WitPIE267Y
         U6676M5/vmvmn8/Z3P0ekrZbGNRW49m8qGD+KJD8Q7HxObGkVHIhqn2aQWSxtDK+NL5B
         b1Qw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpz00lBXoymTCMrbfzSbA/7sXb0IicIG3HHTwlkc7OVgjBiUQpg
	S9jN0ySY8n7aUCKkSZyznU0=
X-Google-Smtp-Source: AMrXdXtMdvMzs3ayKiuPc77wBzvXn6jf53dK+hXhMUSIyJ6vCiabdXEkM67FuoyETqj1VC5z41KiwA==
X-Received: by 2002:ac2:5339:0:b0:4b6:f0ac:7af5 with SMTP id f25-20020ac25339000000b004b6f0ac7af5mr6767497lfh.73.1675088665674;
        Mon, 30 Jan 2023 06:24:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3116:b0:4c8:8384:83f3 with SMTP id
 n22-20020a056512311600b004c8838483f3ls2177639lfb.3.-pod-prod-gmail; Mon, 30
 Jan 2023 06:24:24 -0800 (PST)
X-Received: by 2002:a05:6512:2809:b0:4d5:8306:4e9a with SMTP id cf9-20020a056512280900b004d583064e9amr16147673lfb.46.1675088664246;
        Mon, 30 Jan 2023 06:24:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675088664; cv=none;
        d=google.com; s=arc-20160816;
        b=lVGlOy1i2vfHYJhHiaEmBcDA1STE5cxVDTC6MDfwY/B/V79XLL5Mubmmb4zAw7T4J+
         4B9yXfYE0Kg77I6B0W/cVUDgg+bvhu1DOffvpwc2oow5yBHUnP+a3GyhZ8LmNOFP0eSC
         v0BP/H6fJbL49K+UKroK8tPFJ3IoWwOGdVpr9Cd8511svW9u62TmIzGZMTaOVcJxEO2p
         NuA7r3hXr0Xunn4wTU5v6D3abqr1+BngPswnCY4pzCf0IRT4pc/asZ6THDJ0BhKKFYqz
         5aQaIM5nL63n0zEccCKzDUvELMKxClaZa7DEVUiKyJ4jFNwjGn6O7oeg9H7uYN7e9TUT
         lyvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=eklLDj3vjqmi1JAEH9nmkvE8R8TFrc6yFvjm6e5rp04=;
        b=PLGZIiAK49Nlquj43UezY0aFLHSFJKWvUhpgf9K9Im5xGv4bF5dPoK0HyCu15ASp1D
         Ff7AFvEPynTZaxRRympUOyRAJ92fQPRKyK9i7iGvGq/NODZUdeoStSxNAEQ+WpWbqMGj
         T//8f4Ih+jAPYU+Qzurx8cYcO+//orO2IMWDUwI5X78QqZ3OkUmi3uWOixFg9ylVeYSx
         elsDs0BLQeNlKf39Kl5OzkrrnkRUgC2rGf52IZ1hl75WaM5sZ56ubHrGD7nvx+hZRh60
         4o6ThcVfd3ET+O7ykOpqtAziz6UdAeduwIfkRNaqx7bQuGO9UD+Szkvy/4Q6SLyN6ZG0
         KAOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=RATipVPU;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id y5-20020a056512044500b004d579451cc2si715573lfk.12.2023.01.30.06.24.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Jan 2023 06:24:24 -0800 (PST)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id C6133B80C9B;
	Mon, 30 Jan 2023 14:24:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 034D0C433D2;
	Mon, 30 Jan 2023 14:24:22 +0000 (UTC)
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
Subject: [PATCH 5.10 094/143] panic: Consolidate open-coded panic_on_warn checks
Date: Mon, 30 Jan 2023 14:52:31 +0100
Message-Id: <20230130134310.753061249@linuxfoundation.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230130134306.862721518@linuxfoundation.org>
References: <20230130134306.862721518@linuxfoundation.org>
User-Agent: quilt/0.67
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=RATipVPU;       spf=pass
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
 include/linux/kernel.h | 1 +
 kernel/kcsan/report.c  | 4 ++--
 kernel/panic.c         | 9 +++++++--
 kernel/sched/core.c    | 3 +--
 lib/ubsan.c            | 3 +--
 mm/kasan/report.c      | 4 ++--
 6 files changed, 14 insertions(+), 10 deletions(-)

diff --git a/include/linux/kernel.h b/include/linux/kernel.h
index 084d97070ed9..394f10fc29aa 100644
--- a/include/linux/kernel.h
+++ b/include/linux/kernel.h
@@ -320,6 +320,7 @@ extern long (*panic_blink)(int state);
 __printf(1, 2)
 void panic(const char *fmt, ...) __noreturn __cold;
 void nmi_panic(struct pt_regs *regs, const char *msg);
+void check_panic_on_warn(const char *origin);
 extern void oops_enter(void);
 extern void oops_exit(void);
 extern bool oops_may_print(void);
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index d3bf87e6007c..069830f5a5d2 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -630,8 +630,8 @@ void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 		bool reported = value_change != KCSAN_VALUE_CHANGE_FALSE &&
 				print_report(value_change, type, &ai, other_info);
 
-		if (reported && panic_on_warn)
-			panic("panic_on_warn set ...\n");
+		if (reported)
+			check_panic_on_warn("KCSAN");
 
 		release_report(&flags, other_info);
 	}
diff --git a/kernel/panic.c b/kernel/panic.c
index 09f0802212c3..0da47888f72e 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -192,6 +192,12 @@ static void panic_print_sys_info(void)
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
@@ -630,8 +636,7 @@ void __warn(const char *file, int line, void *caller, unsigned taint,
 	if (regs)
 		show_regs(regs);
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("kernel");
 
 	if (!regs)
 		dump_stack();
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index a875bc59804e..1303a2607f1f 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -4280,8 +4280,7 @@ static noinline void __schedule_bug(struct task_struct *prev)
 		pr_err("Preemption disabled at:");
 		print_ip_sym(KERN_ERR, preempt_disable_ip);
 	}
-	if (panic_on_warn)
-		panic("scheduling while atomic\n");
+	check_panic_on_warn("scheduling while atomic");
 
 	dump_stack();
 	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
diff --git a/lib/ubsan.c b/lib/ubsan.c
index d81d107f64f4..ee14c46cac89 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -151,8 +151,7 @@ static void ubsan_epilogue(void)
 
 	current->in_ubsan--;
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("UBSAN");
 }
 
 static void handle_overflow(struct overflow_data *data, void *lhs,
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 91714acea0d6..2f5e96ac4d00 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -95,8 +95,8 @@ static void end_report(unsigned long *flags)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230130134310.753061249%40linuxfoundation.org.
