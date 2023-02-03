Return-Path: <kasan-dev+bncBDEZDPVRZMARBU5N6GPAMGQEDWQHSTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id A0A84688BDE
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 01:35:32 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id b24-20020a0565120b9800b004d593e1d644sf1479562lfv.8
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 16:35:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675384532; cv=pass;
        d=google.com; s=arc-20160816;
        b=PWk5XM1Svj74DRr4Dm3I5EF5aQkGFoLnPEROsXLDIUuhlgycOo7r07VVP3H/e3JUQQ
         m9x0wef+YTxA2KBwU+RzCtf+pjCRdNb0N04vppl8ZKDAV5nobJXFERhiLtfxhdefHJSE
         CUimtFaq/9YIoHIOnyYpK//dYNVNHmsS9LrMEs+eB9xTzf7UJcSmWwgUtUawL6eXx00v
         RlQF4ZSkBHuNc4Xqw44neYa/6k3fIYhYFygpbOSY0iBdtcDAXwFDCZAdbtnR0B7RHmBe
         yqy9NCU3didTpZ7rvCXR5XYckv7uVMs0Ud25TdqoVlp0/Fou3kedNuuGVDIBzsBbAdOY
         hXxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=X2e4msyIiUi1WWvQ41Zh6ZM9CVZ3vTrWGTivzc1ybao=;
        b=ahCUJvr77M5wQ0kccqsYYu0ELTNtFOIDY/wAVUwzUZC62S+iVH4yOXWvBfkDHRHU9H
         cguVrp2JmnCJZSTp6VbzH/6Mvjn4UXAz0keDYr0mxcY9umqjZuuxvGWR8GUCxWgVRR6X
         OzFNe5lsB1gyaBs8ABz3otC3w6x9yehaUAy5RxoIPJds36HZ9frrvMcs2sGLC6X0sH2G
         gsnPVx6hjEY229bgp3rO8tXcPSi1UxdmwX0Uso9hR1oO/YZD2bJt0N0Wz0nD9p1tNqs/
         QW+JfP/C49pJ6GRjgpoHXSSi3+IzuJ8rgCyYawXCc/MLUyP7BPhlJwiGsqPR59Qh8yAJ
         4+xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KKN3O7Mr;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=X2e4msyIiUi1WWvQ41Zh6ZM9CVZ3vTrWGTivzc1ybao=;
        b=d5IiKl/dfyEG00mCFzYJAPCq756/WbLJBsE1svSijRDBBABP8/+1L3nBAUQUOQInjM
         OW68eFt/nbGYeDyklnCd8olMVWZC3mbBipmzMHNojjp/iifBCDsDiZniLtI/5Zc5yT4A
         Ft6IvtqaHNBsnAE0sIhaVgOzndg+SzGIwcXrDoSLP7FBhGPrTftMvhu1DLkDA4fObp6/
         B4SIk2s4ypDpYwOyXgshTihqPFhS3FdUigJeCxvhShfQPrusUnHZDsJvRpSUhuBbgUIo
         MpdybYer2PfO5++0sdHqHU7KprH3yxWx5Lt4Q0EJHq8zgyRTGAOmq1nu4INt+Q93xlkr
         izsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=X2e4msyIiUi1WWvQ41Zh6ZM9CVZ3vTrWGTivzc1ybao=;
        b=F9wL2p2yrUhvSMeg+ospLxVItDuZgLFlFZ7GuQ8bVMhX/oPhJjpZ8uVf4OmmGfcJAf
         bdpZlkL0U9cavEKtOecmymCIizfMtl0eoxDfAFwItANpkIYxJdiuyDskvsv7FHDbkzQC
         BHA8/2SJY+RNiNrLDBXfZ74jes9ubeNsWoquPWx2kzMIGkotLNNRp34/XBhMP/YLsmw+
         tfQqy98hOojdKxAPBO/Nikg61TgL4AKya2KWpSBS8T1gK9IT/IONU6b2SCjIi7jAqJjS
         lHCrAAD2sQehxwzh1tErvtJJTMGKqzbXxkN74qBv6T5EGQQl71JdqEjpZl0+7sXXEuh2
         w8vw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKX84KeTEXe/LZpRFLGuedDL2d/cMkBNcNX32V59L2xEjJHdHQnK
	llkzFUsQJohsmA3epu3LwKY=
X-Google-Smtp-Source: AK7set9Y2xjmx4bIOAGDXijYBEdm5V3OUyWWSOsweEoEcIdt6blNpEiXEOpibtiyMnwjYaE5lWAG+Q==
X-Received: by 2002:a05:6512:128f:b0:4d8:5083:ebd9 with SMTP id u15-20020a056512128f00b004d85083ebd9mr1384037lfs.158.1675384531992;
        Thu, 02 Feb 2023 16:35:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d1f:b0:4d1:8575:2d31 with SMTP id
 d31-20020a0565123d1f00b004d185752d31ls2556838lfv.0.-pod-prod-gmail; Thu, 02
 Feb 2023 16:35:30 -0800 (PST)
X-Received: by 2002:ac2:414a:0:b0:4b5:b06d:4300 with SMTP id c10-20020ac2414a000000b004b5b06d4300mr2073302lfi.29.1675384530424;
        Thu, 02 Feb 2023 16:35:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675384530; cv=none;
        d=google.com; s=arc-20160816;
        b=VZceUw03/2NbbCg2dRn4y4jmSNa8lCakbgADqzzNBemMi3UxKQjGwv0nhEZGbckv+g
         vy73yoJWkUXGwf434qmV8HlBNAUT140j3gpwNMBsR7IE44czagaoibUn+BAdgPRF9lOI
         NYwlcb3JgDxSJG8ONNCbGmgQl9JtthKnCKQROBUc13nUKd3f//TZB1X+8GYYdeNXiyPs
         L//R/TdGzkAN5qHkBipUoSU31Rpg3ColTeC418tC5D+yNJ8GyrwaJKTDR2FB+zFgiyOw
         eRFXY5Y0mr6yecPfUOUFBOayWwV3y9rLWxavGyLaCWjJNfCWqwSmr1QZpl0yZzT8Cf9m
         hBNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TkJOR9gE/ZgCf1np52kiVzP8tod51X8d+0G4m7OAISk=;
        b=YLO9/XU/ubcYaJUbmqyBw+eBh6gMiRUks+WRF2Ij8pg4GYP9RkJdj7L5WoBTA5rFe0
         q/Ip2ifX+KvnJWKGXnL9P7xXB2Gty709DWE8VxKitRp/qk65EuJDPwjWjdJaenRFuqww
         K5SwQEqBcJWcQ1jFKgBfDWGZsgqxGWAOUZqzxs4MY/GxvVWzkU2/BYN/R0g9SAXaekc2
         kGNk39Mq4Z1MrMsZbIc/e1A3RGcrnkkZCpXoOiJWxLjcXuHmDz1K4aZ6JT7gsFsngONc
         HuJhpKakY2o2m4gop+vgUqZBPXAbTWP69Xu7nFwkAQdeGXQPc+rIXHA/s4qiQhRla0Jv
         eHgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KKN3O7Mr;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id c23-20020a056512239700b004d34d4743c0si52623lfv.2.2023.02.02.16.35.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Feb 2023 16:35:30 -0800 (PST)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id DAFE0B828E3;
	Fri,  3 Feb 2023 00:35:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7F7BFC433A0;
	Fri,  3 Feb 2023 00:35:27 +0000 (UTC)
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
Subject: [PATCH 4.14 v2 11/15] panic: Consolidate open-coded panic_on_warn checks
Date: Thu,  2 Feb 2023 16:33:50 -0800
Message-Id: <20230203003354.85691-12-ebiggers@kernel.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230203003354.85691-1-ebiggers@kernel.org>
References: <20230203003354.85691-1-ebiggers@kernel.org>
MIME-Version: 1.0
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KKN3O7Mr;       spf=pass
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
 mm/kasan/report.c      | 3 +--
 4 files changed, 10 insertions(+), 6 deletions(-)

diff --git a/include/linux/kernel.h b/include/linux/kernel.h
index 22b9146655958..a4ac278d02d0a 100644
--- a/include/linux/kernel.h
+++ b/include/linux/kernel.h
@@ -293,6 +293,7 @@ extern long (*panic_blink)(int state);
 __printf(1, 2)
 void panic(const char *fmt, ...) __noreturn __cold;
 void nmi_panic(struct pt_regs *regs, const char *msg);
+void check_panic_on_warn(const char *origin);
 extern void oops_enter(void);
 extern void oops_exit(void);
 void print_oops_end_marker(void);
diff --git a/kernel/panic.c b/kernel/panic.c
index bd7c3ea3bf1e6..8e3460e985904 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -122,6 +122,12 @@ void nmi_panic(struct pt_regs *regs, const char *msg)
 }
 EXPORT_SYMBOL(nmi_panic);
 
+void check_panic_on_warn(const char *origin)
+{
+	if (panic_on_warn)
+		panic("%s: panic_on_warn set ...\n", origin);
+}
+
 /**
  *	panic - halt the system
  *	@fmt: The text string to print
@@ -546,8 +552,7 @@ void __warn(const char *file, int line, void *caller, unsigned taint,
 	if (args)
 		vprintk(args->fmt, args->args);
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("kernel");
 
 	print_modules();
 
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 544a1cb66d90d..5dc66377864a9 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -3185,8 +3185,7 @@ static noinline void __schedule_bug(struct task_struct *prev)
 		print_ip_sym(preempt_disable_ip);
 		pr_cont("\n");
 	}
-	if (panic_on_warn)
-		panic("scheduling while atomic\n");
+	check_panic_on_warn("scheduling while atomic");
 
 	dump_stack();
 	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 6bcfb01ba0386..1c96c83f97751 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -172,8 +172,7 @@ static void kasan_end_report(unsigned long *flags)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("KASAN");
 	kasan_enable_current();
 }
 
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230203003354.85691-12-ebiggers%40kernel.org.
