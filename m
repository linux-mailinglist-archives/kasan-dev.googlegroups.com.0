Return-Path: <kasan-dev+bncBDEZDPVRZMARB7XFYCPAMGQESHOIQ5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 52A8A67A30F
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 20:35:28 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id c5-20020aa78805000000b0058d983c708asf7248822pfo.22
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 11:35:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674588926; cv=pass;
        d=google.com; s=arc-20160816;
        b=pmpNs5ptHf6wUPycTm03ZLiBgsZPTruywUdJlN5DfCzw4MIx0IAlLLpk9QWLo37Jx1
         BkG/dKA7aae9yneMje6H+8MMkARypMRyltWB+cN/v1z4dT9xq3BRJfD5yWfGCqX4iPsa
         QT+Mm227/41M0kFg7llwiWNVytTjiiXz2k/u3K4d727GzaT3iCDUv9UQuIEVERYC2xWi
         VLqB5COaQ9mdNiCQnroK4ORLSTWK+2kOAcY0qkv2fJIwjkdQPxmZMN3K/yxPkRRCEkCA
         lTxKWgqFIP9ZOumCl1mq8rGhjT1Bf4j4lDbnAesacea5DvnRuj8z5PlEcx9JLAIMEs3V
         PkDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PuCc0zFkRHT9/sdHfN8BDhkWsU86a4ZVlRy50A3HHEs=;
        b=ZUJuYfFpDhrglBZWZfQRfXLA6es/jLjoM8y+LV2rMlRtbKIYE16m6CpQSwjLtvNNSG
         pkGvtfw7STBdhv3eI0+1ra+j2Vpj0PjCHuW6kTIodVhyJcWUfZEl9hJwd9o6SegI2IEt
         KWg0jQCsOIUxG8qP3fyeONIRu9Esy+PiF/PBRspJkJHvs/2wfhzEZ1nbOZnJK3mTgYg1
         3so+3BwWvhpAmsBrTrVKc6dLxy+yE0knRswyZoEAyqPq0CsiDZzhstTLJn+6aCHl+ROq
         XezcDnWkSTajVAs5wFwiq5ZHK2QMoJ5viJk/4E3bSf3y4cUzIZCW/YTIR6B0aYkmcM1f
         KwxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YyDF0M7V;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PuCc0zFkRHT9/sdHfN8BDhkWsU86a4ZVlRy50A3HHEs=;
        b=Po66wJNpZd2iZwqwkPM7W1JFunVB1PcjLR4yTh7oEQJ8VkdPdC2ZBPeKHyZLO/T/OF
         QDpznGgqFIaQ3g64ItEGCnkXooGlLdYIX5Z6IVlmWfzQSOQKxyslou9Y3o6wWH25vSfh
         hBvF0l1kW6uOQi4mst8sU4oSRgRwzZOHdGR/xkpBBbVu4FLl+n3bTFzUa7oEOadKURaL
         /0tavSSCTybP5k4yOpHoF5jP9RIFGozET2hJ39UX2WKF+DD6BqZMgOpxi5ohzWrylnZE
         o/xX7W2Ku1+nAySOaGSCZdlCNvwrQ19bmAS2vQFs1sL0MWSoMZZmnVpbMa0Hn/B3z44J
         NMQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PuCc0zFkRHT9/sdHfN8BDhkWsU86a4ZVlRy50A3HHEs=;
        b=idQw2ZBBHtmPU3uHTIuwQTdkShgJ/lbsfHT1KFb6F/LChFlu7bKvbafEXkLYYotFxf
         5LgijvNtc6TlFRZZfzDN3+3hW5zaPNf8wmpBan1+HYR2+S7z9Rh3x8MfvxexUEAEkfUJ
         lHSHYhxfCuzBCIx43j7rfDYd4BgpJO3sk0onjRF8+RdnMWZzXBIuGrJFpT96OMvyRKbk
         XpE1R2+iv3q7+4LMgZ4aU9j4pxiTj8YTpMh7Pu3nVpRfcnL5cV11OIwQPZMm6IGHNqiX
         v7K+28PAHGh+zmBinBW/glHdvve/adaCLW/bhgO6C4J/dxX5omAj+5i/etFQDDpsXS4H
         P7Xg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kp0mAaswpcx9dmxCdxDnlIqmcQGV+8/RCVFwQIyTRnUbAvT4ndu
	zKZGfeNxmuOH17FQi6gfQh8=
X-Google-Smtp-Source: AMrXdXtC5wai1wA+Hzj18ApZamk2YV67vhC6nvFvGE0aeLo5essuDsq9h/GtOnDaxnlFl7hKVL9jBQ==
X-Received: by 2002:a17:90a:7644:b0:229:7d98:4587 with SMTP id s4-20020a17090a764400b002297d984587mr2983657pjl.10.1674588926398;
        Tue, 24 Jan 2023 11:35:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8c06:b0:210:6f33:e22d with SMTP id
 a6-20020a17090a8c0600b002106f33e22dls17565529pjo.2.-pod-control-gmail; Tue,
 24 Jan 2023 11:35:25 -0800 (PST)
X-Received: by 2002:a17:902:d64e:b0:194:8d95:a4dc with SMTP id y14-20020a170902d64e00b001948d95a4dcmr27083608plh.65.1674588925630;
        Tue, 24 Jan 2023 11:35:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674588925; cv=none;
        d=google.com; s=arc-20160816;
        b=tHost9MlsZqUslgMMAJW7R8p+KdwCQP7NaUTSLPj0KzQhIF8+aVjnz4s6DgDoV+WyW
         1eKRvI+FQ0OGPn3sh3ui84JjLsB9LmNLLau2nSXwfQ9sXc19FCC/rLB3v9Ma7S+LZxGA
         HVw2IM4kK01RGqBMlkkVkvMnEQmonyqSAPPhSoomgP4QtBjTRvLpOf+dhMsXU1PxsEgy
         mUPGBsdY125vgKjJYYoRrNW2YszE/9PBe7r1DaDg4eodEmGZdpq0EDmcL7BFd6xmR9+m
         RbBnQXIhFnO/NMi6I3tqmsQkn7aYSJ4Lg/RMWxAPvBGIw+ukjffuTHsdpOsZd5T1xUF7
         Vb+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4z52APiytAm8OqknPvttz9EikKLtbzkAxZOEsnVF024=;
        b=gZluP5Stxpt5bcA7X0U+LKO0maS/6POEce6mRdi0ywe99CD5K1ivM7l4M2IsH/VOp/
         GYxQc06p5ldT+ne7uFz4ql/3ESa1Lto0iRwWa7xQXDyfR66THVIzuy8yzdohpzwoN9GY
         xwpWgvS3Vv3aIDX7jsQGqyXSetmM8BGKD0L5+VFeswwg4fXYZre7FTibpR7a683I7SS3
         PveQZI/E3ynC01muO58GHC/yPk/dODrmxjDXy0zSUgVZWwI8y3xZ0AaU0IPcJBez68qR
         QyMT9g+b/PQ+wuyZEaCGQMeXeFtIDSXmyKRMyp+c5+TCmpW+btk8S46c+O0fwxC4dpL9
         9ZfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YyDF0M7V;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id z4-20020a170902d54400b00189348ab16fsi174794plf.13.2023.01.24.11.35.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Jan 2023 11:35:25 -0800 (PST)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 1553361344;
	Tue, 24 Jan 2023 19:35:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 65E30C4339B;
	Tue, 24 Jan 2023 19:35:23 +0000 (UTC)
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
Subject: [PATCH 5.10 16/20] panic: Consolidate open-coded panic_on_warn checks
Date: Tue, 24 Jan 2023 11:30:00 -0800
Message-Id: <20230124193004.206841-17-ebiggers@kernel.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230124193004.206841-1-ebiggers@kernel.org>
References: <20230124193004.206841-1-ebiggers@kernel.org>
MIME-Version: 1.0
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YyDF0M7V;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as
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
 kernel/kcsan/report.c  | 4 ++--
 kernel/panic.c         | 9 +++++++--
 kernel/sched/core.c    | 3 +--
 lib/ubsan.c            | 3 +--
 mm/kasan/report.c      | 4 ++--
 6 files changed, 14 insertions(+), 10 deletions(-)

diff --git a/include/linux/kernel.h b/include/linux/kernel.h
index 084d97070ed99..394f10fc29aad 100644
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
index d3bf87e6007ca..069830f5a5d24 100644
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
index 09f0802212c38..0da47888f72e8 100644
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
index a875bc59804eb..1303a2607f1f8 100644
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
index d81d107f64f41..ee14c46cac897 100644
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
index 91714acea0d61..2f5e96ac4d008 100644
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
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230124193004.206841-17-ebiggers%40kernel.org.
