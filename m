Return-Path: <kasan-dev+bncBDEZDPVRZMARB2MT5WPAMGQE7Q3DKOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1541E687517
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Feb 2023 06:28:11 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id x8-20020a25e008000000b007cb4f1e3e57sf741190ybg.8
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Feb 2023 21:28:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675315689; cv=pass;
        d=google.com; s=arc-20160816;
        b=XtS+arvXPmCSvURRVQJmAmQmkSRCwKajG0lL4xEJq2qFxehxyI8+W6rrc+W3LZLd17
         cyENyTeBRT/5f6yRAYcSTvEXzH4vOeOUJGbPbMlauuz3IqXg301+Aw5vLpoRE3M8k/16
         3vkzAUSw1q9E0SZmE79K3DEvJXdUwnI70dN1/OkiS0x98s/U5NJFLxYZyFFRktAroVNI
         Gn3oBFCsRJOLf2ONwttL9kVHAzMYNmpo632TrnvRO0/QuCAnFh9n0+FnGB9wfX4JwEpE
         AuxeU6RwpUG5k6wl0Fzjuko5z9fTjP+yha457mtSRgmDfArTEajLkHFEk+HBoSWl3/TA
         8WkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PmaHH59ZZRfiNKyyNT4afapydq+me1EpxwwIiNS53w8=;
        b=kXj9Hr7xLnJxDr7juLd6ZF2vBM3NxVwwA/49N7zy6yivKuuSbe48ctWjOmHvtg8BA3
         NodsPGsdAfprcI7btmQgOFY+TemUk3QsXvXe++2F+2BYebOPSuLixMW+Ds6bA6/vzE5i
         p4Q9Hq24SxknxbtgDHZuswcWPIHxTN4Peck8+8a95HW+XpLMvwBpC8Jnlzwpy9UETEE7
         pRinnvWQ3aiaDf5Y1x5I0UGduI02nGQcQnydsb4skpK/avx2/eH9T+JhGykJQ7ODDJnP
         qpREmqB4n0EF6oDj5IkVMdYNN7dDe7DIKTwKnkDdSqy1ihX2RbjJBmqP/IRPU6n+CQg9
         tSlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YmzlX08Q;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PmaHH59ZZRfiNKyyNT4afapydq+me1EpxwwIiNS53w8=;
        b=CWZn/xQ4OUvD01PGUL3EOgyhcnIA7Yc8s7hWprvaM8XSGEafSlXVlkW2raE/DypDp6
         BrqND4DowR8wsR+GspMKMsLorFA4rm4D9L+G6otkZnnF3DeFwZs81oBpzPCf1C2H71iE
         M/GcJDAaxnAdp7fG1VDOxwmxJcxJr5GE6BnmlptLr50VAsKXMDi9lAIVjlwCpn1jRsqY
         D4Yx+M/S8UmAmB33jMme7OcAAOwZGrdmrarlSHKePq6JBB0wOyEVtrQ8KjUl58MI/fO7
         1YgLOdgFpYPuTZ9aWJN4gg7a9Sm6LP1VFfIfYhdYPAet6fLrNK+ZOz704Sb42giX3UvT
         68cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PmaHH59ZZRfiNKyyNT4afapydq+me1EpxwwIiNS53w8=;
        b=L5Z30TgDNE5mylaJt0scBZEBjpQONYVVEO0CAki5DIpZaHEmK43bCi5FaJCYZQCQ8H
         T13mCB2bDvqkk/7Bz9IguYpIIcj0LdRcAPpXcW8/0PHOEN2L9bzWUmmsAEkWHYccEGZu
         RrY8frzX3BCa+3eIV9+t2kjhrEASeCmwHqN2/ZjMGdm1AR2HEWe24yl2imU7Wm7NRLs9
         KYvpgCEkoRD+eJn5cyX7VIcfNkyzU3gpWXLIhRfbmLP3nsjJJooFZCG//r+gxS+ZhtWK
         GgW4qcMc8vI0bQpae1a2dkNb0sREzSCkkVNmiOQ/LBVTQw8VYUNkf8aSxKtKZWJmUrO0
         68Ig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXev8yqWshRlFnBVW2W8zQDJunt7rA34Nak0d47G3qSsb4VouKq
	JCzAkQaGvHEgf3TGFZp3a5s=
X-Google-Smtp-Source: AK7set+XO7PaiLfv/Fu1220vxGkvhp/q+KwncfTR0FlagpbWOWcYy/RJygF6GPudeQ1ZQ/bJRypJ+g==
X-Received: by 2002:a05:6902:1544:b0:802:5b06:4d1d with SMTP id r4-20020a056902154400b008025b064d1dmr523854ybu.527.1675315689646;
        Wed, 01 Feb 2023 21:28:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:c684:0:b0:506:3896:7a33 with SMTP id i126-20020a0dc684000000b0050638967a33ls317306ywd.10.-pod-prod-gmail;
 Wed, 01 Feb 2023 21:28:09 -0800 (PST)
X-Received: by 2002:a0d:d185:0:b0:506:3e9c:50e5 with SMTP id t127-20020a0dd185000000b005063e9c50e5mr3100715ywd.34.1675315689007;
        Wed, 01 Feb 2023 21:28:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675315688; cv=none;
        d=google.com; s=arc-20160816;
        b=tMEJaNtUrVHDna6LU+GlcPKEivwCMMabSxsdnheNBrd4E+rDeGMwB3abcw9nndibEv
         yz77SfhatSL/MQwCUmktwBwVgmsLrEFwn0V2iwKX6b0cEhbE+At84WZcDVbhK9RHmRI2
         qE95Hc60XfUvV2hWc5b541ybjzHIAwkVloFSvMr+E8H0z3kn3R1oNOMa6ZDKGshKPfJq
         jKArRFf0vDIwroypo9pTX9/Luky1s8xaNeFrsQ1xyBlFUzPIYK9cuiwmRNBsKS/68nxd
         NzMYZa2K2AzlBOv/EpAflvDyOR3c8KRI4rs4+GYMIIVwVSxuDaBFsceAO44sy3ySnfD4
         F5Gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Po7xxo2rOMSPri8SKf4EkdJBnmJkIyTqB8yrnEGgdek=;
        b=jDGAKNsWy2Sxy6xZSCVHPJjaWza6bL72W1hSc1NCorzwlHVyUNtC3W97vdM0WmZ3xT
         jrE+GPjczm2cn8HkTHsGaP0RvQz9IVb4ElqwouQzkUg4BFiryxB0zf1i5CdOBirjzBeQ
         7ROlhSsFgFg7wdw5hD4ZNtmc/Yln83MjUT3jmiPAMip59bQFlrNhdeFueLqHPu9FcFAI
         1uJg+PDW71U7XKWlxQ9YMEAQA1nJ4BBGBj8nFBGSurhbjUl6m+RdvwN66RRzcPz/29lK
         ranAoxfvBOxDrwW38y9bXGssSp9C6AvSpCtBxBVLgealovniwWC7zvAsM/pHsEy/Elh4
         kQhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YmzlX08Q;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id dc10-20020a05690c0f0a00b0050646ae9a2fsi3192758ywb.4.2023.02.01.21.28.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 01 Feb 2023 21:28:08 -0800 (PST)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id A06CA615E9;
	Thu,  2 Feb 2023 05:28:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6A12FC43446;
	Thu,  2 Feb 2023 05:28:07 +0000 (UTC)
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
Subject: [PATCH 4.19 12/16] panic: Consolidate open-coded panic_on_warn checks
Date: Wed,  1 Feb 2023 21:26:00 -0800
Message-Id: <20230202052604.179184-13-ebiggers@kernel.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230202052604.179184-1-ebiggers@kernel.org>
References: <20230202052604.179184-1-ebiggers@kernel.org>
MIME-Version: 1.0
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YmzlX08Q;       spf=pass
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
 kernel/panic.c         | 9 +++++++--
 kernel/sched/core.c    | 3 +--
 mm/kasan/report.c      | 4 ++--
 4 files changed, 11 insertions(+), 6 deletions(-)

diff --git a/include/linux/kernel.h b/include/linux/kernel.h
index 50733abbe548e..a28ec4c2f3f5a 100644
--- a/include/linux/kernel.h
+++ b/include/linux/kernel.h
@@ -327,6 +327,7 @@ extern long (*panic_blink)(int state);
 __printf(1, 2)
 void panic(const char *fmt, ...) __noreturn __cold;
 void nmi_panic(struct pt_regs *regs, const char *msg);
+void check_panic_on_warn(const char *origin);
 extern void oops_enter(void);
 extern void oops_exit(void);
 void print_oops_end_marker(void);
diff --git a/kernel/panic.c b/kernel/panic.c
index a078d413042f2..08b8adc55b2bf 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -125,6 +125,12 @@ void nmi_panic(struct pt_regs *regs, const char *msg)
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
@@ -540,8 +546,7 @@ void __warn(const char *file, int line, void *caller, unsigned taint,
 	if (args)
 		vprintk(args->fmt, args->args);
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("kernel");
 
 	print_modules();
 
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index a034642497718..46227cc48124d 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -3316,8 +3316,7 @@ static noinline void __schedule_bug(struct task_struct *prev)
 		print_ip_sym(preempt_disable_ip);
 		pr_cont("\n");
 	}
-	if (panic_on_warn)
-		panic("scheduling while atomic\n");
+	check_panic_on_warn("scheduling while atomic");
 
 	dump_stack();
 	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 90fdb261a5e2d..29fd88ddddaeb 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -176,8 +176,8 @@ static void kasan_end_report(unsigned long *flags)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230202052604.179184-13-ebiggers%40kernel.org.
