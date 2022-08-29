Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBPLWKMAMGQE73RKEMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A12A35A4C37
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 14:48:06 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id j12-20020a056512344c00b00494698fa6f1sf1200563lfr.5
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 05:48:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661777286; cv=pass;
        d=google.com; s=arc-20160816;
        b=LtybCTgHdYM0Fu+F+91McqpnABqK+tJrq7Em/6+RVOJMubuVA6b+4DuZl+1NQm0cb5
         hz3rCQ7VpcGcqMfumhjrgxCse1O9CzFmWFL5x5UodqxcQWftIz3YWvpVICl0/Wve/J58
         mI2kqNUJXTG/YNNbbrBb2cN9m4xJ3HvRPe/+kc/bOalZpS+GSIlxYy5AwfNtj7ttfOE/
         xb/RSXHDIF4eRzNpOfxIpmTJuxO478D/B5UaNw91FztE4Ml5pzKPn76bdd8Oqy40bJI0
         yCnDphdOlkO7r6q64o5Lr6pF+bk2l35sH5c1Z98/lOv3R6vZIck89Q2WVxgaGOqBMtbE
         L+GQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=vAr1BeqXbg0vm5AeXzKIdwWQCnTX2LlWiLWxy1UUkwg=;
        b=eU5B8Jm2oExIWsB9JqSl7djQVI9vPI4hgVhBmbGvwBrubxHnBFg5o39soeD0bT00mR
         VOauRnaaxjZH3DPNKK/ieCeN2tLELdeDj6czP+GZJjLC5mxoI/I5PVaEPllulEsCGEz6
         eh0K1iuEiYvtyuBeQaeYUNS36mSIB9BuMm9wC/DnlTh3zRcci9GZg66qLZu4e2BFL+rA
         b9OFqC5itju4jxciqasCMSK0OUOZndGrc6Z0L4ssHxmM4AAxParwMPC8dyc92LcAcZf7
         OMLFwQfNqz5G4eJx+rz1yvRf2ltBoJRL5qaD1xP478+9RYsnsHTgtql5NhBCDbIjxko0
         qSmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LRs6v78+;
       spf=pass (google.com: domain of 3hlumywukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3hLUMYwUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=vAr1BeqXbg0vm5AeXzKIdwWQCnTX2LlWiLWxy1UUkwg=;
        b=CRf03dLncRktZ2PWErZasgnoM/6VPb2NhMll0lTylcG+WlS+oV56nAWuGcFa9YUXqM
         8BNl7o8/pLlU7KxSwxnOWCDoSOs3btz+FdgIoa5b6S11k44gJzmIzq0dWI3GAEpl55br
         QsYFeOU22rnk3rGR8PVp8OmriOOcuLNjJ72cq1l9w+tdOeW0uCbMSIRS+s6rxNV6KqNJ
         wkxnbDN96wlCBaawUclqnF00pY9WU9BEr4s1ECdxGQh32Xq2OoznWUt8RFWa79Hadg/M
         9Qq/uqjmQKWcNDuWCt3yjOYnaG2BK+OVXqq3aqmq6kwZnAiPLku+AzmMIOYSq3z6J8Y6
         VE5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=vAr1BeqXbg0vm5AeXzKIdwWQCnTX2LlWiLWxy1UUkwg=;
        b=4H00wy7pg9VSJzxoapYsahztDD+2RCQNNp0uKc2EQsNwJN5YDIgEj0CeTsDj51065q
         NYNbdsCq5WFUxJiTmh/hlcPSf9Eu8qtApX0uFZ6WZurOvVzHLYaJaZpXkPSd5E03jM6L
         CCDq0sUk6Z9L9qqNQy36ip0nNyIcUneGYOvqY1cBcPW14enqYaslg8dNvGJnDApBhDGb
         ZlucNj1ylT2+K07rf3/MsD2shIlyDO39h+dT3ukqmTKs/iaJYMu+eRCb2UrL7L/3xwA1
         waPMiYfkR2on6G8DfABEn+HJmRo4OguF2TdeioMyeXVlZ8i4raKcMtqcdsSA1Rkf+h+3
         /2aA==
X-Gm-Message-State: ACgBeo3Oc6jFClMW62VshNutC38TAOvQBz8mzIvwwwaoxbo3cupuTolz
	mcWy6lydao3AVLtDNSgItCc=
X-Google-Smtp-Source: AA6agR46h4FY8jUi0Y0Oze8LFJImcFgbX/8u2tUj0kvf2bbDtvRWK7OTRjnoLvPnjyJKwgktLZXimg==
X-Received: by 2002:a05:6512:1cd:b0:493:1e2:9e53 with SMTP id f13-20020a05651201cd00b0049301e29e53mr6595452lfp.72.1661777285994;
        Mon, 29 Aug 2022 05:48:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:20c4:b0:494:6c7d:cf65 with SMTP id
 u4-20020a05651220c400b004946c7dcf65ls1400127lfr.2.-pod-prod-gmail; Mon, 29
 Aug 2022 05:48:04 -0700 (PDT)
X-Received: by 2002:a05:6512:390f:b0:494:6c9a:bde0 with SMTP id a15-20020a056512390f00b004946c9abde0mr1303993lfu.344.1661777284560;
        Mon, 29 Aug 2022 05:48:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661777284; cv=none;
        d=google.com; s=arc-20160816;
        b=sh72lfdoCDsIvN+6f/J2BmNTwTtNiLNllv1nrtNx9ypTSHLWa/DkQg6jrl85DCucrP
         8VVvqSqEUNowZjrAQCUUgtXPv+b+ece01Xbi/E53HR0n9nkkBiIO02VZFsjQO68Uk3YV
         IDzd9Vfdg2UT/a0IVYgEGU+uRQRHKk5Bp6xAsX2JUfHIRtknHuw7e0E7HAPKhm9FMA1q
         2ndco6ol6jD3eGwI132j2i3U0rKGSxhniL3BBpkUd+E6PYC/fla96hCMh6ZPHLgth3WA
         Cw2kaKmRNaLpNf23v+fBpC2VJphKOsEXuDvT6bWDi4lFQDmLNCR8D33pvWIq87dD+faa
         FvbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=1tERDk4Y7XiUFi7foUICKHh8rrNwWwU5I8SMJsHxX4c=;
        b=prSWQXZsI2Hf5P1pyT+QlK7D1mTqn9WF+cXPoVSqVJHsqWq2iVdtdqGF7PbNgAHyCC
         Nz/ABXPYrjTKQwNT7J4XWNI01nYbMeUBV5SWFcIEElZBq3sH/G+2eMAzBIHx3RKEmSrg
         HSa6oFzli0Xh3Q85gfNBvnwMeKEwJEzei51ugAn+YwtGZfbn2GUSeldIQsvICclhIu3E
         Ic+BJcgMN5dZzgU6PIFq3d1o4ZhWpIC1EpQamh+VaiKM4xEdDZNizA6xdmrods6qhbAY
         +BwEhKVWPOZ+vlF7XAbvTDSj9E0VtRqkmhchkKiF6il3+hmbBYu+ceHywO3TwmON/0oL
         ogzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LRs6v78+;
       spf=pass (google.com: domain of 3hlumywukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3hLUMYwUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id bd15-20020a05651c168f00b002663282f080si78838ljb.5.2022.08.29.05.48.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 05:48:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hlumywukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id nb19-20020a1709071c9300b0074151953770so1223281ejc.21
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 05:48:04 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:196d:4fc7:fa9c:62e3])
 (user=elver job=sendgmr) by 2002:a05:6402:2707:b0:448:ad8e:39c1 with SMTP id
 y7-20020a056402270700b00448ad8e39c1mr265466edd.315.1661777284113; Mon, 29 Aug
 2022 05:48:04 -0700 (PDT)
Date: Mon, 29 Aug 2022 14:47:07 +0200
In-Reply-To: <20220829124719.675715-1-elver@google.com>
Mime-Version: 1.0
References: <20220829124719.675715-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220829124719.675715-3-elver@google.com>
Subject: [PATCH v4 02/14] perf/hw_breakpoint: Provide hw_breakpoint_is_used()
 and use in test
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Ian Rogers <irogers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LRs6v78+;       spf=pass
 (google.com: domain of 3hlumywukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3hLUMYwUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Provide hw_breakpoint_is_used() to check if breakpoints are in use on
the system.

Use it in the KUnit test to verify the global state before and after a
test case.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Ian Rogers <irogers@google.com>
---
v3:
* New patch.
---
 include/linux/hw_breakpoint.h      |  3 +++
 kernel/events/hw_breakpoint.c      | 29 +++++++++++++++++++++++++++++
 kernel/events/hw_breakpoint_test.c | 12 +++++++++++-
 3 files changed, 43 insertions(+), 1 deletion(-)

diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
index 78dd7035d1e5..a3fb846705eb 100644
--- a/include/linux/hw_breakpoint.h
+++ b/include/linux/hw_breakpoint.h
@@ -74,6 +74,7 @@ register_wide_hw_breakpoint(struct perf_event_attr *attr,
 extern int register_perf_hw_breakpoint(struct perf_event *bp);
 extern void unregister_hw_breakpoint(struct perf_event *bp);
 extern void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events);
+extern bool hw_breakpoint_is_used(void);
 
 extern int dbg_reserve_bp_slot(struct perf_event *bp);
 extern int dbg_release_bp_slot(struct perf_event *bp);
@@ -121,6 +122,8 @@ register_perf_hw_breakpoint(struct perf_event *bp)	{ return -ENOSYS; }
 static inline void unregister_hw_breakpoint(struct perf_event *bp)	{ }
 static inline void
 unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)	{ }
+static inline bool hw_breakpoint_is_used(void)		{ return false; }
+
 static inline int
 reserve_bp_slot(struct perf_event *bp)			{return -ENOSYS; }
 static inline void release_bp_slot(struct perf_event *bp) 		{ }
diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index f32320ac02fd..fd5cd1f9e7fc 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -604,6 +604,35 @@ void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)
 }
 EXPORT_SYMBOL_GPL(unregister_wide_hw_breakpoint);
 
+/**
+ * hw_breakpoint_is_used - check if breakpoints are currently used
+ *
+ * Returns: true if breakpoints are used, false otherwise.
+ */
+bool hw_breakpoint_is_used(void)
+{
+	int cpu;
+
+	if (!constraints_initialized)
+		return false;
+
+	for_each_possible_cpu(cpu) {
+		for (int type = 0; type < TYPE_MAX; ++type) {
+			struct bp_cpuinfo *info = get_bp_info(cpu, type);
+
+			if (info->cpu_pinned)
+				return true;
+
+			for (int slot = 0; slot < nr_slots[type]; ++slot) {
+				if (info->tsk_pinned[slot])
+					return true;
+			}
+		}
+	}
+
+	return false;
+}
+
 static struct notifier_block hw_breakpoint_exceptions_nb = {
 	.notifier_call = hw_breakpoint_exceptions_notify,
 	/* we need to be notified first */
diff --git a/kernel/events/hw_breakpoint_test.c b/kernel/events/hw_breakpoint_test.c
index 433c5c45e2a5..5ced822df788 100644
--- a/kernel/events/hw_breakpoint_test.c
+++ b/kernel/events/hw_breakpoint_test.c
@@ -294,7 +294,14 @@ static struct kunit_case hw_breakpoint_test_cases[] = {
 static int test_init(struct kunit *test)
 {
 	/* Most test cases want 2 distinct CPUs. */
-	return num_online_cpus() < 2 ? -EINVAL : 0;
+	if (num_online_cpus() < 2)
+		return -EINVAL;
+
+	/* Want the system to not use breakpoints elsewhere. */
+	if (hw_breakpoint_is_used())
+		return -EBUSY;
+
+	return 0;
 }
 
 static void test_exit(struct kunit *test)
@@ -308,6 +315,9 @@ static void test_exit(struct kunit *test)
 		kthread_stop(__other_task);
 		__other_task = NULL;
 	}
+
+	/* Verify that internal state agrees that no breakpoints are in use. */
+	KUNIT_EXPECT_FALSE(test, hw_breakpoint_is_used());
 }
 
 static struct kunit_suite hw_breakpoint_test_suite = {
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220829124719.675715-3-elver%40google.com.
