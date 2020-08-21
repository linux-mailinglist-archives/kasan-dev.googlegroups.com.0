Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI75734QKGQE2CTMJAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 60A9D24D506
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Aug 2020 14:31:32 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id q15sf651261ljp.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Aug 2020 05:31:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598013092; cv=pass;
        d=google.com; s=arc-20160816;
        b=HxUxqUaGGFrBHTrrNKd57qX+bX0aDArTgDmaYHEVLsIS18CGzwbWL4QkhiNs7onj4k
         KT4QhGjuMbsZf8ttbt4oqvOAH4YTrf6NkozqFAuOaeoGLCMdph0yTfILAqDb6iwJ41sa
         7R0qwko6jk3aVjryLcx9XzlnZE2rFzfbZlr1z5t04Asja3wo3b4BpCZGlLIcQ1CbVV9B
         BagYUV6UnUZ0s8k7EidS1fYywnG4hN4Ks7APqXrzA0hi0hu/YNzSMapdPWAsR5egoEFR
         nDmPXhBATsCscYD1l1lEmMNU6yYFqstq7HpcYQtKOXP4QvC3PaR+mEwUhV8byxVm4zMP
         nAyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=ws/RnhwCkVHhcFbbVFXf4vH3I3DR+jAw3AnmiUNs6ak=;
        b=M8eDHKwS8HWOCCbGL08aPyT+7Kzul1rdpvCc9vD1uc2dDjbOzh3inLAgi5iTPmG0pj
         WS+tOyxAK7yoz0F8vD+QOqUITJhzdb2VStMdyu+8WR8diyw4EvlQDEeDKG/x1YvUcwx0
         anEdHmI8zoODtS7KCiUc5OoKmkSeww7NxVGFhmdPR1/bgQpp+Y1JCB8fcAoVWm17+BpV
         QLt3oUH0kOxS3yID2v1QJPY3vsYeptFw1ppaVBiS4fhRW4tbIxHlxAp3tmGsHOVIpUgy
         /r8hsON8SdL7BtntpiNfW7OygNATCPyuoFO1jPe+NV8cqIIqm+7RpaiTsJrcfH5Ne2np
         7ulA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NrSy4jUp;
       spf=pass (google.com: domain of 3or4_xwukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3or4_XwUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ws/RnhwCkVHhcFbbVFXf4vH3I3DR+jAw3AnmiUNs6ak=;
        b=Wo+7blbrKYIoTxAy/3mm1HyvM38LmCee90S8hg6JC925OEoWD4OqTSomYcqGbO9D/x
         TjwwmPy31kG0WgoQzou6sP0BJmyQ0ysV5CM9xJOLQFM7XpTeBqs10VqZDL/BkfuaOnWm
         16zWV51nS3KVKFmMiHq5Wlj76MLqIgDw3PqQvhQdj7wYN1Y9Yy4dkAfO6yVbJ343zxPX
         WGXSccVskcSIXa+E/vgtJCH9VZ9+7F6duQ/YyzVk8wstaAhix3sfXjDyUC6Aiak3h+jJ
         0agr2jHm4FTszXw3Dtie94Vu8sniDYt5bsi1NxivQluR7Kak5bKC3QTfPPk2j383EeeT
         uFAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ws/RnhwCkVHhcFbbVFXf4vH3I3DR+jAw3AnmiUNs6ak=;
        b=hDAB9Uc2vldk/pF/rzIMDrRocunnd9jJi3oTn3JXBJKguVWd3hQ+A/qS2GvnTtQbIA
         G5tbs+I0AkqW/6mgUWmu3N8cOZAZSQvMXw7IA7eacuIraEF3ySwMR8MAm60AW4tZuGAv
         syDYJ2r/Bf53jDHjVHNuQUqgm4e7sWvyLmBREGlLdEnMJw8vEGhQRd+ddXbBVb43/drO
         TiE31kue51sCvdV2w6ZNKGz5bUrYKhZtfxiHiDUjonYD9qFMrqmiE4ww8xhpqCfByR4P
         5fv87gIrTz4urzsXOerTxLtJYKC/CQrCaL3AzIdmtkq/sw2hyzActMiyhiz2HRdqXWwY
         dc/Q==
X-Gm-Message-State: AOAM5335nQW7kQ4v5uS1wZgL4uyAd2kucXRaf++wr+tEiJThvHk+2Qc4
	6XDBtjQGtkacNhR5tlnzEQw=
X-Google-Smtp-Source: ABdhPJxB5LOjo83AzF/HcYw01wpnhomqSVarPGf2iot9SgdIWY8qq73MLQm2qbe+FKJlvQiTG4R+xA==
X-Received: by 2002:a2e:7c05:: with SMTP id x5mr1324330ljc.451.1598013091819;
        Fri, 21 Aug 2020 05:31:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2c01:: with SMTP id s1ls376565ljs.10.gmail; Fri, 21 Aug
 2020 05:31:30 -0700 (PDT)
X-Received: by 2002:a2e:7215:: with SMTP id n21mr1527096ljc.242.1598013090774;
        Fri, 21 Aug 2020 05:31:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598013090; cv=none;
        d=google.com; s=arc-20160816;
        b=RR2K1+JaSwHjf3pHu7lZy67gGwCb+NV02ZPt++mCyUKcPJ7ByCRGk70t4zG0n6n17M
         RK75yBzr7FuerdbXq8wmeDGlC3ntXNxLzGG53fTtI9FaVr9ptzlhc4U1WDN9kYrHK9hR
         yGe6Rosd3Q/EHjBdScYND5RyWpmE4u7DW7dqnmnnZl4YP6Q9yMJ8FWRRZRYOB9s1MoR4
         xI97WFSaq6lHSjX9M9ECwfy3JeDjHacb3tUH+34KqUm+3Ss2jQBqA9PNNfa0nX/buinN
         03CywpYif2gwnKB/qnNUFAlRnRuOrai+U6NuOXbX4Tva7OPBjn4So+blajXXdTQMMKld
         GcrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=EoagnfooXXSHbL+CSOarlDeWOkZ9GCDzxKOSIZ6/Baw=;
        b=MStKqye/CqWlftmE/KQKqDaw+iuuGbEKyaLul6qBwEHduE3oyqAyJYC2aDgpOKsaSD
         o1aU3ytkTdsPtWXDAHI8rqyYxkpQuoABxuVIU7SlVM3BXlICi9cBvIwLk3ztaaoMzBc8
         q0CGVFUuDSkv5rcRnHS4aToz5FlrqDgQuvXTF433e8chh0mJD+b3BxyCJirBsyO6TRyJ
         PzMEk+r/D5W0SktMukhR5Gc60Uqw322RZ25LelHUHLWCig6vAcTiiHBGAiTPL4nVIja3
         PSt8atSNdi6YcvUuNS6qcsSKhTBvATxQ6ASHiZ9AgupdnsUoZR8swsR7pJvexBVzMhLI
         Y+Cw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NrSy4jUp;
       spf=pass (google.com: domain of 3or4_xwukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3or4_XwUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id c27si95641ljn.3.2020.08.21.05.31.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Aug 2020 05:31:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3or4_xwukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id u144so764721wmu.3
        for <kasan-dev@googlegroups.com>; Fri, 21 Aug 2020 05:31:30 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:4c:: with SMTP id 73mr3543536wma.58.1598013090088;
 Fri, 21 Aug 2020 05:31:30 -0700 (PDT)
Date: Fri, 21 Aug 2020 14:31:26 +0200
Message-Id: <20200821123126.3121494-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.297.g1956fa8f8d-goog
Subject: [PATCH] kcsan: Use tracing-safe version of prandom
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: peterz@infradead.org, mark.rutland@arm.com, dvyukov@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NrSy4jUp;       spf=pass
 (google.com: domain of 3or4_xwukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3or4_XwUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
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

In the core runtime, we must minimize any calls to external library
functions to avoid any kind of recursion. This can happen even though
instrumentation is disabled for called functions, but tracing is
enabled.

Most recently, prandom_u32() added a tracepoint, which can cause
problems for KCSAN even if the rcuidle variant is used. For example:
	kcsan -> prandom_u32() -> trace_prandom_u32_rcuidle ->
	srcu_read_lock_notrace -> __srcu_read_lock -> kcsan ...

While we could disable KCSAN in kcsan_setup_watchpoint(), this does not
solve other unexpected behaviour we may get due recursing into functions
that may not be tolerant to such recursion:
	__srcu_read_lock -> kcsan -> ... -> __srcu_read_lock

Therefore, switch to using prandom_u32_state(), which is uninstrumented,
and does not have a tracepoint.

Link: https://lkml.kernel.org/r/20200821063043.1949509-1-elver@google.com
Link: https://lkml.kernel.org/r/20200820172046.GA177701@elver.google.com
Signed-off-by: Marco Elver <elver@google.com>
---
Applies to latest -rcu/dev only.

Let's wait a bit to see what happens with
  https://lkml.kernel.org/r/20200821063043.1949509-1-elver@google.com,
just in case there's a better solution that might make this patch redundant.
---
 kernel/kcsan/core.c | 35 +++++++++++++++++++++++++++++------
 1 file changed, 29 insertions(+), 6 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 8a1ff605ff2d..3994a217bde7 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -100,6 +100,9 @@ static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS-1];
  */
 static DEFINE_PER_CPU(long, kcsan_skip);
 
+/* For kcsan_prandom_u32_max(). */
+static DEFINE_PER_CPU(struct rnd_state, kcsan_rand_state);
+
 static __always_inline atomic_long_t *find_watchpoint(unsigned long addr,
 						      size_t size,
 						      bool expect_write,
@@ -271,11 +274,28 @@ should_watch(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *
 	return true;
 }
 
+/*
+ * Returns a pseudo-random number in interval [0, ep_ro). See prandom_u32_max()
+ * for more details.
+ *
+ * The open-coded version here is using only safe primitives for all contexts
+ * where we can have KCSAN instrumentation. In particular, we cannot use
+ * prandom_u32() directly, as its tracepoint could cause recursion.
+ */
+static u32 kcsan_prandom_u32_max(u32 ep_ro)
+{
+	struct rnd_state *state = &get_cpu_var(kcsan_rand_state);
+	const u32 res = prandom_u32_state(state);
+
+	put_cpu_var(kcsan_rand_state);
+	return (u32)(((u64) res * ep_ro) >> 32);
+}
+
 static inline void reset_kcsan_skip(void)
 {
 	long skip_count = kcsan_skip_watch -
 			  (IS_ENABLED(CONFIG_KCSAN_SKIP_WATCH_RANDOMIZE) ?
-				   prandom_u32_max(kcsan_skip_watch) :
+				   kcsan_prandom_u32_max(kcsan_skip_watch) :
 				   0);
 	this_cpu_write(kcsan_skip, skip_count);
 }
@@ -285,16 +305,18 @@ static __always_inline bool kcsan_is_enabled(void)
 	return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
 }
 
-static inline unsigned int get_delay(int type)
+/* Introduce delay depending on context and configuration. */
+static void delay_access(int type)
 {
 	unsigned int delay = in_task() ? kcsan_udelay_task : kcsan_udelay_interrupt;
 	/* For certain access types, skew the random delay to be longer. */
 	unsigned int skew_delay_order =
 		(type & (KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_ASSERT)) ? 1 : 0;
 
-	return delay - (IS_ENABLED(CONFIG_KCSAN_DELAY_RANDOMIZE) ?
-				prandom_u32_max(delay >> skew_delay_order) :
-				0);
+	delay -= IS_ENABLED(CONFIG_KCSAN_DELAY_RANDOMIZE) ?
+			       kcsan_prandom_u32_max(delay >> skew_delay_order) :
+			       0;
+	udelay(delay);
 }
 
 void kcsan_save_irqtrace(struct task_struct *task)
@@ -476,7 +498,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 * Delay this thread, to increase probability of observing a racy
 	 * conflicting access.
 	 */
-	udelay(get_delay(type));
+	delay_access(type);
 
 	/*
 	 * Re-read value, and check if it is as expected; if not, we infer a
@@ -620,6 +642,7 @@ void __init kcsan_init(void)
 	BUG_ON(!in_task());
 
 	kcsan_debugfs_init();
+	prandom_seed_full_state(&kcsan_rand_state);
 
 	/*
 	 * We are in the init task, and no other tasks should be running;
-- 
2.28.0.297.g1956fa8f8d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200821123126.3121494-1-elver%40google.com.
