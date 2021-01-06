Return-Path: <kasan-dev+bncBCJZRXGY5YJBBAPJ277QKGQEZ3PAG3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id D47402EC249
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jan 2021 18:33:54 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id o19sf2247378pjr.8
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jan 2021 09:33:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609954433; cv=pass;
        d=google.com; s=arc-20160816;
        b=L+Smxd90ZNIwixysyT5OOMcUZ5VzklcsoU26UzC9JRJCzHc9/Fm3TIjHOumkJ0gO7Q
         CN5OAD1kMI16HMfnXNzkL8VswUacx5K5C9CiHg4CDOAY8ofNs4MY3eKjRhTNEva13Uei
         oykvzMIlH02nwHco6gqEddVn8IIXtBzK+QkX8mZpQhjRQEgWLC88DwWZYxSb8ibs3L0+
         8GQofIjS8gKVqN+muMNntDoxTXZ0PE6INaElqs8BBVkeg9X++dvwgObE5x32A8tjRL5b
         6F4Pndt+0ztrOHp3x5VSSjscoolJTIaR7OuhSB2QebPxnM+QKfQ2UqWgSSyG93eXgGid
         xXPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=1YZLFcQNqxAPZ6HbIOxX2Ce0cmU0KBOycYaBWV1+8Ks=;
        b=Yqe/82LpRF6BsRdJMhs4Zvyb1mLiOaCjoIdPOyBECkggRh2K8WnID71TuBhQqj2voe
         QOO8YLudkYFhmhFkgc/dJUy0OzwQ6cCAGKXkkFuOTWsedoq16FzATbbaFeqiC5T2/+wh
         tuX6Es9X/4Cl1ovQ/FM2v5L7O1eyoIpS203pbJRCVc5Aii1Q/7JWQfF9N7jXnWxIJMh4
         6XKNNr0+V+HtFalZ12xdpXb5MuiU5A31nfMgiE8pHtLLFt+QrQHiipwNmgiFn1POrlgl
         65S7VIWJW63H/ND+4VudLjtGHMoTKpU3uEeTt2a0zDEds1hGoYDP4xfcc+PEdgjPjxdD
         8mYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SHgAliZ2;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1YZLFcQNqxAPZ6HbIOxX2Ce0cmU0KBOycYaBWV1+8Ks=;
        b=b75osqstAEK2KAqzTdQTSAR1g92tyyoZ21aUCFkO63yrwfK9J+po6FIUMgbI5bC6LA
         9v2tfdwWQrt8kfv+tGB19M3xlYegqHRhE3nke/WD34/QXYPBZU3BumGbSmYodIiXNCNZ
         xmuvtcXBaawWwSsuh/sE0kHpIBlh4mpPhinlT0N1awJCnHSQzetCB6MpfSB+hBagnFJH
         jMJXpAcTBc7z9ZDIycUMTJ8tA+selkBanDruDS5yjqkbRPprOvOSbLVBh2lH0IdZO4/E
         rsAURPjDNvNkG7wo24hc7oXlbcM2lcYVyMHuS1cWJSMpwkxmAiqjUn/1/P3kiK1pTAWL
         nynw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1YZLFcQNqxAPZ6HbIOxX2Ce0cmU0KBOycYaBWV1+8Ks=;
        b=kWI9AAtsO7xdvHELOoPytP41wnjBd21CxxzkxKpfzsQvRyZuMq46ZuQtBeTOACFL1J
         4jIQ4ic7ltdNeZY7RZgGdcUN/Myz7OJR2wYKG6PJEC8QcJ3lfrfYxyzxuVOpDGHnQrE1
         M5Bmu7NkezhVsllaYMjUilVNbQdQKjtcEvCZXFKfEr2WWUI/sVnkX4pncIVPoBH8kByv
         /EZIJRXESonOHi3P3X3KrsprN+pQhF7n7DA7nUnKDqh3D7v6XP7jfBxgX4xHxZH34YVU
         IhouaccaWe+daQ6+O8sbq+XW3wkfuVBHTLfHwYnDZ1tCX3+AInQlBdudbGqWDltSt6p2
         Bc4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530mdDIHkXcoPOIfBOpUbpB/Ah1RSOZkfrB+h5WNXZ/Z5fwTgYP3
	fuEH7oN4ucLaNwmkdhFr8UY=
X-Google-Smtp-Source: ABdhPJzrTX0x/WNefN1VJGP61WqSVuFe6kRm5rZ+yBTt/fnLm1Qx7DP5dRhGgu1HQN0uAz7RK14tpg==
X-Received: by 2002:aa7:9848:0:b029:19d:c24b:1179 with SMTP id n8-20020aa798480000b029019dc24b1179mr5145595pfq.29.1609954433414;
        Wed, 06 Jan 2021 09:33:53 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1e5a:: with SMTP id p26ls1489240pgm.10.gmail; Wed, 06
 Jan 2021 09:33:52 -0800 (PST)
X-Received: by 2002:a63:d601:: with SMTP id q1mr5486389pgg.417.1609954432810;
        Wed, 06 Jan 2021 09:33:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609954432; cv=none;
        d=google.com; s=arc-20160816;
        b=tAHyqCilMH49gXRh301v3X0uOUNs98YEikXpWxaslQ+rYOX052YA7ko0mXB8p5+L5r
         D6BqbhwrPhDckeAg2s/QmlX35d9oF12J3u7FDHWPsCh4GbzqwOOjZneD0NMiQ5VFrbBu
         EnVe3AREvBwFij7+fxGKpDTKsKUr+G57CkBVHHneBvArMqhV/ikSH7wG/LTgv+sjnnnZ
         zsl/JN+dnjK7BoE7yAgIBYMkzl88yJ6LkKMwuMm7vDnn0DbWg3QGb2Km4tKSKHAMUw3m
         mgZL9yHjEXv7NK8b2MQO+kCgAwK3fhMLrl1aE1YqccvjxXacUasT+jJDfFOMmPTkHxyp
         oZew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=V9j8sI5oo5sA9sEkKh5syO+pWXtGkFHSsHrlyMS8mZk=;
        b=pUekmUVWNmkHN5gq2uJ78955X0kUKZErWUasZtnD7ooyPnHh6oyl3z5zpSZZCmMqBK
         TlGwsbhQ9W+NK+tZ34ooanqc327ihZu2aLLunhx79x+P3ixyfZMSOZUUSRQf+LZelEpB
         jQeR8Lv2Lhy6HP2cNTIC9oMTyZGYycuy3IxqGxTI0jLAiVl3Bo+WTuGABFkcwT0tgq7M
         sHFbebMqqmzvGJ9IQonWEwDMieBfslL8HAKBgaeIqUzB+q6ou+53FX7sMwUZ19arD1IX
         nAoKMQ5AEDgy/IDCF6kp4ci0+lWHLk8PsQaQuNq6HPAClDYSr14AxZBKbMv3G9q291Uw
         CKiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SHgAliZ2;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c3si218362pll.0.2021.01.06.09.33.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Jan 2021 09:33:52 -0800 (PST)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 5F34223125;
	Wed,  6 Jan 2021 17:33:52 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH tip/core/rcu 1/2] kcsan: Rewrite kcsan_prandom_u32_max() without prandom_u32_state()
Date: Wed,  6 Jan 2021 09:33:50 -0800
Message-Id: <20210106173351.23377-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20210106173323.GA23292@paulmck-ThinkPad-P72>
References: <20210106173323.GA23292@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SHgAliZ2;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
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

From: Marco Elver <elver@google.com>

Rewrite kcsan_prandom_u32_max() to not depend on code that might be
instrumented, removing any dependency on lib/random32.c. The rewrite
implements a simple linear congruential generator, that is sufficient
for our purposes (for udelay() and skip_watch counter randomness).

The initial motivation for this was to allow enabling KCSAN for
kernel/sched (remove KCSAN_SANITIZE := n from kernel/sched/Makefile),
with CONFIG_DEBUG_PREEMPT=y. Without this change, we could observe
recursion:

	check_access() [via instrumentation]
	  kcsan_setup_watchpoint()
	    reset_kcsan_skip()
	      kcsan_prandom_u32_max()
	        get_cpu_var()
		  preempt_disable()
		    preempt_count_add() [in kernel/sched/core.c]
		      check_access() [via instrumentation]

Note, while this currently does not affect an unmodified kernel, it'd be
good to keep a KCSAN kernel working when KCSAN_SANITIZE := n is removed
from kernel/sched/Makefile to permit testing scheduler code with KCSAN
if desired.

Fixes: cd290ec24633 ("kcsan: Use tracing-safe version of prandom")
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 26 +++++++++++++-------------
 1 file changed, 13 insertions(+), 13 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 3994a21..3bf98db 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -12,7 +12,6 @@
 #include <linux/moduleparam.h>
 #include <linux/percpu.h>
 #include <linux/preempt.h>
-#include <linux/random.h>
 #include <linux/sched.h>
 #include <linux/uaccess.h>
 
@@ -101,7 +100,7 @@ static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS-1];
 static DEFINE_PER_CPU(long, kcsan_skip);
 
 /* For kcsan_prandom_u32_max(). */
-static DEFINE_PER_CPU(struct rnd_state, kcsan_rand_state);
+static DEFINE_PER_CPU(u32, kcsan_rand_state);
 
 static __always_inline atomic_long_t *find_watchpoint(unsigned long addr,
 						      size_t size,
@@ -275,20 +274,17 @@ should_watch(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *
 }
 
 /*
- * Returns a pseudo-random number in interval [0, ep_ro). See prandom_u32_max()
- * for more details.
- *
- * The open-coded version here is using only safe primitives for all contexts
- * where we can have KCSAN instrumentation. In particular, we cannot use
- * prandom_u32() directly, as its tracepoint could cause recursion.
+ * Returns a pseudo-random number in interval [0, ep_ro). Simple linear
+ * congruential generator, using constants from "Numerical Recipes".
  */
 static u32 kcsan_prandom_u32_max(u32 ep_ro)
 {
-	struct rnd_state *state = &get_cpu_var(kcsan_rand_state);
-	const u32 res = prandom_u32_state(state);
+	u32 state = this_cpu_read(kcsan_rand_state);
+
+	state = 1664525 * state + 1013904223;
+	this_cpu_write(kcsan_rand_state, state);
 
-	put_cpu_var(kcsan_rand_state);
-	return (u32)(((u64) res * ep_ro) >> 32);
+	return state % ep_ro;
 }
 
 static inline void reset_kcsan_skip(void)
@@ -639,10 +635,14 @@ static __always_inline void check_access(const volatile void *ptr, size_t size,
 
 void __init kcsan_init(void)
 {
+	int cpu;
+
 	BUG_ON(!in_task());
 
 	kcsan_debugfs_init();
-	prandom_seed_full_state(&kcsan_rand_state);
+
+	for_each_possible_cpu(cpu)
+		per_cpu(kcsan_rand_state, cpu) = (u32)get_cycles();
 
 	/*
 	 * We are in the init task, and no other tasks should be running;
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210106173351.23377-1-paulmck%40kernel.org.
