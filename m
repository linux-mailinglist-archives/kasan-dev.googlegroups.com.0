Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOWQ6P6QKGQEG7SUBSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id B12F82C2382
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 12:02:18 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id a14sf7150959lfo.5
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 03:02:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606215738; cv=pass;
        d=google.com; s=arc-20160816;
        b=sfDoDhyuDLpki/Sx/b9EOgtu04PWyVtBZxHzc6NavLINBfRMc9T2F8CqVlaOGAQLxS
         wDQma4guHGOVcHgwwvXlWG2wjrU6C9Jwd5xhBLUdNtE0WkQdmuDbHB6DTnlfKuH8Zo53
         N9wSiX7KOZ6ZqXsWQt2EQTeXduejLPb8vqrn1CUZMa4zd1cFRM5HcgWDWhWW9EXqPZV4
         rj/bUhQO8U3swxuowTQE4az26JXYFyao13KGDHILxBnixuFMWHwhPSJgh/Wn3+OOEtR9
         DY+PBR9qbsWjZlHG52V6LjaysBFVjMuZAhxHnjn2jeYZmIXrjq9WysuxScaj6mrfxg/F
         Oi1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=o//y4awf0z/a17qThm/GIWXX6B5l9Ch80rgo6W+r76k=;
        b=ZVAa7bs3FtrmbgXnN2w8jVrjxCen1Dio25WCpg3AgVz+upFt7gHuS9zNCl69pqFxmS
         osCvIOm88y66VlRwl5IaJgMNaZGMux2x2vqslPZ+skmuWuiD9MMVTnEaKsZdSvhU3416
         2EcUswZtdzd6ijyuUXZChxdeb5cOpsSGdJyEH8iOp7keHx1SZPLtGdo7JPq/IvCD/bkz
         hxSKiyoZkElpsgL/4ETgk+xgfB9yR7DPWZjbaVZxk8o5V+2jB0gXAxBcA6D4fuzuA6el
         VSMT1kjWu6gMWgJc5upfTim1xQyoWQxjnoTrUbS479gYCZy5IK38Kd7Bbucob79Xxz65
         dq5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X0Lj0mwa;
       spf=pass (google.com: domain of 3ooi8xwukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3OOi8XwUKCQEfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o//y4awf0z/a17qThm/GIWXX6B5l9Ch80rgo6W+r76k=;
        b=tWLyQ2jblPoxt2dZQL+JwHetT+gy//TN2VcraGZL+cQY1kUJYseS6/3ZLYQ2JkFW4r
         5Ag92dIxwC1c0O/ufIuI6kAE9rzAsb9fPKRnmXp5i2DoxwalFww0hsDAv35/pNXdYZb6
         98Xnp749zclPkg8VHvbBfMxRoXn5tBCKnwCr2Wkt3t2gYSzehv7n2aHVW7gv2/DMgp+W
         Tqz3/cXn7kxL3aMzbLuZoJhPtdxMUQjoBlBf6xnRWSOCCVo/b8Txn5bnsrtPaPp1kSRE
         3fcuMYFh/Ix/TfqfsCiVL3djM8Z7ru6mOmyA1VoW9vFxqFImOJjN57JoLAXY6JW2FYIB
         fXjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=o//y4awf0z/a17qThm/GIWXX6B5l9Ch80rgo6W+r76k=;
        b=rqoY+2PrPyOLWRBXYI3a77m4wd82uDEMVxYiolsqtPOb/ous60toWDeU4mrIUyZrBY
         s1omGxfGz0bLClDk9OVC5M0GzuCJ3zREnzyYnb4bKQRj8ppNy0rl/tLTADlHwhL9oWDu
         mqgn8yke4mY8T8LcLTHbRujcvuMhKxbiSPO35H9bhf0B1ueEsKMGXplM8KEabBjzdlzg
         OpYHl8ZLDS4m/GhekborvBA7JR9CA6VtfGwtcsD8dsGjEeCnBYeNJn2mv7qcPvyAyCsH
         MM/VFH3pARmIjLyQFwd5j1KTDxyJ3+k4Ubz9gmKiMbBgEb6tcnLMngjgcv0IO8tfjp1o
         JG2Q==
X-Gm-Message-State: AOAM532S9svq9sCDJ7LLdtKkeOMJ4Bfd7wO8l0P/0FKrK3peQD+7Lc37
	TvdT+HCjt361eUBMUYKX190=
X-Google-Smtp-Source: ABdhPJz8Swysh/bfI3+miZhSGAmWl9y188LnUtS44OW1P1dwUBk3ZH7z+0BgrcUR6AEPiCfcV3rKyw==
X-Received: by 2002:a19:6005:: with SMTP id u5mr1426876lfb.367.1606215738313;
        Tue, 24 Nov 2020 03:02:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:914c:: with SMTP id q12ls2682300ljg.8.gmail; Tue, 24 Nov
 2020 03:02:17 -0800 (PST)
X-Received: by 2002:a2e:8041:: with SMTP id p1mr1466832ljg.291.1606215737115;
        Tue, 24 Nov 2020 03:02:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606215737; cv=none;
        d=google.com; s=arc-20160816;
        b=eZIs/Urnis5Y7StrxHRBT8lOQ8t9MuSF42PGXhdiizzVJXSKEQCzeINObuDonWBhug
         i7zTyIjXAjBKLO/pONPANjUNmPmpay4lu5VTacCw5QKrR5TpIHMHAwX8L98w39ruCt23
         XFRXeODAJKAtnwTyGteVMP9p+ryIdTMO8F8uLRdn1dbPoqPKkFXD0U3z61P2kFMCVMrA
         fZHARqQ8G8GqS1f1GYXuyb7/FybqhMnv5Iq4fM5TdsP5viZC1i0naIOVq8iOpm3FHuNA
         1lzFI228zGLAUtxVJZp7FXCI7KO1sBb3BjJbIff6zJ8qB3zLpiogfZQt3u2xXCaK5xDh
         rYKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=fdbbxX9duAWgf2y7mstvbp1Lae/Ec3vzbHyR2vvOgmg=;
        b=mlCOh1kHfIT1OwHPUzbA4VV+xouGjbEHgwpn94TD7cGG+QmluPqwztc3kaE71aCSAn
         Uyk6LL1FZeTROLP/yMwPYYfs1cAPF30GYU28/malkGJZnaHnGknOQznKXdu3PVpILklf
         EOw9ERNfnyJ3LTY9ihuYkYp8c5ME8wcTy+3Mi6WVjGps77WC+tdLNOJsTZ/fxWDs/5BV
         hJMXp876VQuwFH1n7Nd/8FtYw6/2OCitRQedTNHDoS8Mw9rtnjypW3EIx9OTH8VGUCCZ
         myfzclzdxsbPRQbTHZPnHG4UsmC3Pt0sc7F87G0VonUexg6YutqoENsH28MpgpxfeQiW
         IBZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X0Lj0mwa;
       spf=pass (google.com: domain of 3ooi8xwukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3OOi8XwUKCQEfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id b27si67905ljf.8.2020.11.24.03.02.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Nov 2020 03:02:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ooi8xwukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id f4so6742312wru.21
        for <kasan-dev@googlegroups.com>; Tue, 24 Nov 2020 03:02:17 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a5d:60cb:: with SMTP id x11mr4977240wrt.0.1606215736589;
 Tue, 24 Nov 2020 03:02:16 -0800 (PST)
Date: Tue, 24 Nov 2020 12:02:09 +0100
Message-Id: <20201124110210.495616-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH v3 1/2] kcsan: Rewrite kcsan_prandom_u32_max() without prandom_u32_state()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, tglx@linutronix.de, 
	mingo@kernel.org, mark.rutland@arm.com, boqun.feng@gmail.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=X0Lj0mwa;       spf=pass
 (google.com: domain of 3ooi8xwukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3OOi8XwUKCQEfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
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
---
v3:
* Rewrite kcsan_prandom_u32_max() without lib/random32.c!

v2: https://lkml.kernel.org/r/20201123132300.1759342-1-elver@google.com
* Update comment to also point out preempt_enable().

v1: https://lkml.kernel.org/r/20201117163641.3389352-1-elver@google.com
---
 kernel/kcsan/core.c | 26 +++++++++++++-------------
 1 file changed, 13 insertions(+), 13 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 3994a217bde7..3bf98db9c702 100644
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201124110210.495616-1-elver%40google.com.
