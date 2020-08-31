Return-Path: <kasan-dev+bncBAABBYP5WT5AKGQEET3LPCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 388052580AD
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:11 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id j11sf3839670plj.6
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897890; cv=pass;
        d=google.com; s=arc-20160816;
        b=aUjoV0JTCEj299pYBE3x7cXAZQINskzdf0DLxuyf7zYc/nUgXnHxi+SOaIdz4Kc+OD
         Bx3yPrkCyK6akckH5bKl7mJ7Q7kkP7dyVgKtX3/w8uGsWrWjTn0fn80vpEms6GsSYHsg
         Q1xrskv+pQG5OoNE17jO8EcnpR3UpUyX+ohkki+NEXIzi7bB9WSkLfmf8oxw71uH8mgF
         +swoWZx/RyAyXrJsGGDRUT4drIr2STirp8NssdTFGFjbf0+hbqmgv4WJdvO7QY/jvNf7
         dIxHz4z+qgyCvw4VPSNjn9whnHsDKNDR39jeolJAnd8BYjGrl02hdSPFQ/SvIIR3j+MT
         8ukA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=0TV8DCLHJo21/1/lKSR7deujVCYK13TOD2wgPAqOM4Y=;
        b=vac9ZsfLm3UiNvEtJubss1Vl+utPPzbpSzekrzU/Jdd/nRD2w4YCXLrhiKIta5qo8Z
         CaQpTIeSnKXYB22+kUp6xuBlqGZ2fH6kgccBWsxn/d0vQeqR+8EACEz+OP1hAVvfYkJh
         /cbGVWK1BU9VpvBgxtWB4Wm7JG2SimP+FBoYj4HoMUU7rWxJpyAxtrizsBhTtPiFSyuW
         1Clv0cCG8rtzOvlBjU4dbGkYkgwfBJWM9r9WNnlcfsK3d0I/psyxa5DSmAsPS38W9Y6a
         8U18Kj8QFDs2g74VJ35tplu9L/eNILHXgp6u4rtfoWZd0/vxPA/KjFfW0ApkuSjpIaLl
         NVSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DOo6nvQC;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0TV8DCLHJo21/1/lKSR7deujVCYK13TOD2wgPAqOM4Y=;
        b=Dgj2iJzPmcifnQkAXeSSHHbxk5cWTH1UIcACnfAjfn+XYSuvHhaPX6EQNP++f6Qanm
         6keAF4bnWK5SCu2AognyGnOBae+xNEuU/nPee73aLTbEJC8Z8v1Jbp+Gmb6YOfWG4nxw
         zGm+nB4GyKCv2z5ciZgg89/5Bzhsw2Uawsu/VBmpeA9u2akV3RF56XdHIdjkD1/h7YIR
         HxbiM7ju2djBLV9MGkP3TZOurdyGrcUezSAgOieCyTFgig2aa82eFN9+TkqQW87v3g4A
         YTL/M1v0L2cTJAi/nvbwPjJLzEZG/Yl0jVBMMoIVZEX5lpukPhn3qMZ8LlA645AgDJCD
         mg8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0TV8DCLHJo21/1/lKSR7deujVCYK13TOD2wgPAqOM4Y=;
        b=YsXlgGVkCevNY8AWt6XokPXjilBGRqkqRxnQLG73Dp9SpLHF+KW+tHXPCZort6/PqD
         BKxRcOT6OPUshwQlKFHkvtdMrcK8IxSKc8dVQMAK4rE991A1iQkfF43ru1/MvrzRggEM
         J2x1vShmxFzSdSTgS3J5ukMdsbDQE6YQxtBeeBMwjFL64TD05yHYK8Qw4yR26LM8FqyJ
         DUi18jaVp3CbrwLJ+uPA3GjkwxDThDXum8/FBJo+NU3567dCZdNxALyC2eFxkJCUSY33
         CWsYFzHIYlAnuoapRJ42T6QGMI1xxZ+tfdGScS92IUbvOnFZPFyy6MUq+YMNV2CSC4hb
         K80w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530s5TmlO2vMlQQCrWEKRKbeLTFXDGRomjPtmgIuosylR0OXguU0
	6eAWts8jh3pv+P4LxBFcWKg=
X-Google-Smtp-Source: ABdhPJyVirm3yplDrbX32Mkf4m8tEF4dLtCPAdtXDnkt6Vbjc7fcG63OalE6TMioCAt72Ml9UdQedQ==
X-Received: by 2002:a63:2043:: with SMTP id r3mr2201993pgm.289.1598897889930;
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:720b:: with SMTP id ba11ls3867032plb.0.gmail; Mon,
 31 Aug 2020 11:18:09 -0700 (PDT)
X-Received: by 2002:a17:90a:e98d:: with SMTP id v13mr17897pjy.79.1598897889560;
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897889; cv=none;
        d=google.com; s=arc-20160816;
        b=GoWdsNXBUWTF3lCSCR/g226GywrAvASXL/UQ+a1CyWZMcA2XUcE/LC8+WhQKuAbRBW
         tttq96vo8izd/J20zD2WfdPonRmJSUvIM3bsa7GWjKxLtizMqAsAPkKGODEBK7qQ9hsV
         ivu0Zln+pVJu/Wti3R6e1aVL5k1xD3JfX/I2FKCJ/+hQ3N7pOfCQSRYfnXgmmDnx551w
         90qhwC8qDeTLC8g7UGEmeu3f02uSMwIPYXapHz3M45JLa6QOClqXdupZwg64T733qj69
         /kksTK+ES2pGyEkKpbEzPl3+fMfmWRCzogTJA6M6MDa8owJSi0i40S3Xli34xk2ND4Kc
         H0LA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=YFNF3lkjA3fQRzirSqia6QTp7XDho3OuwuM+PBsnl3k=;
        b=lzwTotPwVCDoRDrKOJiL22qDg7+jzGqSdd7zNnC+JAiHTA50hQPQn+VLLRABU+Fxjz
         /80eJOWXqXWRkGc0hVmd/c4kLYvDI/Q6vY7RWMNjgB5s8hyRKWoaJiL3r/RZHv2W+ztw
         /q9aKahGGALa42/M7y++n2kU9SHYLKRPAN8wtfOTevCU1R/CmGHbAqS7Q9jvoZ92Wv3c
         7a4LvC60io2CX/l+XwU+3ZO+y8YGt/yBtNpNyKy1v/5Ttx2BvPeB277h1bTrvwOsiJrh
         Pgt2JgCXxV5FmUru5vClyOGe+C0BsCdkJorHaENS3ZdHGOZRg93/vHNIhpcSr2Hv/Ha/
         uI8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DOo6nvQC;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y204si455143pfc.3.2020.08.31.11.18.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 415312176B;
	Mon, 31 Aug 2020 18:18:09 +0000 (UTC)
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
Subject: [PATCH kcsan 19/19] kcsan: Use tracing-safe version of prandom
Date: Mon, 31 Aug 2020 11:18:05 -0700
Message-Id: <20200831181805.1833-19-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=DOo6nvQC;       spf=pass
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
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 35 +++++++++++++++++++++++++++++------
 1 file changed, 29 insertions(+), 6 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 8a1ff605..3994a21 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-19-paulmck%40kernel.org.
