Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMXA7TEAMGQE5SDHVUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AB42C74CA2
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:13:56 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-477a11d9f89sf5146985e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:13:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651635; cv=pass;
        d=google.com; s=arc-20240605;
        b=MHZcoxsDof6CqljDTpFEUjMCt8qbNR5HyzEDyzwqC4vHReP1bPIaJpDw66CQUDolZU
         67rtaUNKue7G9oCgGiZfy2K8o+rcVoIrQTromXmhomMZSWDxtkKwX7MPXqZ/4kV1lyzR
         uyj+dhPBbJ9BwlaS8lUdMPRUKK88fHaO8glIEixb6RBiwJ8XBw5OOWL0DZQW5FJWwqVM
         1DID/4p2T1NIRWFwgN6mucafIEx5dYhcCaanLlT6VI0A+Qbbi2orw+QrovGfDpcY2gH4
         Av2i6xuiFqLHQdpPQ6q6Ax8CXQ5fxNoq7LR+8dJO+7JOdNUQTLA5zIzBvAWjMGfKflVv
         H0Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=8/lFcdVy8LeYW8ggRVv1EaQ6q+iwb+YYI5ol+xg9PU4=;
        fh=XET6XqFBcVhxPg+Q5H3WSUTaJkbdci2ucsVeQqg2zjg=;
        b=ae93zt24AArzafL+lgkxaV5aQnjMohn0cCXGXOKSeVEt20nepyx96rNELNIafWH2I7
         Zi79dQKo02kWWz4DUtXA10lwTxxXKlu4lpZoVNvsZImmkT/ZZmix5u0t+vm0g0mI6936
         08Hn00uSx97AGHpwtiPeneEVIf1e3h4AXh4tVOOnnj2ZSdy851F4J4bLYrC8zec5vtED
         MZyJ1KE04gmh0p3VzPqGVyzX+gIG4xpRZALfpDjzgEQm/R0slKag9qRoR0S576iDIwBB
         XTvfir1wraL00C85LIxijlz+fZwvQSmpZ6NG1LIJSzfh0BovhLG8GXAk8EdmFkCtWwvD
         Jtfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="xth/xc9/";
       spf=pass (google.com: domain of 3lzafaqukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3LzAfaQUKCVw8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651635; x=1764256435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=8/lFcdVy8LeYW8ggRVv1EaQ6q+iwb+YYI5ol+xg9PU4=;
        b=fUSUf9u+dVz7N4E4NXH2vwJsuIyScMSPqjYHOOUH+cK1FPA6AzMuK0RUJFncmvcZIk
         +U4+mKCe42yN3sUE+5B4FiTGAs/3PxCIofQQ2/magVS+xq3nezHpVdehpJAD7Zg5ZfSB
         3n2HXAuG5o1+GK2B3Jlj7YeABhR3X+mUDdzK3bdV1hfOY0k9+4JzkmcJLz9W+WCjCF9c
         uhRRktaZGxDhu/7gG8RaKJypQW2Wd2iVLRTbA2YBRXqJvPcE39xC4pG3U3Z+ox8PBFoR
         SDjPU56xociRTICruhjfD2Uus1xKF3lWwYJke77t8cOdw0W0LGwYTMhzV/GyKGJiKuzt
         1hDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651635; x=1764256435;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8/lFcdVy8LeYW8ggRVv1EaQ6q+iwb+YYI5ol+xg9PU4=;
        b=k+s/8Eksrn135pJ32sWjxjh2N7M1oZtc7SrRQxMS7fvoetHfi8iJpi1KxEQJd/ovwY
         TAv5Tp8FyxJW8rLhRU2FoXb2+sY7u9kqfLClCRnoSncjQW87IU7LY8CT2V4mknZoKeyk
         UOCrhztnAxJuzfJJsBckiK74G6GFAD9D7EPs01VyqPRSRk9T8J+vhZ2lbsa5uZQvkAFQ
         BG/4dc30mJuHQcQXn53BGfBJnkVqXAcpLBc/Dcw1zvq5qWKhAquxt/56pMrJuKJRlgCx
         7obfH777+J0X/cz2kl3uP6ShLiPtueTqZrxhgl6NiQTQ1XL/oL7CE99Cscnv/qovGMuA
         R5Tw==
X-Forwarded-Encrypted: i=2; AJvYcCUielO4G+gqIcE471t3eFo92xDJplBTNZnutw/Vmrv1I6LDsyXlvtCwNQ4UwD+x552KrpMVkA==@lfdr.de
X-Gm-Message-State: AOJu0Yxa1Ayn2Ovy0N7t8H7vN59ik9jyaYKpcHO6D69YfJZfiSDQ1+sc
	7hhEH2vpt2T9F4ELIi+nQGfnkvMGcSqQotkb3WVxN2sZljS6VOFRHT0R
X-Google-Smtp-Source: AGHT+IHvKwq/6piPLVlMSRwzcpXvN/8r81yuXVWVdZrFvZ76tqgCycuqmceDOC+1YG2id/mbnyD2eQ==
X-Received: by 2002:a05:600c:1e8c:b0:477:df7:b020 with SMTP id 5b1f17b1804b1-477bac0cf94mr24092145e9.18.1763651635161;
        Thu, 20 Nov 2025 07:13:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aENBm+WcC+zCwcptYvDytDj3fGs9T6FjWErPDLbnfbXA=="
Received: by 2002:a05:600c:1c26:b0:477:a036:8e7b with SMTP id
 5b1f17b1804b1-477b8c8d88bls6375605e9.0.-pod-prod-01-eu; Thu, 20 Nov 2025
 07:13:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWhQFnUSNghFtIF09QTM8yapdiIQKUi2wuNpXlHbNgJkTqYNa3rXFJ2QbkR7n5Lfwdcku5oiKFIVWo=@googlegroups.com
X-Received: by 2002:a05:600c:458e:b0:46e:396b:f5ae with SMTP id 5b1f17b1804b1-477bac0cfb5mr29596645e9.16.1763651632291;
        Thu, 20 Nov 2025 07:13:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651632; cv=none;
        d=google.com; s=arc-20240605;
        b=VCNVV0mAfLVzH3XkWAukee8P9X0Tvtgf3yvHBIjNuG8rbxpvVTltKFgcZCNr+p5Ud6
         zn8mnjfPcRhtZ1iySMAkATozMi+BQj0ymT1nNSDNlkCTVVhRTHeROnQ8FxwoyfI8Ah+4
         9aCgzDh1nPegE2wpYtzbl2d4DDYO3hIIr2HJaTYDSTx2fZn8P9VrpVuRLhWh8OVA15Tg
         2D/h4Mh0hcRrCSQRqGOCPnkND7/jCLVimu21yu9uJ1kLDuQAla3D5pnZztybgVavyGxL
         RSqfamYyRJKbRRDe7NQ0+BbSdsyWkZovdCu7LXwJNgETTt1F+R6wC5gkOrThYYTq7MaV
         OAJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=6fdZE8GnxjevnV+ZPYXMwhSIUCp4xQbOOIBc42V/94A=;
        fh=Qxd7Dag3IQHY1IOWEJXFJwi42OSLOw0IHCEDPEjE6Dk=;
        b=j7JdNs93/i1piFhNvf402/RawWAbjG8f9r0uwMnxi9aF5A44tMB8kAStZ571UD0V/X
         K7vEjLObDm29J/98KkW7XgSBBJolap4AHx0rLnLsFXiyjkY4uDZnX/vOUgZs5YDfK+1l
         XXE836svMd/UOesmZm/yeBjZGM4ugYp83nmiHgdVMXG3v2rq8hlITeF5JeJhInHW6l0N
         HPBxVmmDr6Pfz8A++kSSaJ7pNjhGuK8uK4KbO0kzZB6m2whV2SFwTS7FM2GCDKcHf9Fj
         St4zsFul6SVBnmHd9RxaxtvDtmDofdZyUMWbeVXwtBPszH5PgXIt84yLZJe9M1uRIKMc
         4soQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="xth/xc9/";
       spf=pass (google.com: domain of 3lzafaqukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3LzAfaQUKCVw8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-477aa910d7asi1229985e9.2.2025.11.20.07.13.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:13:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lzafaqukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-6411e349b73so1479460a12.2
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:13:52 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUtX4oBwuiVqRVLzCR226FOCM9b4SDQK2wW9sNptK65dUVDTd65H2QrUDhCropwvf86zZh5QNzhcwI=@googlegroups.com
X-Received: from edp1.prod.google.com ([2002:a05:6402:4381:b0:641:661a:2bff])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:3586:b0:640:a7a9:289f
 with SMTP id 4fb4d7f45d1cf-645363c6b54mr3185434a12.2.1763651631398; Thu, 20
 Nov 2025 07:13:51 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:56 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-32-elver@google.com>
Subject: [PATCH v4 31/35] rhashtable: Enable context analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>, 
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="xth/xc9/";       spf=pass
 (google.com: domain of 3lzafaqukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3LzAfaQUKCVw8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Enable context analysis for rhashtable, which was used as an initial
test as it contains a combination of RCU, mutex, and bit_spinlock usage.

Users of rhashtable now also benefit from annotations on the API, which
will now warn if the RCU read lock is not held where required.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Thomas Graf <tgraf@suug.ch>
Cc: Herbert Xu <herbert@gondor.apana.org.au>
Cc: linux-crypto@vger.kernel.org
---
v4:
* Rename capability -> context analysis.

v2:
* Remove disable/enable_context_analysis() around headers.
---
 include/linux/rhashtable.h | 14 +++++++++++---
 lib/Makefile               |  2 ++
 lib/rhashtable.c           |  5 +++--
 3 files changed, 16 insertions(+), 5 deletions(-)

diff --git a/include/linux/rhashtable.h b/include/linux/rhashtable.h
index 05a221ce79a6..5ba7356d79f0 100644
--- a/include/linux/rhashtable.h
+++ b/include/linux/rhashtable.h
@@ -245,16 +245,17 @@ void *rhashtable_insert_slow(struct rhashtable *ht, const void *key,
 void rhashtable_walk_enter(struct rhashtable *ht,
 			   struct rhashtable_iter *iter);
 void rhashtable_walk_exit(struct rhashtable_iter *iter);
-int rhashtable_walk_start_check(struct rhashtable_iter *iter) __acquires(RCU);
+int rhashtable_walk_start_check(struct rhashtable_iter *iter) __acquires_shared(RCU);
 
 static inline void rhashtable_walk_start(struct rhashtable_iter *iter)
+	__acquires_shared(RCU)
 {
 	(void)rhashtable_walk_start_check(iter);
 }
 
 void *rhashtable_walk_next(struct rhashtable_iter *iter);
 void *rhashtable_walk_peek(struct rhashtable_iter *iter);
-void rhashtable_walk_stop(struct rhashtable_iter *iter) __releases(RCU);
+void rhashtable_walk_stop(struct rhashtable_iter *iter) __releases_shared(RCU);
 
 void rhashtable_free_and_destroy(struct rhashtable *ht,
 				 void (*free_fn)(void *ptr, void *arg),
@@ -325,6 +326,7 @@ static inline struct rhash_lock_head __rcu **rht_bucket_insert(
 
 static inline unsigned long rht_lock(struct bucket_table *tbl,
 				     struct rhash_lock_head __rcu **bkt)
+	__acquires(__bitlock(0, bkt))
 {
 	unsigned long flags;
 
@@ -337,6 +339,7 @@ static inline unsigned long rht_lock(struct bucket_table *tbl,
 static inline unsigned long rht_lock_nested(struct bucket_table *tbl,
 					struct rhash_lock_head __rcu **bucket,
 					unsigned int subclass)
+	__acquires(__bitlock(0, bucket))
 {
 	unsigned long flags;
 
@@ -349,6 +352,7 @@ static inline unsigned long rht_lock_nested(struct bucket_table *tbl,
 static inline void rht_unlock(struct bucket_table *tbl,
 			      struct rhash_lock_head __rcu **bkt,
 			      unsigned long flags)
+	__releases(__bitlock(0, bkt))
 {
 	lock_map_release(&tbl->dep_map);
 	bit_spin_unlock(0, (unsigned long *)bkt);
@@ -402,13 +406,14 @@ static inline void rht_assign_unlock(struct bucket_table *tbl,
 				     struct rhash_lock_head __rcu **bkt,
 				     struct rhash_head *obj,
 				     unsigned long flags)
+	__releases(__bitlock(0, bkt))
 {
 	if (rht_is_a_nulls(obj))
 		obj = NULL;
 	lock_map_release(&tbl->dep_map);
 	rcu_assign_pointer(*bkt, (void *)obj);
 	preempt_enable();
-	__release(bitlock);
+	__release(__bitlock(0, bkt));
 	local_irq_restore(flags);
 }
 
@@ -589,6 +594,7 @@ static inline int rhashtable_compare(struct rhashtable_compare_arg *arg,
 static __always_inline struct rhash_head *__rhashtable_lookup(
 	struct rhashtable *ht, const void *key,
 	const struct rhashtable_params params)
+	__must_hold_shared(RCU)
 {
 	struct rhashtable_compare_arg arg = {
 		.ht = ht,
@@ -642,6 +648,7 @@ static __always_inline struct rhash_head *__rhashtable_lookup(
 static __always_inline void *rhashtable_lookup(
 	struct rhashtable *ht, const void *key,
 	const struct rhashtable_params params)
+	__must_hold_shared(RCU)
 {
 	struct rhash_head *he = __rhashtable_lookup(ht, key, params);
 
@@ -692,6 +699,7 @@ static __always_inline void *rhashtable_lookup_fast(
 static __always_inline struct rhlist_head *rhltable_lookup(
 	struct rhltable *hlt, const void *key,
 	const struct rhashtable_params params)
+	__must_hold_shared(RCU)
 {
 	struct rhash_head *he = __rhashtable_lookup(&hlt->ht, key, params);
 
diff --git a/lib/Makefile b/lib/Makefile
index 2e983f37d173..4ca9e8ce66bb 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -50,6 +50,8 @@ lib-$(CONFIG_MIN_HEAP) += min_heap.o
 lib-y	+= kobject.o klist.o
 obj-y	+= lockref.o
 
+CONTEXT_ANALYSIS_rhashtable.o := y
+
 obj-y += bcd.o sort.o parser.o debug_locks.o random32.o \
 	 bust_spinlocks.o kasprintf.o bitmap.o scatterlist.o \
 	 list_sort.o uuid.o iov_iter.o clz_ctz.o \
diff --git a/lib/rhashtable.c b/lib/rhashtable.c
index fde0f0e556f8..6074ed5f66f3 100644
--- a/lib/rhashtable.c
+++ b/lib/rhashtable.c
@@ -358,6 +358,7 @@ static int rhashtable_rehash_table(struct rhashtable *ht)
 static int rhashtable_rehash_alloc(struct rhashtable *ht,
 				   struct bucket_table *old_tbl,
 				   unsigned int size)
+	__must_hold(&ht->mutex)
 {
 	struct bucket_table *new_tbl;
 	int err;
@@ -392,6 +393,7 @@ static int rhashtable_rehash_alloc(struct rhashtable *ht,
  * bucket locks or concurrent RCU protected lookups and traversals.
  */
 static int rhashtable_shrink(struct rhashtable *ht)
+	__must_hold(&ht->mutex)
 {
 	struct bucket_table *old_tbl = rht_dereference(ht->tbl, ht);
 	unsigned int nelems = atomic_read(&ht->nelems);
@@ -724,7 +726,7 @@ EXPORT_SYMBOL_GPL(rhashtable_walk_exit);
  * resize events and always continue.
  */
 int rhashtable_walk_start_check(struct rhashtable_iter *iter)
-	__acquires(RCU)
+	__acquires_shared(RCU)
 {
 	struct rhashtable *ht = iter->ht;
 	bool rhlist = ht->rhlist;
@@ -940,7 +942,6 @@ EXPORT_SYMBOL_GPL(rhashtable_walk_peek);
  * hash table.
  */
 void rhashtable_walk_stop(struct rhashtable_iter *iter)
-	__releases(RCU)
 {
 	struct rhashtable *ht;
 	struct bucket_table *tbl = iter->walker.tbl;
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-32-elver%40google.com.
