Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGHHSXFAMGQEQMHIUEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A91ECD09CB
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:47:37 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5944b3cb6fcsf1840730e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:47:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159257; cv=pass;
        d=google.com; s=arc-20240605;
        b=EfjH2a9qsK+whGLIGtAKRV1AxKXXxN9NvQ+ZZnuOtBEPsKTaIslZHFhff35aUneGOy
         jQ4cyllqj2FuhwTtAnCGCsrnbEpu5qysiHNeQ4lamwUfDD3NqD0c/ckIK91I2TWKF8+l
         X/okzrJwQfe4v3SItOL/5/nPIuOkoj6bgUy9s69bnAFhqVxtfcTVBjzVGp6G3fvyQYyY
         4dWM/9jTP5hPMjEtfVsyGkXhUQoubU7jgK+y45iCQcN2NRHhyjknD1wIhoQEm+G3tZ7M
         y1ZhgOYIUmB6MYAm3FPBDY0VY/Mqa3UoJNYTuH9fPjOHvO1XfOwgZ+O/ZBcCIXUzwm0l
         jX9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=MoDkIxKqaB8Efmap7jr0rhk5t+VZ8qFpWdSGdexM1Qs=;
        fh=clmPclwGZfdccVzK21MG3JV2efxGivASfkGDNH+Nduo=;
        b=R1LeWa6uox4yKxWVrR8dUAWH0o1S4diANIVXuEDMVZo8f9jR2My3jM0FMUj6+QEfEi
         vfyU//p1UQGv/AJip25Eq2WNC4h/95luEtaBozU2GXqDXc1FaHRfU2sHh6H0kXHn0bnu
         iMyzx97HZ0x1GAv+Uv6tUOSX3JFmaiyDAMjn6jxmOU2L/zjQHX18cZUg6UlW+lK/GHCj
         ED4GpiIveVYCpuIDrMkQonjLyjRwDc6ODUZACYm/9Qvsf6qX1v9fFws5US9s/+y3IBcb
         TSjMGD8v8C1yGWECH9NEmxtfqSgJAb5W0lolfKkUIzh+qWCI1vjwcvjdtK9o1Uk2HN64
         RpZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Q5HxPrjS;
       spf=pass (google.com: domain of 3lhnfaqukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3lHNFaQUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159257; x=1766764057; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MoDkIxKqaB8Efmap7jr0rhk5t+VZ8qFpWdSGdexM1Qs=;
        b=qqWqgfSoy0GywqTKXd4ZtYDGzZnt0WlYC5ZaXrhQZwAI9dGCnKq6ctTUzHlaaeZwVl
         I1iyLHf1/DR2kVY0ctRs6PDnVejzaRqnGT85XxqWkLw+2FNLRi5ywizficC3OTXzykS6
         UZDKhW1CYGIqmjC9h5p6QR7ZBqbewjhFanF7o9pIIiXBQpbr6hHRx6P2yDAA4rqZYGsU
         AEEj5ZuE8YN5RuQDZpSHgaBH+msTBz8j8/30+0PQF1JLgoxLbEIfhxr9Ke8z7aUQCQaY
         XyoJpe7m8jW6/763MdRU9gaZ8ArPd2PfJGZvR5uTwzJS0KxV88VCqauNqV4KB5w5GVPR
         NHRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159257; x=1766764057;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MoDkIxKqaB8Efmap7jr0rhk5t+VZ8qFpWdSGdexM1Qs=;
        b=QXZG32Om0TZSpSyK7goOuFOFT6OOjxPjCWNAj1dsd/KmG3HQupckzgwAjTblaAYhCD
         d946NYdap/eone2UW1UzRePnoDsA8ZzEoHhFkTq8RI8Exp+lwvWAYEEuuyNoL7hx2OEx
         lbZ2o+VfLh8RnVvEPq7cQXiM0ajxorIs+eGBhOt/qgzbOlJcXONo19Q0XkmY4ohvXZ5R
         qWoE71QK5IE76mLiSmGDm53N8A0etp0CwWSUi1qX47aGKz+If8ijCBECFoxa2LwkmXvK
         Q3KkxCxzsDyvsVKq5trUNBYf69sNgt4HELpibuu1SIHo5P+GYvFMBaLCQDFK/lkErMOX
         EB1Q==
X-Forwarded-Encrypted: i=2; AJvYcCWG+KLovMjLVCgLsWXnk05mYKyJ0oeKzlnDTwQmrIv57YeGUEfQ/1LKwXbiw/s/Fa39LwcTlQ==@lfdr.de
X-Gm-Message-State: AOJu0YxOtOdw4fiyQMpmxUy4TrdUQ/XNmGFtCakBb45n3W66S4PU7B8L
	2IM9d6wl1r/+kkPr7/gxRDVVqpaR2qO7IUqyTxwlJn1RXOV1PjL2nEUL
X-Google-Smtp-Source: AGHT+IGxADkzL1iFqFeCHwUU+udcW8/P7hN3VmtUq6YTJ8m3/rbld5TOEXRcAsfdVbv5bNLXzRPNQQ==
X-Received: by 2002:a05:6512:2388:b0:598:ee6c:12de with SMTP id 2adb3069b0e04-59a17d6411amr1288483e87.47.1766159256664;
        Fri, 19 Dec 2025 07:47:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZfudJe/N28wDGY8de7tDQsvsd/ABuc8Ay4FUhksRDhZA=="
Received: by 2002:a05:6512:118a:b0:598:f360:1eef with SMTP id
 2adb3069b0e04-598fa3fdac8ls2710366e87.1.-pod-prod-07-eu; Fri, 19 Dec 2025
 07:47:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV7sjfdQvN4aJseIyttPVsnFnLFTwA6L8vjB2x84bU2ncWz1uJBcCJ46RQImCiOCQCkSI0OxsqRKa0=@googlegroups.com
X-Received: by 2002:a05:6512:3c9e:b0:597:d702:58e5 with SMTP id 2adb3069b0e04-59a17d57c68mr1348299e87.39.1766159253875;
        Fri, 19 Dec 2025 07:47:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159253; cv=none;
        d=google.com; s=arc-20240605;
        b=LssKPbAIgh9+BNx74l1YfLRtcaYLcd9F4EfEzUYlrS/msDqlVRJfXqe8utcc9jmWKv
         LkG04tXuin9hYE2gD0zDJsQgqootZpn1AlWXoTH1o0wr3V9gpZDRVNNiQco1Uaz51C4E
         WUhy/3b8e/V46Z/NlBPpgbUax9hF/rLqSvPloAx4YYY3v9dA6XeMniQWtDTCr6d/u9Up
         5wsrmFBJ+WuVs6kEtWpim62Ph6A11Ase7wFE5PC6iKkacNg8YyRmRxQFuX7jLHUI+hNp
         hB34KemgadT8crB5wzyrT2hgGLy0lBfRP/T6uAcnJdpBwyYjjbbSk7KsfO90vw4vilAd
         JMqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=gVYXgtdCpLCQNFVroiaCMxergOmHfVtsDs2aOEVw4MA=;
        fh=ZQeN7f+R47bzJiUBSXnfcfyZeCIYvd9FiBQ0mw7ydB8=;
        b=Ig9VDwihtuRhppCOgNtgX8axiqXNjisOeNP0Evw7wgDgBL7sguu1oySEFUXKez8ej5
         gMp1U00K4du8sJUPiiN9E5qPEAuLmMFQhSPxzOUb7T7cFSGYFrd2RUxkm9+r9Lyqct3g
         Rh+Su/FCnsVEFfWqAGWSxd52Zn9cwtTD7lytq4PYPgTP0khbNKRBPbr3OvilQi1Po+vt
         05VFQZxJmSuPvZaFBag0CLXDw93HWFzqa6xB5SAgZAMfGzgBoFjd1e2cR3rf8/DcN3Jm
         642TMQOKmRqonm1R7vHzyMdzSj7hARu1Dp1HnT6iIPe+Aw604n4zksZEc47Owy6Qf90l
         V0DQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Q5HxPrjS;
       spf=pass (google.com: domain of 3lhnfaqukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3lHNFaQUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-381225ea246si283921fa.5.2025.12.19.07.47.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:47:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lhnfaqukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-47a97b719ccso10200935e9.2
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:47:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUdzTKUU5v2OA74XILM8GmEZ/DTd7X00sLZX6CLxVhLMPn8m2zkulXU9pcFfvCY2fUOqLM7Zdd+S40=@googlegroups.com
X-Received: from wmco23.prod.google.com ([2002:a05:600c:a317:b0:475:dca0:4de3])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:4e8f:b0:479:3a89:121d
 with SMTP id 5b1f17b1804b1-47d1959c74fmr31405385e9.36.1766159252991; Fri, 19
 Dec 2025 07:47:32 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:21 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-33-elver@google.com>
Subject: [PATCH v5 32/36] rhashtable: Enable context analysis
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
 header.i=@google.com header.s=20230601 header.b=Q5HxPrjS;       spf=pass
 (google.com: domain of 3lhnfaqukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3lHNFaQUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
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
v5:
* Fix annotations for recently modified/added functions.

v4:
* Rename capability -> context analysis.

v2:
* Remove disable/enable_context_analysis() around headers.
---
 include/linux/rhashtable.h | 16 +++++++++++++---
 lib/Makefile               |  2 ++
 lib/rhashtable.c           |  5 +++--
 3 files changed, 18 insertions(+), 5 deletions(-)

diff --git a/include/linux/rhashtable.h b/include/linux/rhashtable.h
index 08e664b21f5a..133ccb39137a 100644
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
@@ -424,13 +428,14 @@ static inline void rht_assign_unlock(struct bucket_table *tbl,
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
 
@@ -612,6 +617,7 @@ static __always_inline struct rhash_head *__rhashtable_lookup(
 	struct rhashtable *ht, const void *key,
 	const struct rhashtable_params params,
 	const enum rht_lookup_freq freq)
+	__must_hold_shared(RCU)
 {
 	struct rhashtable_compare_arg arg = {
 		.ht = ht,
@@ -666,6 +672,7 @@ static __always_inline struct rhash_head *__rhashtable_lookup(
 static __always_inline void *rhashtable_lookup(
 	struct rhashtable *ht, const void *key,
 	const struct rhashtable_params params)
+	__must_hold_shared(RCU)
 {
 	struct rhash_head *he = __rhashtable_lookup(ht, key, params,
 						    RHT_LOOKUP_NORMAL);
@@ -676,6 +683,7 @@ static __always_inline void *rhashtable_lookup(
 static __always_inline void *rhashtable_lookup_likely(
 	struct rhashtable *ht, const void *key,
 	const struct rhashtable_params params)
+	__must_hold_shared(RCU)
 {
 	struct rhash_head *he = __rhashtable_lookup(ht, key, params,
 						    RHT_LOOKUP_LIKELY);
@@ -727,6 +735,7 @@ static __always_inline void *rhashtable_lookup_fast(
 static __always_inline struct rhlist_head *rhltable_lookup(
 	struct rhltable *hlt, const void *key,
 	const struct rhashtable_params params)
+	__must_hold_shared(RCU)
 {
 	struct rhash_head *he = __rhashtable_lookup(&hlt->ht, key, params,
 						    RHT_LOOKUP_NORMAL);
@@ -737,6 +746,7 @@ static __always_inline struct rhlist_head *rhltable_lookup(
 static __always_inline struct rhlist_head *rhltable_lookup_likely(
 	struct rhltable *hlt, const void *key,
 	const struct rhashtable_params params)
+	__must_hold_shared(RCU)
 {
 	struct rhash_head *he = __rhashtable_lookup(&hlt->ht, key, params,
 						    RHT_LOOKUP_LIKELY);
diff --git a/lib/Makefile b/lib/Makefile
index e755eee4e76f..22d8742bba57 100644
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
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-33-elver%40google.com.
