Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRUOTO7AMGQEDDYIURA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B481A4D825
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:26:31 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-390f729efacsf1223998f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:26:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080391; cv=pass;
        d=google.com; s=arc-20240605;
        b=fvP45OVJywj3ijYYKaTONUD6HyExyNjjXPPwdS9Ej4Mv6jo7AXLzncik+Wbb932Ged
         f6QsYbsNFVH0ZWrnbFWQmTmAMnsQ1EximlyDdDqOuOFwa+R9LBsyWl+D9+KoAf+EDCJc
         BfcwAuOdkVPduEoLSfBMUJXzU0BMDMFf7KFxNC12NzENDGvwaDnDrkkGMorq98WBU3dg
         33ilnhCT1btDTncLOeElwRGmPtplvchWzEEulY6SEP6tqZnc4SGh4eLUGBHw9CVKZ294
         iMFRBX1vFNrhEVwwSLlSCU9MwNqx9sFj13zuN105nItKsTHB4GIxL/fdy/Ucu57CpVPr
         Z0kQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=+hKVkWJpD+vpYI2g0i7IYK+AXvYOYhBOHKK6SDnw7tM=;
        fh=7qTU23yTdPl7TMFKEM9ddV3QTd5EA/BSvkd+CIbkdoc=;
        b=InZyoKYycFM6ICW040j8f2SDuqd1gYRFplkHdTXzY6/RRcZckVXRfRjFYEn7BtWKkf
         Lx0qugPlYVT3Pu780irIbpNdP3xTernZZvwDeeri/uUBZtG4WbfsLO94dZywIgbyZUNQ
         xKDry9pwlnHbvJveCN+isIj7E6fHmsZyvvqjN7/k2D3fgUVxOft2vsZ0QsizSVqZ8uYd
         xTlq57T80SxBQd0OCgKzmT/0p/FB19hqsuIjm9J8gZoYkNNantrG7FlrTAtwyYn6CCl2
         LiU2K8IZ9mrZU5ocRQWzN4nc4EOrOJHL2Bx1RRo0mbwEV+dPIgq0xf2fUGhndHvvBfjg
         Vm4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RraYdvuR;
       spf=pass (google.com: domain of 3q8fgzwukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Q8fGZwUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080391; x=1741685191; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+hKVkWJpD+vpYI2g0i7IYK+AXvYOYhBOHKK6SDnw7tM=;
        b=Qm5Vkam2HBgGfz9YSSf2fMrqKETFQa2f6I/+kzB9cYRixDF2c07wmxEy09dAsoUAZ8
         3tewYT64G1XT5nVSkew6q+QDVMrSxn6yiGiNHHxMEGNkofCFx9uyFgR7yyR0rEc/lk6o
         RCsEBjvdEjwblPfTF60R6EB0lBQkoCrJlWuiy3ZQMT5nTviEWz16w9nK5n+A4uI8jQky
         ovp7fbcB8Qxpn7UOSWZOyCx7zyL01nC0cF/PfxgeSFScm3Oevx+2nC7fyiz6T4jAmR0Q
         M3EhvgCTN5+8P8m52XNa7DSJBiPjG9eRnNX7m6SHHTdw/kEg8iX7SLG8Twy7s0sG12sK
         DqKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080391; x=1741685191;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+hKVkWJpD+vpYI2g0i7IYK+AXvYOYhBOHKK6SDnw7tM=;
        b=pPkurOdcPERlOdludN6yV8cjQ8tWOZNY+mPL/da0GNepLYDoKStxrUvXr4aDPl+kxI
         CVWUaq88sBfMqgzTH32369LdHhzYWkEXkdqTjUa4Jrcp3FLUi58A3UU0ehToG2Ung3pr
         HtcA9vpJ80oq7vsgvsAGlZYCvEua9rhbRB4vIlsB0ZgbyM2fdci5mxR9V/k8/cQXnH1j
         +i/0fpkwNsES7/3vMAeE2yw06NsxBX9obgWob42htGCv6FMU1hhUDF0W6Ajrf3UgR5KE
         jriTrEh8CYSyQQNX+5yQ0wH8ZrmHGR9uEH4x2Iupkh/4xGRgN7IlOD1UK3D0+bbTgVz9
         AmTg==
X-Forwarded-Encrypted: i=2; AJvYcCUMKFagrnlgQngrgAnLd9d8CQXB07evfgoW3X30Dd1xmfACgVUid55AQpzYyRtufC/9SmiLcQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx1z5xKJOV04qZ8AXO9RbPuQh/jF6QrhO0Z8JpqCif0iQS5rYgZ
	qxY7Aq1xq+3oe8Ud22WVqeZ47b80Wgn9VYrWhrvRbhH9tywhc1tB
X-Google-Smtp-Source: AGHT+IFA0Yg1ECuTLIO+5+Gu1MqE6lDZ2pZpQ5/sAZmqu8TAsLTcUirDEeDXtqBj2pA0dprcRmsX2Q==
X-Received: by 2002:a05:6000:2ce:b0:390:f902:f96f with SMTP id ffacd0b85a97d-390f902fafamr6567216f8f.22.1741080390500;
        Tue, 04 Mar 2025 01:26:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFH7YeHhd8NOMKBdk0pqozIBMOHjehyqqkTkcA9bulyRQ==
Received: by 2002:a05:6000:400a:b0:38e:5a45:4a6e with SMTP id
 ffacd0b85a97d-390e11f47f9ls3364085f8f.0.-pod-prod-06-eu; Tue, 04 Mar 2025
 01:26:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVXb4Cg0REHElXPqptlnDBoL6beSJRM3uo2BlX4KSwHaeEWgBIa0IXvy3UbQKTBx5RsDuYYVvPg5pA=@googlegroups.com
X-Received: by 2002:a5d:59ac:0:b0:390:fe13:e0ba with SMTP id ffacd0b85a97d-390fe13e232mr7098964f8f.27.1741080388136;
        Tue, 04 Mar 2025 01:26:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080388; cv=none;
        d=google.com; s=arc-20240605;
        b=XoJz+KSVh8yxlUcjo8y8iaEnEGkk3VGMjeH7+8vRCwjCksBmRrtmA5vo4yNZZlm9jw
         9OJObXn0+UbbMsoRbz0tqhKbbERz2KwoZpHmQwnsO4aUpHIlDm0SIY2EIE+x7AiCeAMY
         t8HN3KSbIvMiVAClY1qaAxewlgLMRKZ5S2ztiKM4QQr3JIqd4t+dJCzswhif8DEQEU0C
         7kFhCVvw/EN2MeGugw5K3kixnBvlnS7JucDiGr5SVQ7m25JgjQ6DsirOMBVBHFRGzA6y
         w7SfTMMO3GMdcBrsQjkaaOiqigwaDEp/h1xq7P+2z7LTSN4YSn8ihoRZoO8NYDepMoMj
         lrPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=6Oslc0Vw7rD1eBm5IrdyoxIc7gTLsk2fVXwffC4VNN0=;
        fh=7Zmw4XkKkTb+8MjVD8kTOR0Z4upDaH7MUIocEjkppj0=;
        b=B06ggTm4COAcT5HUG0E0/KoChzv8OTWs0akMvxOqUPcYHKyrDiIA8D9OgCiZdT3IHL
         IPDAtxoP0hLL/Ct2yb+YwkPvfDHfqppHIBPQzjICkcbgApCvd9GNQkr8gnapPJF405xc
         63ZwFH7kqNanLdYoet8En+TdsLNvPOPwUhyZW2DLsHAj3u7m3exrYvV2n/kwPH8W1Xk+
         H2Bjb55RbjlqewkeMp7qu3ByL83I97Hszpm15bDrmG++p7ASZw/xotCtcxLFVHaaH1q6
         OX41ZuncT3GfBnx62bTz1R3nXNI3K2iu1qqGrrLFuSBdhvk8GZOnF+YfgreuUgMmmcFX
         IW7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RraYdvuR;
       spf=pass (google.com: domain of 3q8fgzwukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Q8fGZwUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390e482d56csi439501f8f.8.2025.03.04.01.26.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:26:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3q8fgzwukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-abb8f65af3dso528841566b.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:26:28 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU5Cx3p9ocU+/uVx0CzB9h1RNIOafNICd9vng4fhDDVrBbhYmAyVujmJWkViUlTdbAZKIFhyRX7dHU=@googlegroups.com
X-Received: from ejctb24.prod.google.com ([2002:a17:907:8b98:b0:ac1:4149:808d])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:781:b0:abe:f6f5:93fa
 with SMTP id a640c23a62f3a-abf261d3b82mr1992742166b.33.1741080387611; Tue, 04
 Mar 2025 01:26:27 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:28 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-30-elver@google.com>
Subject: [PATCH v2 29/34] rhashtable: Enable capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RraYdvuR;       spf=pass
 (google.com: domain of 3q8fgzwukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Q8fGZwUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
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

Enable capability analysis for rhashtable, which was used as an initial
test as it contains a combination of RCU, mutex, and bit_spinlock usage.

Users of rhashtable now also benefit from annotations on the API, which
will now warn if the RCU read lock is not held where required.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Remove disable/enable_capability_analysis() around headers.
---
 include/linux/rhashtable.h | 14 +++++++++++---
 lib/Makefile               |  2 ++
 lib/rhashtable.c           |  5 +++--
 3 files changed, 16 insertions(+), 5 deletions(-)

diff --git a/include/linux/rhashtable.h b/include/linux/rhashtable.h
index 8463a128e2f4..c6374691ccc7 100644
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
 static inline struct rhash_head *__rhashtable_lookup(
 	struct rhashtable *ht, const void *key,
 	const struct rhashtable_params params)
+	__must_hold_shared(RCU)
 {
 	struct rhashtable_compare_arg arg = {
 		.ht = ht,
@@ -642,6 +648,7 @@ static inline struct rhash_head *__rhashtable_lookup(
 static inline void *rhashtable_lookup(
 	struct rhashtable *ht, const void *key,
 	const struct rhashtable_params params)
+	__must_hold_shared(RCU)
 {
 	struct rhash_head *he = __rhashtable_lookup(ht, key, params);
 
@@ -692,6 +699,7 @@ static inline void *rhashtable_lookup_fast(
 static inline struct rhlist_head *rhltable_lookup(
 	struct rhltable *hlt, const void *key,
 	const struct rhashtable_params params)
+	__must_hold_shared(RCU)
 {
 	struct rhash_head *he = __rhashtable_lookup(&hlt->ht, key, params);
 
diff --git a/lib/Makefile b/lib/Makefile
index f40ba93c9a94..c7004270ad5f 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -45,6 +45,8 @@ lib-$(CONFIG_MIN_HEAP) += min_heap.o
 lib-y	+= kobject.o klist.o
 obj-y	+= lockref.o
 
+CAPABILITY_ANALYSIS_rhashtable.o := y
+
 obj-y += bcd.o sort.o parser.o debug_locks.o random32.o \
 	 bust_spinlocks.o kasprintf.o bitmap.o scatterlist.o \
 	 list_sort.o uuid.o iov_iter.o clz_ctz.o \
diff --git a/lib/rhashtable.c b/lib/rhashtable.c
index 3e555d012ed6..fe8dd776837c 100644
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
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-30-elver%40google.com.
