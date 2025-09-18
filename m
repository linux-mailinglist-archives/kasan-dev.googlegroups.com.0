Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7NDWDDAMGQECVSU3UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AF1AB85008
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:56 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-5793e699a7esf371323e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204415; cv=pass;
        d=google.com; s=arc-20240605;
        b=eFb9Rh7h7YUw8MH8xHcQIJY6ENRNzELoJ0Lbxv0UU2pBIHFPiG6u52hS6Sa/ALi6Cq
         3BIRrSIxECv1jKfxwYt8GyaKVlULvCDr8Jhum/zQw3mKKSbkgaaetmlY4y+9HgSYC9WH
         o2yOa1fJF64ur+rE/1PwHmcH2eGnZTHvIW1yIcCEcxukx6Oo3+Z/fw1Ozr95KaYq+kyz
         lHawZaxUDpKO8tRlzMXFR4JyrW0i4rmD3PtimUtzZ3iBdpLmnQ7nDqFgk+JN7XHNbvwJ
         jEepGrZfgttDU5KWnyY005M7Ch16093OIge+k7e5PSjAwofoJzLetR7S6NNXbVyKnrMP
         9c8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=/zcMQVpCBByzEvUYFskW+zbFuNsy7wSjw3FFopqiqrs=;
        fh=PrCc88ceE65+2wWxhRc19Mi4xluNwU+UCmadwPYAbXQ=;
        b=OKx1pVtmTQWi7WKy/OsidiQVV03Sej27/yrlmRyXTX38fGhExGf74PZ3Ndrgmbb+Nd
         EHOKTu8VfwCng12bgN6ui3309taMtnlS0EyMG8OpVIBE0GgUc+Bp56vJ/wpnEPVteB4r
         UpwhKc9v/M0u2NEmi6h/BB2+mkKj6RbqlyoutCKStCkxOKVTe70srqfl/Bv9OFok1ZyN
         5DVnH2cXtGMFNrT1FKL0KDPRXPeALDET5hi0wutkoI7zylITajHA4BVg5Sh9jHX+I0u6
         cRuiLxxZYUV0i/IBEdVkXH3j9HGy9Kfm5rm1BZjbqjvimAit/46UBFtpxUd32c+fPDHP
         PMJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1KNJ5pzY;
       spf=pass (google.com: domain of 3-hhmaaukczs9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-hHMaAUKCZs9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204415; x=1758809215; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=/zcMQVpCBByzEvUYFskW+zbFuNsy7wSjw3FFopqiqrs=;
        b=Qk98GJ+z3lzrmdWto30jcY32m3m53anwo6zudFT3iPRwZfelYf8BWDpzWUERhAcW8t
         QiBaMGMD0MDG//Cw/MQsA5ZOAKfmKiGyINCQJnfrQc/BvcQFf+y3g4hJbsKs0kRRSiYt
         cDTLRMbo1qQ+pjig3egpwWPmKLRL14JHe6Wji264QRcBXTz9nXuLfqS4o9QD/+7Av0WR
         Ze+6onzCiN/+2Du20+uFUESuoczilYSlQ8Y/m++1ng7Dn+uEUgpfUxbdaAujtMxo7sc4
         yWNjLugZ9GXJcRsKoGA87F5Jao69fhJDcTw2c4ARxLVsZUjBzWra0Zdb8fUy18J5uNaQ
         ewog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204415; x=1758809215;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/zcMQVpCBByzEvUYFskW+zbFuNsy7wSjw3FFopqiqrs=;
        b=qF7EuLSanpm6E/843UrRSrzbMmqBM7F8NrDUSKk9qWwnc37qW6uhHIs0oUAamBK8dj
         jdPBfvz8jrb3A2PiSIagi/6ACYoyoaq9XXYK+4grqQturjdU4nOy2jnpxhe8a2cUKzZk
         RgCwmXIwg6Pr+ECGepT2P8CkrBneKkLnGTx84yUGYh+JLniRQHsuot18i27lYOeproMv
         mFHU/l4pXN2+GPB36sQI/ksuLUs0vWOugJ6SNai4gDXOrMRNd80Ip/VSA4t9Ornmg5JR
         JUrez8aO5Vpuaorz1Vp+ZAFDEe+TQZ5oI845EtAoTDRRn+q9dW+q6BhXN7OzaXF5sxb0
         1Emw==
X-Forwarded-Encrypted: i=2; AJvYcCVEXTiTtnnVIhGb/tQmBPnk3I8arV5U1Cnf+7gdF5cW21AVpzlo7wEHiRI0tXwcZT1QRGhzLQ==@lfdr.de
X-Gm-Message-State: AOJu0YytfpWbhDYmdJuNOiyJU2lXrxu9SldZGnrP96Rf51vBCpQS9CN5
	4ZzawQX6iAQk1u4gpxjP3kQTwG0S5DB9Ur4lrV0JMo++ZP+XJboY/YL7
X-Google-Smtp-Source: AGHT+IEvZ8/HnnE6wL6DUJpG+WhE4FEEYHKufzppcK7GcT5Yq36DlXPEW8DP27Tz5dF9AuYb/j9Sfw==
X-Received: by 2002:a05:6512:1156:b0:55f:61de:5359 with SMTP id 2adb3069b0e04-57799405aebmr2093166e87.24.1758204414629;
        Thu, 18 Sep 2025 07:06:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6PTondHBfpqGEiZsqfXzix0sfvK+PDBJCNAd1N/6YegQ==
Received: by 2002:a05:6512:289:b0:566:3587:7dee with SMTP id
 2adb3069b0e04-578cbffd937ls234849e87.2.-pod-prod-03-eu; Thu, 18 Sep 2025
 07:06:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWjxrk/QqI73otqy9BEihb+MgJJanSc7u5+Gf0EpbK1v8SxTRVsQjR38imvMd/lGU3zisiRsp28/F4=@googlegroups.com
X-Received: by 2002:a05:6512:3f26:b0:55f:3f00:a830 with SMTP id 2adb3069b0e04-5779b9b5a1fmr1849738e87.57.1758204411226;
        Thu, 18 Sep 2025 07:06:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204411; cv=none;
        d=google.com; s=arc-20240605;
        b=iIWrw/xtQgqFYP4zEUAWjVRYS6Jaz2HL2OlH59/poh4HD6ouMSFWOzRqCF9fwmX70b
         7Z20JTJ55uQ6G6JrQcTbFAYhZ506Xf+OipjvtcXCOPKyMTca4fkySjuJvKuezncDRBU1
         5NsEkzx0C79VJPEXmfN9ca+AsMFFj1T3iD7okl4Z5XJjyOdQ8yQRFAaCNsUp2mYo1JuD
         97PPtg/iVJqWE4LVEAuXweoVMhIx3L2BOpSgAFSr3/04HJDtWq7tYz5kbya+gTlZ+c+V
         FhsMUKugt2IVYyTAnzLKGzDzWA+ZhyCMLZFM/hQEMHkzQV9PoKl1I4EnopKCagK742vC
         gI9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=uu2U7ivUVuh8UFOqD9X78NwxcdL3Tv7H02aP9D4eaJs=;
        fh=KlAN/4NNWNFP8lo2VCBkgXTXrbAT3mor0suSFAkZawA=;
        b=AX60ntzA6BmF08bQLOUeWb0fgfOKvCYonALGWqMPTbUiPHwnrcD+9quyS/VShZnUQ3
         Vc4zGTU91nHJqxgUTbgRSupjMdWgsWF2f9C4rdQ8aaXudPoYILDBzJ6ffXqtc4QYVvH1
         RCb4UsC2IY6VHGORF8oCOH6zGu5Ca88oiJjNr9cp6sJ1JsVRT0JxQxYy0S/MvFcFGrXC
         5pz+eVH2GBBzXD99vDa2JD2GzIXLkupB9uAEIzsFA++Q/73h9upOVUFwPW43FoSQjW8p
         YLhGY6jvZxZv30SWcsP1YbxPlPxvT9bEfd+3/zir2d7lPuaa6t265DE88JR5miYmeEzL
         txRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1KNJ5pzY;
       spf=pass (google.com: domain of 3-hhmaaukczs9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-hHMaAUKCZs9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-578a8bd4644si17943e87.8.2025.09.18.07.06.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-hhmaaukczs9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-45e037fd142so11172675e9.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV90Vi3Y7NsMlR/PvFEPs9qqw7rOmq5czcJzLQL9nnpgXBl4rDjfXVo5cK7ed1VZjrqOUjBvxqpDGM=@googlegroups.com
X-Received: from wmkz6.prod.google.com ([2002:a7b:c7c6:0:b0:45b:79d1:abcb])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:1d1a:b0:45d:e326:96e7
 with SMTP id 5b1f17b1804b1-46206b20d8bmr53761355e9.29.1758204410398; Thu, 18
 Sep 2025 07:06:50 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:42 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-32-elver@google.com>
Subject: [PATCH v3 31/35] rhashtable: Enable capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1KNJ5pzY;       spf=pass
 (google.com: domain of 3-hhmaaukczs9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-hHMaAUKCZs9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
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
Cc: Thomas Graf <tgraf@suug.ch>
Cc: Herbert Xu <herbert@gondor.apana.org.au>
Cc: linux-crypto@vger.kernel.org
---
v2:
* Remove disable/enable_capability_analysis() around headers.
---
 include/linux/rhashtable.h | 14 +++++++++++---
 lib/Makefile               |  2 ++
 lib/rhashtable.c           |  5 +++--
 3 files changed, 16 insertions(+), 5 deletions(-)

diff --git a/include/linux/rhashtable.h b/include/linux/rhashtable.h
index 6c85b28ea30b..347716b1ca37 100644
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
index 43b965046c2c..85a9144b008a 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -50,6 +50,8 @@ lib-$(CONFIG_MIN_HEAP) += min_heap.o
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
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-32-elver%40google.com.
