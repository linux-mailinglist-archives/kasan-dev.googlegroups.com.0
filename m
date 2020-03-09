Return-Path: <kasan-dev+bncBAABBN5GTLZQKGQEPDCGIZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id D297517E7C5
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:24 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id l62sf7241327ioa.19
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780663; cv=pass;
        d=google.com; s=arc-20160816;
        b=wuYKw7fJG2MNBT96N/+09xLCB14GtYqcALzz34iL1Yyl5JCamCoGdTrNL8ylG8Kij9
         +PHlQcN6sqE76+05b4BAOQuTmXh9fVLfEAGJWzOfu7eXkoInPP5mx6InkI4iGgTkSdMM
         7cvi1RWAkjfmo77rtdPCHO49Zivt7IvTcD8Q5q2u2dsGLLMB+ms2Wm87QezrdtKnOIJ+
         KhySaP/RB+ec26Vu5iRo2jg360H02mrbtJfWnmgM5VwT57n63iN6umsI7EvL+Np397pj
         CL8U1szaWiRS0s+AEWWObT9mOW+Lhiyqnvkhewmk5Xcq2nFPAd22PrfR4Yug/tkZPChn
         OpXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=oHsUdGXKD4hBNMasd02a6njohyPXiaspsyHyCn3Gjig=;
        b=v3irbaW4GQvTqNhwdF/jS4ArYIPTiICis38y1wKPnWUIedwRUAx+wGeICWsRqiNoe+
         xCxR6H0TKD6E92ibtTiQPTwrbz+DXrPuxGvZ3TKSWdQUqw+EZ75kHgho6kX/Oap5Kn62
         9ar3+b5oHOGGto1X9OZulCHtjOd/3JCOQ5o5Oyobb+QPozFfPcMYbQgeaobGEqMbPVzm
         1rVv2qHXWnUo6Dm4QGnzkKR4Ztgy6nDNRZEAFz6JYV94ytkbwhWKPNzYd1WuU+5AIBa1
         R9ee7K52hclWgImCt7FBfpeMXZl6rsp7cLNvVg1W+/UYN2uvFBzP5xLrBaO9TmFnvvGs
         vkZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=jocnfW4Z;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oHsUdGXKD4hBNMasd02a6njohyPXiaspsyHyCn3Gjig=;
        b=O+5Y5nnUK0w1+pFRXHEC+E0/Zv84sMLoC9MjY0gnrvQbsEPft7u2SmskBh4q1HjMyJ
         JAtUjYA2EdW6uBpGktrm/weLTqsrorhgjB7jXN5GW4SBF1bbbdcpF6rHQEjTr97Z7t4W
         YE6qOYxkx6LQcjdMiamLAms8f7Hs3nX0vxhUJN6vJ1bOaXiUas+dZq+gZ1PRa7qnPQdT
         R2gcb0IcBcApquxLKf9kuo+/pDGS0YAQd9V8luAqYO6M1T0pb4Wu8IMd7wZX/PySXyi0
         eYIUghvyMqzMrW5bdRUFvtqQEolgqrcWPtzzuIWj6gX5nCT1iEjaOFbzPS+8He1QZ4i0
         SV5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oHsUdGXKD4hBNMasd02a6njohyPXiaspsyHyCn3Gjig=;
        b=ppc2NkQ1hkIV/4o0k+HSxoZSCJRtasv9ZYDODuwFnEbRhbIW4zyguwgPiFmGShK/v4
         3icjdFrgMz9HAsb2lwIGX1zoaFxOCf+3fGswoSjwACmsQAohmKQi5nw3IM/sZIjp3by1
         O/Vf6lh6mbkdoFhZ0q6UaZdkCF+zzN54ltnWIFjnJxcqyyS3jIwgikiPxVB0NzV2pzKv
         ICv3laUe5DmGsj/45eADmLTG/bJBhUWr1jQXwI4+81uwvlzn5dca0H1dIFFDsH2vGBOf
         VOx7OBdRUV0dDs2WvIjhp1DAOav7YllobGf6LFqzViNPC7uCreuV7FKj4/klBcX2GNir
         5iCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0EBuZj899GhavAOVP0gVejkDYCSACy0Ntg5Wu2Oaakq5A1oLzc
	vrn9Ngjx5Gk6QFh1KZjAAmM=
X-Google-Smtp-Source: ADFU+vsIEEuzFQxoYnArxI1RVULQ+LVNuB3EdH32bOJmJJO3ixS82L0ZUjm1j+hTuk8zRdVPIuMWmg==
X-Received: by 2002:a05:6e02:cc1:: with SMTP id c1mr17377704ilj.165.1583780663406;
        Mon, 09 Mar 2020 12:04:23 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:3084:: with SMTP id q126ls1289125jaq.6.gmail; Mon, 09
 Mar 2020 12:04:23 -0700 (PDT)
X-Received: by 2002:a02:b09c:: with SMTP id v28mr15923660jah.82.1583780662910;
        Mon, 09 Mar 2020 12:04:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780662; cv=none;
        d=google.com; s=arc-20160816;
        b=F4WYNfiYDaZoK1Vxip/OAvXuAfe1VX4MtEDr/qCV5bQRGJoGXdbP/6rA7mr0+D9iX6
         TE8p3c47jp/9fTLlrx1BoMtmngK/4w96GAVpkOjeGijngiBKYt8AFyvVqOCG21FwMrX2
         Olky8LbN2oytBq+zgY9MywycEOJKIVS0bJx0fl49XpvV9blM76y6TpbUqt9IO1aYmkke
         emaIRA3yOvrm7h0iWQJ6GViBsem7SUu1CJSc0QJgF7C1Vz0ER3Ak9+LcM1ZFSP8yJz2I
         z4MTj59xOZPhMbP/MyxFxiXRIXxQEROrwCVe/APo+cNK3dK8i5UPN2MyIszO3KD8QJ65
         pYOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=CFWP3ptdY3H4ubSpc3jXyi8HVOtEEBPQ55EsDYvIYV4=;
        b=yj+XCkQT/6f2wAFQ8WAwCTudZ0D5y9ITQ5ZvlSd1eGuUc+q9NJ11CPlL2NRQ+H+9Sa
         b7afGt5VI8ijFGbtO94J9cd/gfre7zaPTGepmbsdX81uej5Lloauob9Hj9hIKm/qrswv
         qJnzerPV2R0Y5JFd1aP4s9PhLVFDLVo1eVD6H5JIblxQPFn3TKeV2DEpuNy7PUzXFU2t
         fjfGdNSAsP0V2mqIqBdvG6iHp9vvD+f5B90zAXZ+/Evmnn30RqEuXofURPuqDp/VwCFE
         TIe9I3Yr4Doi05ySH1XnXViAh2kciab2q3UmHiRnhTkcyNu02dxJhgXo/l5SdfIIb6+y
         jvBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=jocnfW4Z;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t10si634871ilf.3.2020.03.09.12.04.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1B40720873;
	Mon,  9 Mar 2020 19:04:22 +0000 (UTC)
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
Subject: [PATCH kcsan 01/32] kcsan: Prefer __always_inline for fast-path
Date: Mon,  9 Mar 2020 12:03:49 -0700
Message-Id: <20200309190420.6100-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=jocnfW4Z;       spf=pass
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

Prefer __always_inline for fast-path functions that are called outside
of user_access_save, to avoid generating UACCESS warnings when
optimizing for size (CC_OPTIMIZE_FOR_SIZE). It will also avoid future
surprises with compiler versions that change the inlining heuristic even
when optimizing for performance.

Report: http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
Reported-by: Randy Dunlap <rdunlap@infradead.org>
Acked-by: Randy Dunlap <rdunlap@infradead.org> # build-tested
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/atomic.h   |  2 +-
 kernel/kcsan/core.c     | 18 +++++++++---------
 kernel/kcsan/encoding.h | 14 +++++++-------
 3 files changed, 17 insertions(+), 17 deletions(-)

diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
index 576e03d..a9c1930 100644
--- a/kernel/kcsan/atomic.h
+++ b/kernel/kcsan/atomic.h
@@ -18,7 +18,7 @@
  * than cast to volatile. Eventually, we hope to be able to remove this
  * function.
  */
-static inline bool kcsan_is_atomic(const volatile void *ptr)
+static __always_inline bool kcsan_is_atomic(const volatile void *ptr)
 {
 	/* only jiffies for now */
 	return ptr == &jiffies;
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 3314fc2..4d4ab5c 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -78,10 +78,10 @@ static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS-1];
  */
 static DEFINE_PER_CPU(long, kcsan_skip);
 
-static inline atomic_long_t *find_watchpoint(unsigned long addr,
-					     size_t size,
-					     bool expect_write,
-					     long *encoded_watchpoint)
+static __always_inline atomic_long_t *find_watchpoint(unsigned long addr,
+						      size_t size,
+						      bool expect_write,
+						      long *encoded_watchpoint)
 {
 	const int slot = watchpoint_slot(addr);
 	const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
@@ -146,7 +146,7 @@ insert_watchpoint(unsigned long addr, size_t size, bool is_write)
  *	2. the thread that set up the watchpoint already removed it;
  *	3. the watchpoint was removed and then re-used.
  */
-static inline bool
+static __always_inline bool
 try_consume_watchpoint(atomic_long_t *watchpoint, long encoded_watchpoint)
 {
 	return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint, CONSUMED_WATCHPOINT);
@@ -160,7 +160,7 @@ static inline bool remove_watchpoint(atomic_long_t *watchpoint)
 	return atomic_long_xchg_relaxed(watchpoint, INVALID_WATCHPOINT) != CONSUMED_WATCHPOINT;
 }
 
-static inline struct kcsan_ctx *get_ctx(void)
+static __always_inline struct kcsan_ctx *get_ctx(void)
 {
 	/*
 	 * In interrupts, use raw_cpu_ptr to avoid unnecessary checks, that would
@@ -169,7 +169,7 @@ static inline struct kcsan_ctx *get_ctx(void)
 	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
 }
 
-static inline bool is_atomic(const volatile void *ptr)
+static __always_inline bool is_atomic(const volatile void *ptr)
 {
 	struct kcsan_ctx *ctx = get_ctx();
 
@@ -193,7 +193,7 @@ static inline bool is_atomic(const volatile void *ptr)
 	return kcsan_is_atomic(ptr);
 }
 
-static inline bool should_watch(const volatile void *ptr, int type)
+static __always_inline bool should_watch(const volatile void *ptr, int type)
 {
 	/*
 	 * Never set up watchpoints when memory operations are atomic.
@@ -226,7 +226,7 @@ static inline void reset_kcsan_skip(void)
 	this_cpu_write(kcsan_skip, skip_count);
 }
 
-static inline bool kcsan_is_enabled(void)
+static __always_inline bool kcsan_is_enabled(void)
 {
 	return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
 }
diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
index b63890e8..f03562a 100644
--- a/kernel/kcsan/encoding.h
+++ b/kernel/kcsan/encoding.h
@@ -59,10 +59,10 @@ encode_watchpoint(unsigned long addr, size_t size, bool is_write)
 		      (addr & WATCHPOINT_ADDR_MASK));
 }
 
-static inline bool decode_watchpoint(long watchpoint,
-				     unsigned long *addr_masked,
-				     size_t *size,
-				     bool *is_write)
+static __always_inline bool decode_watchpoint(long watchpoint,
+					      unsigned long *addr_masked,
+					      size_t *size,
+					      bool *is_write)
 {
 	if (watchpoint == INVALID_WATCHPOINT ||
 	    watchpoint == CONSUMED_WATCHPOINT)
@@ -78,13 +78,13 @@ static inline bool decode_watchpoint(long watchpoint,
 /*
  * Return watchpoint slot for an address.
  */
-static inline int watchpoint_slot(unsigned long addr)
+static __always_inline int watchpoint_slot(unsigned long addr)
 {
 	return (addr / PAGE_SIZE) % CONFIG_KCSAN_NUM_WATCHPOINTS;
 }
 
-static inline bool matching_access(unsigned long addr1, size_t size1,
-				   unsigned long addr2, size_t size2)
+static __always_inline bool matching_access(unsigned long addr1, size_t size1,
+					    unsigned long addr2, size_t size2)
 {
 	unsigned long end_range1 = addr1 + size1 - 1;
 	unsigned long end_range2 = addr2 + size2 - 1;
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-1-paulmck%40kernel.org.
