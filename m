Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJEE4DXAKGQEFHHHXTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DCA410751A
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2019 16:43:33 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id x24sf1441711ljj.4
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2019 07:43:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574437412; cv=pass;
        d=google.com; s=arc-20160816;
        b=MvCEbOulvMpeaUlDiv4ViT0594/1JLAFoaYmJdiQgayI12pq08/c6luDs9BnyzVLor
         BZZRwjF4DHrnZsD0cEq24wPSx9KkNP9Rdw1l4jIPoklOlNgO6h3PxwRxpJSRlQJ5b/ZZ
         Kz8qTJpvFaZlHeuzlfi/+ylS176NadzVn+hDpN/0F0jIP/2+kZmhwogNKAmMIBC09F1x
         LZ7ZWrr2QGXnCa/OZLavkxx6GuWZMnYJ/xy32vW8xHQnE7wOAhJmkbgPdEnM2dG4+Qcy
         kuycEolsmXckJ3bBj1oFB1XOLY0Jn4GGj+Siq88r2Mw2DNehfeRr1PBsZyIGLRqqwYFp
         lhsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=dCpCcDFvoR9+HSv6sQpxss2RWZJqy9LXODB8bdbyS9U=;
        b=IdA9D3XQieA2GWt6d6CivtvLU817PYbcFrSm7euDcsmbtF6UC7evhN0s7qfd4xbLjT
         OUUtgrG8cIE+QbyF9T4fb3+yeTncwtVT2713OSsi5nnk97ls8iR2NiiBNtA/MpM+A+go
         lbVzjp5YvnL7O6VS99zrDsOGpH4i+CogvU0SX1Auu/tlfX0imfM/s2gyz+dm/Fs9K23b
         5R/yhagYMq6Kfgn+7x2waE3/+0z55Hr4MDMEsVrt2eFHNDWL8iy2AqoHcEE1f/tqmiNd
         1nsAd0X6jqGarNw6bDcnzPaH3duZ9Dfo4vzlwf4CYAMAVa8cdLaXQFJssgg/6tXbkBsq
         hhpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EgIhXGwx;
       spf=pass (google.com: domain of 3iwlyxqukcxwjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3IwLYXQUKCXwjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dCpCcDFvoR9+HSv6sQpxss2RWZJqy9LXODB8bdbyS9U=;
        b=tUjUS7HUk3aaJxB8olhrSGNVxPm4VNlTnHn2/C3Ukd6unjD7OMlYllsoNMvyHWXfu1
         4+rRCLdzrPbisPt5QQqN1KPvh6XvV1AQD7FOm45jloEe/7P07yhd1P8JV+kRNj6tnIBo
         G2kZdfHs8dL7mOQI7lzfWzdl91z6Sh7WAbr1z+yxOJo73FtImmLapNMpxdyVOFg5AXw6
         jY7MtqcVkSXRXmGOocpSds8iMqw9Z0huowKnsHmmeubevqDIly7ln2yosHZZPQ03t0BO
         E5koiyuSlDK0xVj1OdEvUAMUFoDvYeqPZq8/vlTgc+FkW0TwSJsWXnZeLmdRvqMQudnt
         Z5jA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dCpCcDFvoR9+HSv6sQpxss2RWZJqy9LXODB8bdbyS9U=;
        b=qc4ZhxS7Ds5VvqC50Qf/f5i2n/V8Kefd3x+UIxIFU/BEgixlWhQNZ7pJipbKGHaTCy
         4ZBENtQBm5ae5Yu+Zx+zZPPeCUX6z3c5olvQcSwvOTlsPKBcjLWChVm1g6eRnxvD0daa
         ZIO6dx87Xfm4H5NNr52bSMeb+CfAdnzLV8bxXQrpPtQhUSSqn+A1PBZ2thKrDZODxAsP
         8ngL8d0IaqqYGsDP8z6+gfzUlf2iA+mVhBojCgyoFgMRYueBpeD5vk5pjxEgPKTh6jDH
         6oPKBevtB05bzg5ZhrYMTtOpQh/4COTk4PR+1nQfPeJ7G2a3H7ezcz+LiklPuLrklqFO
         oaSw==
X-Gm-Message-State: APjAAAUWhjyIRaogJRumq+V5JzXLOQc8atM8OnRLCgpPUcbNQoJELWpV
	lQaouWzpBm9MmAWA2DMFJyI=
X-Google-Smtp-Source: APXvYqwfdE5PIPWQNK9LIaG3PUCTzmVl/Pqq/J75eFLCKF04gt1+aV7n6G0yebW51ExG+eXRfmfOnw==
X-Received: by 2002:a2e:9e97:: with SMTP id f23mr12812404ljk.89.1574437412846;
        Fri, 22 Nov 2019 07:43:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:86d5:: with SMTP id n21ls1551684ljj.16.gmail; Fri, 22
 Nov 2019 07:43:32 -0800 (PST)
X-Received: by 2002:a2e:994f:: with SMTP id r15mr12817516ljj.18.1574437412081;
        Fri, 22 Nov 2019 07:43:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574437412; cv=none;
        d=google.com; s=arc-20160816;
        b=LB5bpxinjK0fN0zW3El8y63Q5aLwOoJ3eY1BION5UnI7pSGInnW91v4PX4fPFYWr2X
         lYMk7ebKnS7hHPZzZoFeEsSoOaTBNpxt8ak4BK7hNB7gmeMkjaxD8n9efss1NXkzbYvc
         oBGahbqU4vzKccb3LAQBZMHtWD6jyIZH9qPs4DberYygrLrGFeg/Jv4l84RF63oBr0Qg
         lA6vMO8P7g8+o8OHMqkSrchZvjvLBFOXl4Ujtviv05OmLKejL66MyN3XUSoS/ugmTMdq
         uC+cce/Zw4+VO66NNB4yg/zRGaYG9JhjPyMS8K1PJ5xMnhmmBQ+bb0QfLlXvcwlsyYZl
         W82g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=UhG4TbrFQmzzMiP4BKNG5iQmKmV3aCdN4xUR1YDfRPM=;
        b=NFVHdzyEyl1+G+xyEoxCUqUajxx8sRIqY/3KV6vBuUso/lyK6UQAAc2Hrzy507lQQ/
         mB6f1Kl4B/2OOZm0P5zGYq4npOV2DLRCHiY5CSBMgw5zb7kCjp7eLj5WcOY3s8nJEWvm
         8reRvf3TAzlx8gCAfP2pFtQsobzb0UqaMzEWQAnUfh9KlcejpZcELNbI6vAvPWX34izN
         QAMUfkdj8oJKEmzTql020sqx1F1npJ0fh8OTHTXtVIQ/OkW3rSne0m8sNEFBMXF3PvVz
         ZXVFZqkdNW7RaCX/yQ9Sta+dbw8GEt3M4uH40IWq5WAxvVLY4tmXD+X1WYINNxtOGTJs
         Dpvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EgIhXGwx;
       spf=pass (google.com: domain of 3iwlyxqukcxwjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3IwLYXQUKCXwjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id f1si336272ljg.2.2019.11.22.07.43.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Nov 2019 07:43:32 -0800 (PST)
Received-SPF: pass (google.com: domain of 3iwlyxqukcxwjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id j12so4054222wrw.15
        for <kasan-dev@googlegroups.com>; Fri, 22 Nov 2019 07:43:32 -0800 (PST)
X-Received: by 2002:adf:ee92:: with SMTP id b18mr19174146wro.346.1574437411113;
 Fri, 22 Nov 2019 07:43:31 -0800 (PST)
Date: Fri, 22 Nov 2019 16:42:21 +0100
In-Reply-To: <20191122154221.247680-1-elver@google.com>
Message-Id: <20191122154221.247680-2-elver@google.com>
Mime-Version: 1.0
References: <20191122154221.247680-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH 2/2] kcsan: Prefer __always_inline for fast-path
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: will@kernel.org, peterz@infradead.org, boqun.feng@gmail.com, arnd@arndb.de, 
	dvyukov@google.com, linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org, 
	kasan-dev@googlegroups.com, paulmck@kernel.org, 
	Randy Dunlap <rdunlap@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EgIhXGwx;       spf=pass
 (google.com: domain of 3iwlyxqukcxwjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3IwLYXQUKCXwjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
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

Prefer __always_inline for fast-path functions that are called outside
of user_access_save, to avoid generating UACCESS warnings when
optimizing for size (CC_OPTIMIZE_FOR_SIZE). It will also avoid future
surprises with compiler versions that change the inlining heuristic even
when optimizing for performance.

Report: http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
Reported-by: Randy Dunlap <rdunlap@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
Rebased on: locking/kcsan branch of tip tree.
---
 kernel/kcsan/atomic.h   |  2 +-
 kernel/kcsan/core.c     | 16 +++++++---------
 kernel/kcsan/encoding.h | 14 +++++++-------
 3 files changed, 15 insertions(+), 17 deletions(-)

diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
index 576e03ddd6a3..a9c193053491 100644
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
index 3314fc29e236..c616fec639cd 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -78,10 +78,8 @@ static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS-1];
  */
 static DEFINE_PER_CPU(long, kcsan_skip);
 
-static inline atomic_long_t *find_watchpoint(unsigned long addr,
-					     size_t size,
-					     bool expect_write,
-					     long *encoded_watchpoint)
+static __always_inline atomic_long_t *
+find_watchpoint(unsigned long addr, size_t size, bool expect_write, long *encoded_watchpoint)
 {
 	const int slot = watchpoint_slot(addr);
 	const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
@@ -146,7 +144,7 @@ insert_watchpoint(unsigned long addr, size_t size, bool is_write)
  *	2. the thread that set up the watchpoint already removed it;
  *	3. the watchpoint was removed and then re-used.
  */
-static inline bool
+static __always_inline bool
 try_consume_watchpoint(atomic_long_t *watchpoint, long encoded_watchpoint)
 {
 	return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint, CONSUMED_WATCHPOINT);
@@ -160,7 +158,7 @@ static inline bool remove_watchpoint(atomic_long_t *watchpoint)
 	return atomic_long_xchg_relaxed(watchpoint, INVALID_WATCHPOINT) != CONSUMED_WATCHPOINT;
 }
 
-static inline struct kcsan_ctx *get_ctx(void)
+static __always_inline struct kcsan_ctx *get_ctx(void)
 {
 	/*
 	 * In interrupts, use raw_cpu_ptr to avoid unnecessary checks, that would
@@ -169,7 +167,7 @@ static inline struct kcsan_ctx *get_ctx(void)
 	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
 }
 
-static inline bool is_atomic(const volatile void *ptr)
+static __always_inline bool is_atomic(const volatile void *ptr)
 {
 	struct kcsan_ctx *ctx = get_ctx();
 
@@ -193,7 +191,7 @@ static inline bool is_atomic(const volatile void *ptr)
 	return kcsan_is_atomic(ptr);
 }
 
-static inline bool should_watch(const volatile void *ptr, int type)
+static __always_inline bool should_watch(const volatile void *ptr, int type)
 {
 	/*
 	 * Never set up watchpoints when memory operations are atomic.
@@ -226,7 +224,7 @@ static inline void reset_kcsan_skip(void)
 	this_cpu_write(kcsan_skip, skip_count);
 }
 
-static inline bool kcsan_is_enabled(void)
+static __always_inline bool kcsan_is_enabled(void)
 {
 	return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
 }
diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
index b63890e86449..f03562aaf2eb 100644
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
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191122154221.247680-2-elver%40google.com.
