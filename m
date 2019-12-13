Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJHTZ7XQKGQEKU32TEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5583511EC0D
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 21:50:46 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id g26sf35954wmk.6
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 12:50:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576270246; cv=pass;
        d=google.com; s=arc-20160816;
        b=EAjCwIqIya+3VFaCQ4MGxXncO/8kJld1GrGQOkM3YLLhEnO8b06A8W8SocaCJm9tV3
         MraB+bP5TNHIsrLu3MyI2oYUHl8ordJUl0ANdLVcOcOKdvKoVVGx5AID1b1BqgbyjxS7
         dRHX50sEcIgHqN3zj27tniVO9F+6Fcvi+sDhEPeTLwojxv9hJQh3wt2AqjXadnobNrNR
         lJrahtN+rAxG93c5RkKsteiI9ilwkw/i3wazzqOKzZd0qxaIgkotCQx/fX/Q5TT4Gmfa
         T6vbo1DelnXxqCMmRWEcfm2gI+6CRg7kDF/MqNANcdH7l4IFEon1PVAzC3Kf1PxBYWF5
         y5TA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=9E5crYpgs978oMLi0Bi1Ubaj/JJzDEfPUzHWQxsQX9A=;
        b=kpfGkRAVHsiE2HpirnC7BsK5juwwID2A/8ZRhJlXsIZ1khBTzyxtnS78De7bQ84dbC
         pubG/9b0ujM7y8vQaYlirIIyX+MLuIcmKvhPLEA8jmKuQw60t1xHQxbQDg4r8nEcf0Tm
         W9f7B9yuqeuFOL4nJXkuFdnTgKmeA2xIErLJm2BVYWb7p2QF4Ea3z73wDMcnUYNV4SiB
         aNSJy3/xr8Ac0H9CNRZWoIIK2psT4zZsVFW0dzfA8bkrSXGllfvttaSkJloJigz/6dhH
         sl0NIBSE2Rh2yjN50H1W1jyDZWOfEtHZ4eH/9tGYpVA7itbqKuZe4POoOe56YRJa4p5Y
         3GUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N3yH+STX;
       spf=pass (google.com: domain of 3o_nzxqukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3o_nzXQUKCVw8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=9E5crYpgs978oMLi0Bi1Ubaj/JJzDEfPUzHWQxsQX9A=;
        b=IkAIKuCtj9Z+zjClNoF2lh628Hamis5AbNevaksx3qNnaUgdCjYEy4FpZaQ+QN1Gob
         Mi9QELAcTq15w4/eS5AycMchXHejI2IOVe75FB2sWu25AYKo3ABiF7kB9NpsQJzR3UZt
         sbNQXE32gbvibJX79GV1IUckMg7vq8sM2OZhuW4POhCVjfdnYWpKYTBYvp4Cwm9SbWMw
         CJ4H4mdMutEMan4P5gGn7e5X1gSzlZmqgZ7RkYIzr6r5mjOSTyeds7j4mtVUU9LJKCVj
         9rtvDEMe+zwfLyyTLnrz8o8IAStc5BVK5e1mj6kV4Vu95TjiO/4r/zTT9S9mU+zv/kx2
         BJYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9E5crYpgs978oMLi0Bi1Ubaj/JJzDEfPUzHWQxsQX9A=;
        b=T3metQmJE3mYrdcJ857gxfTelQCl1B81A7L1oo7mLGCafefHSR9pWl1XaEAY8qCJFy
         0Cq/L2/dmima8ufs0oazYkG8SD0a9+t7ur81ZBafAxVUfJjx2Pq0LuDTDi+VddYvhX8w
         6VRU9BRVJr1Px4U5ziVSPHRVFWX4NQfCEmRuzH+aclY11oU9Hma/YdNkWWjSGiBzbNnB
         VwbCTJ09295P1j4gg+yekJbfe6BRz7SFqPSGMKVKI6LLOcPAL59SPeE0y33koe2O8HxM
         XPepDNuQh3AnC9aIil01sx+KaRUTutAuDfq96ojoPd/gBJeEYaWPcgM3fRUqWCKxucZn
         F/0Q==
X-Gm-Message-State: APjAAAWCoy6IvrxNDfKs959xF0Kqllw4hOh6M4d9OK4lIqptMduG7/Gh
	V54zRFDRxTHWpiXFchcT23s=
X-Google-Smtp-Source: APXvYqxVscwD0qSW1ZVPgyzWecvM/meeGSJL0fN5M0m20F7RaYu06bMMaVqTSYWXxPjFHfrek8aZjw==
X-Received: by 2002:a5d:494b:: with SMTP id r11mr14967314wrs.184.1576270245037;
        Fri, 13 Dec 2019 12:50:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7ec9:: with SMTP id z192ls5392837wmc.5.gmail; Fri, 13
 Dec 2019 12:50:44 -0800 (PST)
X-Received: by 2002:a1c:f70d:: with SMTP id v13mr13483861wmh.44.1576270244416;
        Fri, 13 Dec 2019 12:50:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576270244; cv=none;
        d=google.com; s=arc-20160816;
        b=pz5akudo9BR6gGOgspB8NbciBFYumNQ607azWeWmgg5PtMQ1vQuamF2G/b/HrK3rzi
         GotOIjwm1zU/jJQoL2t52IeUZKkkLSiGj2nuEelMOpQg71WcgOi85O4mIl0ZV4BnAHIf
         Gb8k4kGg6Z+npymYsRbTyW3XQ0Vk54pVQYfRnPKSEsLptcIVel8RstAMddzWER3OvTYB
         M7eKNKSk6IrCxoHn1P1odTlPCD8l+/kVs5BT4TpkcXwvEiiGBOWFfuN3JYcMDIRzkBL6
         0eplvKDdlxfCmBtQYwZ8bA0w9c4rjxjXBR2W5AT54LCgnkvDgxp8MF7GAOZb0Ga9ncKP
         GXJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=a1jdZmOtDq0rK4AdE9X1BQB4Chvj4FuBPej3mFQLPjk=;
        b=aqJuvOF1i7m+tszb4/do1dyrO0H5uxcmC/e5Nr5eP1RFAd22BQdoMNIU0FOV2lJRQJ
         E31tH/hFRRzaye0LvIMwPnU4xYGHEEaJLsE4cEg8Nc/l0d8yR9rV1WjM/uewvvkJT39r
         gXL1YJqQUUkzDGVVS7w8Rn9J6xLZ3iEzYcreEgIOmXnyyOEU2gULJhPgCQHUHIP3Luvz
         kbvki/cRCWC6XSJjNKND5WSy+JreMJDkNHCqWLix52Ipf32gnYmgvWeIy+AjKNZWoS5b
         xVZqqW7AlIm2DCb10LBkpsnXTHTZGe2hZhoKNxK5C0kyqs0mYYqF5NZYoaTy9UAwck+K
         AgJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N3yH+STX;
       spf=pass (google.com: domain of 3o_nzxqukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3o_nzXQUKCVw8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id a138si426975wmd.1.2019.12.13.12.50.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Dec 2019 12:50:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 3o_nzxqukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id y7so61873wrm.3
        for <kasan-dev@googlegroups.com>; Fri, 13 Dec 2019 12:50:44 -0800 (PST)
X-Received: by 2002:adf:dc86:: with SMTP id r6mr15819986wrj.68.1576270243820;
 Fri, 13 Dec 2019 12:50:43 -0800 (PST)
Date: Fri, 13 Dec 2019 21:49:46 +0100
Message-Id: <20191213204946.251125-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.24.1.735.g03f4e72817-goog
Subject: [PATCH RESEND -rcu/kcsan] kcsan: Prefer __always_inline for fast-path
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, dvyukov@google.com, 
	Randy Dunlap <rdunlap@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=N3yH+STX;       spf=pass
 (google.com: domain of 3o_nzxqukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3o_nzXQUKCVw8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
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
Acked-by: Randy Dunlap <rdunlap@infradead.org> # build-tested
Signed-off-by: Marco Elver <elver@google.com>
---
Version rebased on -rcu/kcsan.

There are 3 locations that would conflict with the style cleanup in
-tip/locking/kcsan:
https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/commit/?h=locking/kcsan&id=5cbaefe9743bf14c9d3106db0cc19f8cb0a3ca22

For the conflicting locations the better style is carried over, so that
upon eventual merge the resolution should be trivial.
---
 kernel/kcsan/atomic.h   |  2 +-
 kernel/kcsan/core.c     | 17 ++++++++---------
 kernel/kcsan/encoding.h | 11 +++++------
 3 files changed, 14 insertions(+), 16 deletions(-)

diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
index c9c3fe628011..466e6777533e 100644
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
index d9410d58c93e..69870645b631 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -78,9 +78,8 @@ static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS - 1];
  */
 static DEFINE_PER_CPU(long, kcsan_skip);
 
-static inline atomic_long_t *find_watchpoint(unsigned long addr, size_t size,
-					     bool expect_write,
-					     long *encoded_watchpoint)
+static __always_inline atomic_long_t *
+find_watchpoint(unsigned long addr, size_t size, bool expect_write, long *encoded_watchpoint)
 {
 	const int slot = watchpoint_slot(addr);
 	const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
@@ -150,8 +149,8 @@ static inline atomic_long_t *insert_watchpoint(unsigned long addr, size_t size,
  *	2. the thread that set up the watchpoint already removed it;
  *	3. the watchpoint was removed and then re-used.
  */
-static inline bool try_consume_watchpoint(atomic_long_t *watchpoint,
-					  long encoded_watchpoint)
+static __always_inline bool
+try_consume_watchpoint(atomic_long_t *watchpoint, long encoded_watchpoint)
 {
 	return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint,
 					       CONSUMED_WATCHPOINT);
@@ -166,7 +165,7 @@ static inline bool remove_watchpoint(atomic_long_t *watchpoint)
 	       CONSUMED_WATCHPOINT;
 }
 
-static inline struct kcsan_ctx *get_ctx(void)
+static __always_inline struct kcsan_ctx *get_ctx(void)
 {
 	/*
 	 * In interrupt, use raw_cpu_ptr to avoid unnecessary checks, that would
@@ -175,7 +174,7 @@ static inline struct kcsan_ctx *get_ctx(void)
 	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
 }
 
-static inline bool is_atomic(const volatile void *ptr)
+static __always_inline bool is_atomic(const volatile void *ptr)
 {
 	struct kcsan_ctx *ctx = get_ctx();
 
@@ -199,7 +198,7 @@ static inline bool is_atomic(const volatile void *ptr)
 	return kcsan_is_atomic(ptr);
 }
 
-static inline bool should_watch(const volatile void *ptr, int type)
+static __always_inline bool should_watch(const volatile void *ptr, int type)
 {
 	/*
 	 * Never set up watchpoints when memory operations are atomic.
@@ -232,7 +231,7 @@ static inline void reset_kcsan_skip(void)
 	this_cpu_write(kcsan_skip, skip_count);
 }
 
-static inline bool kcsan_is_enabled(void)
+static __always_inline bool kcsan_is_enabled(void)
 {
 	return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
 }
diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
index e17bdac0e54b..e527e83ce825 100644
--- a/kernel/kcsan/encoding.h
+++ b/kernel/kcsan/encoding.h
@@ -58,9 +58,8 @@ static inline long encode_watchpoint(unsigned long addr, size_t size,
 		      (addr & WATCHPOINT_ADDR_MASK));
 }
 
-static inline bool decode_watchpoint(long watchpoint,
-				     unsigned long *addr_masked, size_t *size,
-				     bool *is_write)
+static __always_inline bool
+decode_watchpoint(long watchpoint, unsigned long *addr_masked, size_t *size, bool *is_write)
 {
 	if (watchpoint == INVALID_WATCHPOINT ||
 	    watchpoint == CONSUMED_WATCHPOINT)
@@ -77,13 +76,13 @@ static inline bool decode_watchpoint(long watchpoint,
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
2.24.1.735.g03f4e72817-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191213204946.251125-1-elver%40google.com.
