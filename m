Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI7A2TZAKGQEF6WBGJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7078916C3F4
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2020 15:33:07 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id y23sf9271560edt.2
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2020 06:33:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582641187; cv=pass;
        d=google.com; s=arc-20160816;
        b=jR8mV4acdVFpcbeHmV0I+TSHqWOMJZu52LvK6ixnEioiR4MNEGIJwkdByuyuCRGIyd
         ewXUP6mC0eyGw2qTRSA1S2vP32wrOP3PR9MiOXBqCI5//7tQX32eqLR4wKxgh3yTEMIB
         dI4U0/q68i9tJNGbljWVGh6HM40ksD8ZHk16zuWhg2INnDQmctobzvokFD804XcMp6Iw
         Ayyq7jRfVw4rzbImmODIBCSjGinE3EZDt5IF1OkN124n6bYLr4OXIxya2vVBvC0NZdx7
         Xeo8QpgdKCeZiOyprjd4X6c9t8cIRnm3PzITFbO/owdXn6UnIAw7QmRDMGPpL49inXtZ
         m4TA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=YSCm5MJLy5AYMoMdFjKhpWme2hhw8wY2jt77jzL8s4c=;
        b=xjfvIz7rhdWT45+OjdX8GQ4o/cgR3e+fsyWtqSl7KsDOo4/+1FHk5Efqbfm0HRbTBL
         i7tBRF0MK96OZgnV21+A4a6ESblr/L+u8/h3kPi/3UQofddb7MtDlz/mZXDLLOnm9Cj9
         cXHeDWt+1ZRKskppIc9XVR1rnd9xm4yGUJEs+EJIgZ3kPHv8xdrlhCy3DUBMA+letjE3
         QehK8rZE06HyUONPYgjnvnc5kpnwv9F/E7DSC5htpyBPij3Mfc9Tbl5YE5FH6v3tXHwD
         5EaregeMP5BQk2oD1hpNsyfSNrfPUiEAcNdekgd3kTm09X90sizcVeN98Htd+p4VmAKc
         NddQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jfC5okCc;
       spf=pass (google.com: domain of 3itbvxgukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ITBVXgUKCc4y5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=YSCm5MJLy5AYMoMdFjKhpWme2hhw8wY2jt77jzL8s4c=;
        b=O/bTLFoHzqrCwWL1W1CjdL29lYX9egOFFw/0b+NdmzXUR2f+dGutNrtsuJu4HauOHj
         ei1qiA+bTtJRtJGBY2Ly8xLIeVGZfO2O5rX1FZV4pZ1yppeI3oEVq0FCTYcmECaW0/lp
         AzmqE+BvxjzVkzvOJewrOdW5AejOpvkV/bVVsGGchOm4xSsV54ZQMuHdmk0VlzgUrirr
         ls4qR5JmV9nEXbBP1Vy7Nr/czY5exMj6IUr2ssLXbZlzP9TWMRiUtWtLfKvgxOQwHT7/
         NoIMU7TAypj9vB2ogTEKBtK3NgAsj9smBqGRGRX1P454G3U4vdN10JUx5Ny2wTX3h9n8
         +h+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YSCm5MJLy5AYMoMdFjKhpWme2hhw8wY2jt77jzL8s4c=;
        b=RGqwUssfDAbdwdNZnWSvnlI+y/byIdJkVPu3cXC/JC9hS/f4EVGRcRp9moZblzAS88
         Gpb8G6SJAKbfsLdUao0S61WpLF+4MY8GHPKsSB8cMyh+cz9YAdtktK/OPSjdgnlucq+o
         OnLVRvVhJM9gYagHhjft+ng4WV1kgPwERkx+3xA4KJDtQU8ZtULrNNwWzP8LkhM4uBj2
         TAlerKSwBuE+FIp1/UZCKgkE5yYb4U06zL4AUOMjK96bebHpizacqXzDWLYTKKxDcjf5
         PWPwtJJINg00sAVcM9ywdkBX9xlHBUJ4ieQnAZluRBSUVZQETqHI5PSCobdju5HglsRw
         4OIQ==
X-Gm-Message-State: APjAAAWE8C3MHfMcPA2cj6L3i29Oegvg6fiUUGG7A2N288TNP4pBhZ0Z
	vxbxMmqP7iTmjo2ZcAGbGm8=
X-Google-Smtp-Source: APXvYqwXlTanJQBz9IClulEQS//QvG0UUilBknbp05sIZbqzgD3hav0rYgtV/ItDwSQpNZvnmymG6Q==
X-Received: by 2002:a17:906:1697:: with SMTP id s23mr54153860ejd.355.1582641187144;
        Tue, 25 Feb 2020 06:33:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:de05:: with SMTP id h5ls4719500edv.3.gmail; Tue, 25 Feb
 2020 06:33:06 -0800 (PST)
X-Received: by 2002:aa7:ccc7:: with SMTP id y7mr53391740edt.45.1582641186420;
        Tue, 25 Feb 2020 06:33:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582641186; cv=none;
        d=google.com; s=arc-20160816;
        b=NH1bPMziUVixyG4l+irnCWExYPpj5O4gba/KU8vAkzs7np/LjHiQbW0x0i9WaXzOvm
         VWnv9i0+z5o0AKBsPlATqgcB00SMw5yxlq8NQzdkT+YKSvCBbqSxdb/02N+XARlgVaOC
         AtjJXyEUzC2R4E+k5YrvfuTdI2OFDeSBGPcXlJIl+i+L27+q3gVcZmQH2OzYjnik+3Df
         BJi82YaFDG7+qSy7CRTOYEvN4yHmWB+8/JkPhcnS9ReSm6yT+Lq1lRZfrhp1SMAoVpH5
         +H6kelmlXnWYvanrr6cCF5dTO41D9xBClMwjARpWP9F4rqEeVknPYgs9LNxpjHnmMJO8
         2YQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=K+gSCW97RfUzEfcHuqWjNaS4orn1ZLbZApAUp8Q7WZI=;
        b=bLIFgCNTq3gpqEuvSEoKzw1Pr2h1Y1TxwaJFk9L4NN0sJaX8iPxvh98BTIItJgWITZ
         rxcbipwd4BPDA/15buJunpz61dhwxXPJmAxqsavY+Lk8+nXSqt7NcRSM3yZHzzgjuuTQ
         BDs/chr325wvUH11/NTGILCO8dZjyb9TeyRYFL4DCsATjpE9U1SyP/RqeEs9PPrhK1oh
         PdEm8bWHNgUSPqj90+QLMxh0c7OoiMtxKZHFd9KzstSUMCU2p1tD3L5RCIG1FGkdBsAc
         hAd/w0zRYW03cgCg3pAFl8dAmdeBeHZZ0uomR8QKhoM8cR5VEzmkXFY1QAoLXd/24b3Z
         9E9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jfC5okCc;
       spf=pass (google.com: domain of 3itbvxgukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ITBVXgUKCc4y5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id d29si1047973edj.0.2020.02.25.06.33.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Feb 2020 06:33:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3itbvxgukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id l1so7432521wrt.4
        for <kasan-dev@googlegroups.com>; Tue, 25 Feb 2020 06:33:06 -0800 (PST)
X-Received: by 2002:adf:ce87:: with SMTP id r7mr72959617wrn.245.1582641185618;
 Tue, 25 Feb 2020 06:33:05 -0800 (PST)
Date: Tue, 25 Feb 2020 15:32:58 +0100
Message-Id: <20200225143258.97949-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH] kcsan: Add current->state to implicitly atomic accesses
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jfC5okCc;       spf=pass
 (google.com: domain of 3itbvxgukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ITBVXgUKCc4y5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
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

Add volatile current->state to list of implicitly atomic accesses. This
is in preparation to eventually enable KCSAN on kernel/sched (which
currently still has KCSAN_SANITIZE := n).

Since accesses that match the special check in atomic.h are rare, it
makes more sense to move this check to the slow-path, avoiding the
additional compare in the fast-path. With the microbenchmark, a speedup
of ~6% is measured.

Signed-off-by: Marco Elver <elver@google.com>
---

Example data race that was reported with KCSAN enabled on kernel/sched:

write to 0xffff9e42c4400050 of 8 bytes by task 311 on cpu 7:
 ttwu_do_wakeup.isra.0+0x48/0x1f0 kernel/sched/core.c:2222
 ttwu_remote kernel/sched/core.c:2286 [inline]
 try_to_wake_up+0x9f8/0xbe0 kernel/sched/core.c:2585
 wake_up_process+0x1e/0x30 kernel/sched/core.c:2669
 __up.isra.0+0xb5/0xe0 kernel/locking/semaphore.c:261
 ...

read to 0xffff9e42c4400050 of 8 bytes by task 310 on cpu 0:
 sched_submit_work kernel/sched/core.c:4109 [inline]  <--- current->state read
 schedule+0x3a/0x1a0 kernel/sched/core.c:4153
 schedule_timeout+0x202/0x250 kernel/time/timer.c:1872
 ...
---
 kernel/kcsan/atomic.h  | 21 +++++++--------------
 kernel/kcsan/core.c    | 22 +++++++++++++++-------
 kernel/kcsan/debugfs.c | 27 ++++++++++++++++++---------
 3 files changed, 40 insertions(+), 30 deletions(-)

diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
index a9c1930534914..be9e625227f3b 100644
--- a/kernel/kcsan/atomic.h
+++ b/kernel/kcsan/atomic.h
@@ -4,24 +4,17 @@
 #define _KERNEL_KCSAN_ATOMIC_H
 
 #include <linux/jiffies.h>
+#include <linux/sched.h>
 
 /*
- * Helper that returns true if access to @ptr should be considered an atomic
- * access, even though it is not explicitly atomic.
- *
- * List all volatile globals that have been observed in races, to suppress
- * data race reports between accesses to these variables.
- *
- * For now, we assume that volatile accesses of globals are as strong as atomic
- * accesses (READ_ONCE, WRITE_ONCE cast to volatile). The situation is still not
- * entirely clear, as on some architectures (Alpha) READ_ONCE/WRITE_ONCE do more
- * than cast to volatile. Eventually, we hope to be able to remove this
- * function.
+ * Special rules for certain memory where concurrent conflicting accesses are
+ * common, however, the current convention is to not mark them; returns true if
+ * access to @ptr should be considered atomic. Called from slow-path.
  */
-static __always_inline bool kcsan_is_atomic(const volatile void *ptr)
+static bool kcsan_is_atomic_special(const volatile void *ptr)
 {
-	/* only jiffies for now */
-	return ptr == &jiffies;
+	/* volatile globals that have been observed in data races. */
+	return ptr == &jiffies || ptr == &current->state;
 }
 
 #endif /* _KERNEL_KCSAN_ATOMIC_H */
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 065615df88eaa..eb30ecdc8c009 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -188,12 +188,13 @@ static __always_inline struct kcsan_ctx *get_ctx(void)
 	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
 }
 
+/* Rules for generic atomic accesses. Called from fast-path. */
 static __always_inline bool
 is_atomic(const volatile void *ptr, size_t size, int type)
 {
 	struct kcsan_ctx *ctx;
 
-	if ((type & KCSAN_ACCESS_ATOMIC) != 0)
+	if (type & KCSAN_ACCESS_ATOMIC)
 		return true;
 
 	/*
@@ -201,16 +202,16 @@ is_atomic(const volatile void *ptr, size_t size, int type)
 	 * as atomic. This allows using them also in atomic regions, such as
 	 * seqlocks, without implicitly changing their semantics.
 	 */
-	if ((type & KCSAN_ACCESS_ASSERT) != 0)
+	if (type & KCSAN_ACCESS_ASSERT)
 		return false;
 
 	if (IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) &&
-	    (type & KCSAN_ACCESS_WRITE) != 0 && size <= sizeof(long) &&
+	    (type & KCSAN_ACCESS_WRITE) && size <= sizeof(long) &&
 	    IS_ALIGNED((unsigned long)ptr, size))
 		return true; /* Assume aligned writes up to word size are atomic. */
 
 	ctx = get_ctx();
-	if (unlikely(ctx->atomic_next > 0)) {
+	if (ctx->atomic_next > 0) {
 		/*
 		 * Because we do not have separate contexts for nested
 		 * interrupts, in case atomic_next is set, we simply assume that
@@ -224,10 +225,8 @@ is_atomic(const volatile void *ptr, size_t size, int type)
 			--ctx->atomic_next; /* in task, or outer interrupt */
 		return true;
 	}
-	if (unlikely(ctx->atomic_nest_count > 0 || ctx->in_flat_atomic))
-		return true;
 
-	return kcsan_is_atomic(ptr);
+	return ctx->atomic_nest_count > 0 || ctx->in_flat_atomic;
 }
 
 static __always_inline bool
@@ -367,6 +366,15 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	if (!kcsan_is_enabled())
 		goto out;
 
+	/*
+	 * Special atomic rules: unlikely to be true, so we check them here in
+	 * the slow-path, and not in the fast-path in is_atomic(). Call after
+	 * kcsan_is_enabled(), as we may access memory that is not yet
+	 * initialized during early boot.
+	 */
+	if (!is_assert && kcsan_is_atomic_special(ptr))
+		goto out;
+
 	if (!check_encodable((unsigned long)ptr, size)) {
 		kcsan_counter_inc(KCSAN_COUNTER_UNENCODABLE_ACCESSES);
 		goto out;
diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 2ff1961239778..72ee188ebc54a 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -74,25 +74,34 @@ void kcsan_counter_dec(enum kcsan_counter_id id)
  */
 static noinline void microbenchmark(unsigned long iters)
 {
+	const struct kcsan_ctx ctx_save = current->kcsan_ctx;
+	const bool was_enabled = READ_ONCE(kcsan_enabled);
 	cycles_t cycles;
 
+	/* We may have been called from an atomic region; reset context. */
+	memset(&current->kcsan_ctx, 0, sizeof(current->kcsan_ctx));
+	/*
+	 * Disable to benchmark fast-path for all accesses, and (expected
+	 * negligible) call into slow-path, but never set up watchpoints.
+	 */
+	WRITE_ONCE(kcsan_enabled, false);
+
 	pr_info("KCSAN: %s begin | iters: %lu\n", __func__, iters);
 
 	cycles = get_cycles();
 	while (iters--) {
-		/*
-		 * We can run this benchmark from multiple tasks; this address
-		 * calculation increases likelyhood of some accesses
-		 * overlapping. Make the access type an atomic read, to never
-		 * set up watchpoints and test the fast-path only.
-		 */
-		unsigned long addr =
-			iters % (CONFIG_KCSAN_NUM_WATCHPOINTS * PAGE_SIZE);
-		__kcsan_check_access((void *)addr, sizeof(long), KCSAN_ACCESS_ATOMIC);
+		unsigned long addr = iters & ((PAGE_SIZE << 8) - 1);
+		int type = !(iters & 0x7f) ? KCSAN_ACCESS_ATOMIC :
+				(!(iters & 0xf) ? KCSAN_ACCESS_WRITE : 0);
+		__kcsan_check_access((void *)addr, sizeof(long), type);
 	}
 	cycles = get_cycles() - cycles;
 
 	pr_info("KCSAN: %s end   | cycles: %llu\n", __func__, cycles);
+
+	WRITE_ONCE(kcsan_enabled, was_enabled);
+	/* restore context */
+	current->kcsan_ctx = ctx_save;
 }
 
 /*
-- 
2.25.0.265.gbab2e86ba0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200225143258.97949-1-elver%40google.com.
