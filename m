Return-Path: <kasan-dev+bncBAABBJVH3X2AKGQE7SJYMLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 17E731AB0C6
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 20:34:16 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id e18sf705592pfl.17
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 11:34:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586975654; cv=pass;
        d=google.com; s=arc-20160816;
        b=wtHrhOAAyHp6sPUuNUjBAZyRM8Z+wisCsHTIoW2ukzwiLERxMA/UtvvRNgmFVFuTHb
         DGYSDRQWO0boPBxwZNDTWEWmWXxih5D+YO3gIyUblrSoqqQEEONa3r2l7WjFAXfmfiu8
         QXBhP818/EBkvqZoWPrGX6VtXa7oXfF8M6bMj7itQ9R4HNLYEH6aKb26EN/1MJe9OBDo
         lTiK8N1Wh3iZuaTp1/nAttB9GUgplkYWuWUTdGSl/lsk//6CeVs20F2oioKRBQwIYecz
         gVUocycCgaqbA+LjCKQEtSE7I81XqgZrK4Sh99f3x285kjCw2zEn4+vxkuGCu2F5LNeM
         OJWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=Q0S3NbKNVut3IeFl+0YrOpiaEv48I1OxOKgeHCxXoEo=;
        b=ChJCUW9oi7XndvKavOKRSnIzyFhQfLKq4p8gdqNHiODRQyVB8W2fxadW1jPU4JEOtu
         QQYqa+IDqcEQgM+CBOVY/tpTr3RA9Xlz4yp8DFMO/tMMiwxNkcJKKqD7r0xtGKbConlz
         /F0fgrfE76cXi0qL6sr/EQReuzoKh/WOgyYTOOJmy1XD/xfl1Ct42gxmrpOCeIK/YZDv
         QxKg8tN7LPUmHGCU8F+YDqw03xeihOMTUYi3yRYwsJZ97KaMm7GDvGH7OM3RtsEddja0
         deQMs2cflOrfkzzZFMdVPDE4TSY3Y+vYGPQwFyNaTS3FaOUIDn6kB/al3uMyeIDxTcsG
         pLwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=EdjBUZSO;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q0S3NbKNVut3IeFl+0YrOpiaEv48I1OxOKgeHCxXoEo=;
        b=QFNgwDxwhc2DJ0Xqpvgmf3EP9tdWhEi4rg72fiYaLq4tsTnKEGwPMdkOc3vvtMkkXT
         lqifiNkBumA3Cis4yofUKQjrUkCmQQwNE7qokC/dGvfgeRo0ESamrw/XiobNIFt5GdLO
         W1n3oRuOEJlFbiFBSwslkv07ZsWXJQ0n9oY1s21cGqooBWLKbiLmhYGZtn83oG9NkQz/
         ll+R/cCTFJtEZRu6Zy1WFKu+FVRCyRnH7xthCfESzCghdEBcl0PE0klP3NR9YLc+Jq9s
         5zxHP/fYeOtZGin1U7QM6HU+Jy2YkVGX0drCQcx/rbQLi/6QOA8RvmzD1GxYD01meWt8
         0aFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q0S3NbKNVut3IeFl+0YrOpiaEv48I1OxOKgeHCxXoEo=;
        b=LiQuwbjJm4mEFdvbTPIHpU5Q6RBIubPDkaTBoCi8h86QruJigEoUvWRaBtReS5d+H7
         XafYK3ZClHtKPfE943BHgutERPnpZHAIugxw5cyZ3/a1wI7VzZPmQPNXjx4tNz+U5dVo
         HyEoIy7tpOtR0adiMz3NH58puvzpUjlJDBJoDzOilgxlW+sNhjAqtxeSd9wWOVSWJXvm
         noyFKfGxXu65qiFw5K4+K4DTCzt4mRORsKie99OSbMEv5dwhtV2b+B6uL9HY7ECh+hv7
         qS1kpOWkDWygJL9nvM/jKNQv69IHocCLTo4zYWeC0U+5f1mi0w2yUImDD536lAvTNlEW
         refw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZduPf7exxoqjdhg+gA7AGN2OTC9jpcJAYCAgOMwz+sRAG9shgJ
	8b3FAV5+w074vgxQgeB3ndI=
X-Google-Smtp-Source: APiQypLKnIdHMLrDkLAntKTv7oHGpp/rBb5/AQ99KbGOMKYVtXdZtqh3SDbbAPztYBQ8YGpxYPoXbQ==
X-Received: by 2002:a17:90a:23a3:: with SMTP id g32mr647179pje.78.1586975654374;
        Wed, 15 Apr 2020 11:34:14 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:fb01:: with SMTP id o1ls5830384pgh.3.gmail; Wed, 15 Apr
 2020 11:34:14 -0700 (PDT)
X-Received: by 2002:a65:5a8b:: with SMTP id c11mr20344476pgt.215.1586975654035;
        Wed, 15 Apr 2020 11:34:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586975654; cv=none;
        d=google.com; s=arc-20160816;
        b=OYm80E/pX2BiPeKY84ifGrwWnDoTUHHJlDUC7/n7i0QNIxfzM3yuJjGNccVdgIIex5
         T0lfbHBE+lJAOF2+0PobFioIujJXIOsX+hKvU9uvi1i8LEMgNVBGDesjsboPN8fQs3tF
         fquBmQA5jTA0IpINBpxCmhxQA2KkZo4MLQtYeLGqFoD2s01cybfUMd8MIJNkpdv3qOAK
         JMg66P5iVhPQN52pby+jBQifbRZNm9Jmy8uEcfDyvEtQcJaPNxvXW+IovTp7CkqTwV4S
         H7gWQWf5yJa64XWKrcTtXsX8qcGn5HFpLTsOqjTxR2cbwFZ3RYnQYtQ1dvvGXU/HUY25
         KwUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=F5qquXZYYEz2Mdo4QrMw9S6XTuVoqzwgE6HNDwY41DE=;
        b=ErdqEuFk8cqsVihOhRdFl48v8JdzfdYsjACcPthshzrKqPwaDu504KAbbr500VFFDi
         P2BSJHuknkIaAHmwal2pBs+rvPJotz220c23R8Zfq0zjs9Z2UT4jF8mCOsdGWpN0G7bz
         oXkulp82qbTFLQ5op+wRaeK2qCSfLfG9Y6dSrOCaIWC/nooYzwkijwx6Ml70lLlAwIPr
         ae4nqdYAS3gRs03HQxSfF4BlQiBioApnJHhQpmt4/GbbIvsWAl0fzL0Mc3E6EwK9zl+E
         Xk4tXorrYqOTu5Sio5AHfZabxB+ZjKS2DLhEOYUQ8jv7ui1+VdABKuwR9yHP+RjTUQPG
         7I6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=EdjBUZSO;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g23si1447997pgi.5.2020.04.15.11.34.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 11:34:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A0D7F2166E;
	Wed, 15 Apr 2020 18:34:13 +0000 (UTC)
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
Subject: [PATCH v4 tip/core/rcu 03/15] kcsan: Add current->state to implicitly atomic accesses
Date: Wed, 15 Apr 2020 11:33:59 -0700
Message-Id: <20200415183411.12368-3-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200415183343.GA12265@paulmck-ThinkPad-P72>
References: <20200415183343.GA12265@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=EdjBUZSO;       spf=pass
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

Add volatile current->state to list of implicitly atomic accesses. This
is in preparation to eventually enable KCSAN on kernel/sched (which
currently still has KCSAN_SANITIZE := n).

Since accesses that match the special check in atomic.h are rare, it
makes more sense to move this check to the slow-path, avoiding the
additional compare in the fast-path. With the microbenchmark, a speedup
of ~6% is measured.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/atomic.h  | 21 +++++++--------------
 kernel/kcsan/core.c    | 22 +++++++++++++++-------
 kernel/kcsan/debugfs.c | 27 ++++++++++++++++++---------
 3 files changed, 40 insertions(+), 30 deletions(-)

diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
index a9c1930..be9e625 100644
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
index 065615d..eb30ecd 100644
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
index 2ff1961..72ee188 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415183411.12368-3-paulmck%40kernel.org.
