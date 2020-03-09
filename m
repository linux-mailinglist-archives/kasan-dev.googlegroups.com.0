Return-Path: <kasan-dev+bncBAABBPVGTLZQKGQE2HH7G7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3d.google.com (mail-yw1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id D7D0C17E7E1
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:31 +0100 (CET)
Received: by mail-yw1-xc3d.google.com with SMTP id o79sf17031355ywo.14
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780671; cv=pass;
        d=google.com; s=arc-20160816;
        b=ff0TtJC4o5VACztNAtmZuTY4EeQhYa7lQxgnDChvO6hyJ8xm8UCsuvtGWfoS4sOBT9
         jqjth/nWsIB6mvZPDqhhtBoNEgNyeJV/qjwAR5C4XRrJ3uEpBP516PfKANjv9X3J9/zZ
         nqAdtkrgcqZHST7IsE4Y7Y6GXnuisjYmj8JRcou/KvPeIu3YyedvXG6yh05z2a0yhP3D
         9ye+52p1y0a6bSV6zoNNhFEdvH3VWU70bShpnZEjGKvDRI7XYdcpW+gCrXjbDC13is6H
         O3ywIq4ggAbQz7pMEhX+Aw0JUoaK227J/QKiHF7NxntXRzsL/z1ZGFpH5gtAvOf6uK4Y
         +vvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=f3TCJn6oVzvhj2VN/FM6sVmqMSxbdkDBrpKqU9IYSZk=;
        b=SYtVsPfnrXi7ZU3chc8v4XDlLdNAdcWdpvxaedUZ96eqlYaPA9Rqi3lp/DR/h1YXK/
         NSUB1ZoTCTINuo6s3peOlxBmVKLWitovWeSukxt/u06ylP8f7RDRU4v3ApDfHlyvUbDM
         cwSGmJ1v5gb2SgVXbFzXQvqYFZ1mmRCIsI3L8gpPsVxjY2ny1EJ2isQZltzCYqI3ktbn
         Rw3uUBdxLJbzpxD1S36TMfgaiIVKZ1DX+7DlFZpaPrj1jJkwx5ItASR6P3YCY5PHohkl
         GbEfQTrAXWU+O5cSbZeUCRQB26gXacEpHh2or/4h2KhoIGPgKtwlTPrhfuU7rEjLy2qz
         yG1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=FEqXJuAz;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f3TCJn6oVzvhj2VN/FM6sVmqMSxbdkDBrpKqU9IYSZk=;
        b=tLFDLFCBgwerHaZGshpxMry65RGBazw0bIoL7KMrtJnn6s6MGuhvdj66EgMvUm0Yi+
         WF53Uk42ri7LBb3hVAsNSfvTJcASoS7J3XJBsRmu+NNsrpoDavl27LQAYbz4nZU1ibIS
         PUAd5PVbXGg+je8kPdMID0oWCPnPHXP56fSAEcNitq+cahdjwxnaaXAXBNxowQ6ANXga
         M+QN8ILgRFqCUpnOduYZX91BWJFwr282RJ4bwxcHtfL0hQh008nLir7tAFZPB+Ki5T5U
         utckEOV7DF4uTVl96v+Bn0klBMN+q8PjwXR5Y5f3hcVFI/TL/WGRPMdPbYUn953LVyn1
         o0Tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f3TCJn6oVzvhj2VN/FM6sVmqMSxbdkDBrpKqU9IYSZk=;
        b=lCy8xglvNK2JJJoo0WcdfYf4OJjS+XS16B/c9rwHFxBlKFSBX5Q+ssH+Tb2smPSkoa
         wosITMrubtWAfpayEhS/DVLNwgb6UvuMZyrPVB2OjeFOzhoLF1bp3NRfxKTQ3QJC0UkJ
         LGH6LqX82QS/g5Pg16vASg3SzAzoFk7eFtubdIQeEN4iwiXkWrK9EvBhaQzwGnEfLgnG
         vsSuJl1X+F4UiDJDp1FWCqehQ/QibI+Z+F/x/5oN6huuDDqBRnAEBJ6SIpqTQdNcfCeZ
         8bOrNqmVOi27cXb+WLMHYLZMbsjJzqOJ9vG/Xi75SmVukhOTso+o6gorl6h+E/NYHWJ3
         PQFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0YCHhfP9FGtkvUJE2d58viE5Iz3603oBzTEzttqXKWPOTlo44+
	Uc9A/A9dXID8J0ZFi5Xax9o=
X-Google-Smtp-Source: ADFU+vssAJAekQpR1dVKpHJsMTtxNP63hUUVEgU1xEYdp6ACNmvV3lXhlbZuDhnE+BHMtaCciLy0SA==
X-Received: by 2002:a81:5cc2:: with SMTP id q185mr16958179ywb.108.1583780670656;
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:883:: with SMTP id e3ls727688ybq.11.gmail; Mon, 09 Mar
 2020 12:04:30 -0700 (PDT)
X-Received: by 2002:a25:cc15:: with SMTP id l21mr19496664ybf.385.1583780670397;
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780670; cv=none;
        d=google.com; s=arc-20160816;
        b=M1KDSBelaYTbDOnqcpk+MofpiWgkSoqmyYqt+7IN4REWrlduhmWRE76LZ8IOHcUaEU
         OzFwqByJWuxXl/rIVYvLFoJD5E0++VwHGDwcCYzUyB/nd1RxOK9J+uXO4LW8pfthGBnv
         x4NL+Y1vTkXsBCCjVDi10l7kCikP8i50p/pmDNVKFsoNSpGFZj9Y+FJCjgTfV2Xiucpy
         EC31azHC9mtR2Spw4KL1YERFDyY+BjVE+p4hDTYtWvDTSaEZtdq2PTYUsbavUfU1k+hp
         Kh4sUgX/Z3iE3oo0YF4vAyJKQJZF62jUPQB6JWsRVktUQMrg7/Pb5Pdin3EJ56dTyhMs
         KF2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=F5qquXZYYEz2Mdo4QrMw9S6XTuVoqzwgE6HNDwY41DE=;
        b=DVJj9PRr66m4L2bcgOlP2Fi3PwtIoW/jaYJeah8SS8H9Qw94Pu7/sYs2YvWHI939gN
         VUQWnhjcs+nlKzsuY0jdBOh/3kWPBxQrsmn4HqHDXaHjRPl/HT/ztEJSAW4vDiEGvrAj
         cUc4KFuASN89VfHwFyE2caU2aahsq+3AUvNboLTIMAzpCVFUUG2geFe62bPwT0UunhYJ
         pI0EImyvmABMpZdb0BRABLBeOVtbAGEGb8fXFF8yiLgxMQ+ReZvV0WV6umZQPNjDRsBW
         Sgs9GGgImv1Ozificr/bZeODEaOAUri5PU2eIgt3lBzKx7S8J7kWb0CPlomW9hECldxr
         Co6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=FEqXJuAz;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s64si611092ywf.0.2020.03.09.12.04.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 61F1124676;
	Mon,  9 Mar 2020 19:04:29 +0000 (UTC)
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
Subject: [PATCH kcsan 29/32] kcsan: Add current->state to implicitly atomic accesses
Date: Mon,  9 Mar 2020 12:04:17 -0700
Message-Id: <20200309190420.6100-29-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=FEqXJuAz;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-29-paulmck%40kernel.org.
