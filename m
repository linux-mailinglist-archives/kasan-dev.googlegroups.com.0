Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY4T53ZQKGQEETVBCJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 508C4192E70
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Mar 2020 17:42:13 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id q15sf2159216pgb.4
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Mar 2020 09:42:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585154531; cv=pass;
        d=google.com; s=arc-20160816;
        b=thtSXY320lJ4Q2c5L+aSS2JICJjGb6UYYdKiJQYEwIwZCHKO0946eZzJQdJwH3oJ1F
         4Vp4cRr/y0O33OvmN0jvA8cQHZYlhfKFm0CLjbXOeitTxBvpdzlDnQVmkZaL+KvT/sH/
         0qYy1uV/LlS8nu5rVzhwOwyp52Ar4KRY1W8/6pl5z9btDwwz6RqTLRVJdgkSMpGtmCKs
         gM+2xfjeeSHDsELlEe1oreOFWIoTTa1ojYMxf13xVa9AqtyfVQLNaCrvkZ7QvqSmKQT4
         ZYvm9nkE4zXSD8BJ9PugCM1Qv1UwlQPCB2G4pAuW13HomvJDPJkLAFrwcV8ITeh7Opgq
         r8tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Tmej8RU0akdrssfhxNJCbt5y2ellToNGXNLCuOGaYdc=;
        b=yroQv31gQlEXqVdA1o+d9rs+nMctyIzB9l9tBJTPp2dGutq+DVkfNrlEXcRjVq0gEu
         cA1xaREEFlUcRjsQhHGVpCICMmAXoBlWhYOYlxqr9jR2QtulY96iq+eWDucZY67fzr81
         OfX3vhovWpeTYwymOVS2BhqHi/B6MTR/Ebzn6lAsIb2V9PCHZcQpmIM1ziMc0K2K2Ix7
         QLUkrYOUDn4yneiSJIESWyzKcHsfOt/15PSBqSK8+sZiwbi70jG6TCIy+8TBeKhrtSTk
         cIRjKALivn0AIwghZUcnWsG++Nz2BJtQoEI1MiBydHEG4yeyNJ6DVbEEtCyav/rmurqV
         YH2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IV6OJWR7;
       spf=pass (google.com: domain of 34yl7xgukcdwcjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=34Yl7XgUKCdwCJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Tmej8RU0akdrssfhxNJCbt5y2ellToNGXNLCuOGaYdc=;
        b=rK93VVJ/eBqTwBJ6oEQxWpvJr345El6ujwxJJ1LOmEAQR8TIHdM8MNCJ24xtf6aEAR
         Mg/5EGJVdrbywpQjRDPMkUBZkPD+PycwOl100g63M2hKxsFY7E521UGKWkkL3UhRQkDj
         /mQX3lqHA7FB1W5TnPHxz/TMf8Vv03TZPxRoPzleeZSrl3mHmB8d4nE0bjqv8krnKCZJ
         T1fFEVCkAGJ5EbvRcShvPs72zRSPyGkDo4ECFNtfFcHTcXozckXFJeSfK5eIaMZQD9PT
         RU5GdMDDzoayQJBM0l+G9ny0E2btO1B6pijqKQMZzGGoJLjmpk5FTK8BHus85hmUow0s
         5C9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Tmej8RU0akdrssfhxNJCbt5y2ellToNGXNLCuOGaYdc=;
        b=Zoctm91t9ntcqfOYkJGG9GJKFzmkbINeXwteobYEATA9TvqY7LR5Hk4IvXDjKwbRGK
         Pmw5dQ3OesiXdRHH3u0bDspQcBByJBY3oVR+oFs60KlOzXkJTvY6w0rxuY6/CwGxJQE9
         BGhHcGMb+ysbFKLKowmAN6CinMztsTSucEOhdO5ll8SbeZxx5aYc2jVwEsYGr6fTxSqE
         DFRImpGwAjOcbIKdA6KZvkaFwwJK4oceNCBImwKrY3j158/50xJJkqDnSQO7Z0RJ4iR9
         7nxW1JM9qHUSkePjmBNkUTBYCYO1H7R74uOFxdLnMkc6Zu4R1KjB/9VFTdL39Im3FA2R
         PhlQ==
X-Gm-Message-State: ANhLgQ2udl4L5xYI7VoX9mA6CSTzRd3ZrnpTKJPjz+6CK4KONs7fu2o2
	gL0w7/hBET2jZuItQRIZqbI=
X-Google-Smtp-Source: ADFU+vvt5So9PHnrIZIWWZHio6/jemlSmFef1lSJ+MoaGJgjVAl4QiklC7HIbNS+ZqrdliYteP5W/w==
X-Received: by 2002:a17:902:8d85:: with SMTP id v5mr4153136plo.146.1585154531616;
        Wed, 25 Mar 2020 09:42:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a9c1:: with SMTP id b1ls1943350plr.11.gmail; Wed, 25
 Mar 2020 09:42:11 -0700 (PDT)
X-Received: by 2002:a17:90a:9409:: with SMTP id r9mr4634897pjo.39.1585154530976;
        Wed, 25 Mar 2020 09:42:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585154530; cv=none;
        d=google.com; s=arc-20160816;
        b=SOPjWnUkE7qmBw4gHq+KqSxaJHj3iv3YzV5CUXIRfL8JuQqMyOvvxyjfQkGmINtRu3
         3CZ4u2rQlLY3oS8KNooDz3KhWZlz1FuawnaCcOf8CoK2TMXlvpsw/UUTjcJFCKuOdG9U
         iADH+ttdIxQqpaWFVO2NaoIOTUCuToqcJwgJvbCMx2Hz8+RAB4abQTL7IpLevsm2SuUn
         xTf6uoKyBCZe0p61JOctVV8Emu/d3L01qkYVL/hoX4IknDuevge1vaJYCyS3OFkxjrrR
         gcEYrQi67zXvdoh1VxDtwq7g2vMWV/XNHUn6BwxYk34QQFrHe6WOvN+cq4kutCADVRBE
         yezQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=EGhnUj7ioBzGectSkIqL2PzeN3zdjD+SletKvmksBXU=;
        b=tPBmu7C7d8MnID8FBlaff5S1QG3OoZQgr76MunGFAoI4ID96qLWg5mSG16Uz7JfQ3C
         0XMAFMHO6+k+jZkTnyjHLsGC5pBGh6WsbpLOuEZoGPmGVm7RUyC4WRKrnEDEa8sLJzz0
         q2S/+mUF0IhZPEDwgCSgalLwqULhE0D8N6Qv9to1CkaLTwWLz0JUFm+MEm1wwIWOC1lj
         IwD6jritWMrs8y82Z9EBm3rmZY+2RwAFioedcsyQqjLQhmqUY3ai9xF8VIekau1UoLTh
         rxzdDBK1Fq+bYE52XZVbVbLGJwN6zJC3mZx4Qv3IdB52NmkyFMfVs+LWRrWgNSa3gXDz
         Mu/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IV6OJWR7;
       spf=pass (google.com: domain of 34yl7xgukcdwcjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=34Yl7XgUKCdwCJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe4a.google.com (mail-vs1-xe4a.google.com. [2607:f8b0:4864:20::e4a])
        by gmr-mx.google.com with ESMTPS id y5si882368plr.4.2020.03.25.09.42.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Mar 2020 09:42:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 34yl7xgukcdwcjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) client-ip=2607:f8b0:4864:20::e4a;
Received: by mail-vs1-xe4a.google.com with SMTP id b125so472711vsd.23
        for <kasan-dev@googlegroups.com>; Wed, 25 Mar 2020 09:42:10 -0700 (PDT)
X-Received: by 2002:a67:ecc1:: with SMTP id i1mr3159758vsp.89.1585154529924;
 Wed, 25 Mar 2020 09:42:09 -0700 (PDT)
Date: Wed, 25 Mar 2020 17:41:56 +0100
Message-Id: <20200325164158.195303-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.1.696.g5e7596f4ac-goog
Subject: [PATCH 1/3] kcsan: Add support for scoped accesses
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, cai@lca.pw, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Boqun Feng <boqun.feng@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IV6OJWR7;       spf=pass
 (google.com: domain of 34yl7xgukcdwcjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=34Yl7XgUKCdwCJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
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

This adds support for scoped accesses, where the memory range is checked
for the duration of the scope. The feature is implemented by inserting
the relevant access information into a list of scoped accesses for the
current execution context, which are then checked (until removed) on
every call (through instrumentation) into the KCSAN runtime.

An alternative, more complex, implementation could set up a watchpoint
for the scoped access, and keep the watchpoint set up. This, however,
would require first exposing a handle to the watchpoint, as well as
dealing with cases such as accesses by the same thread while the
watchpoint is still set up (and several more cases). It is also doubtful
if this would provide any benefit, since the majority of delay where the
watchpoint is set up is likely due to the injected delays by KCSAN.
Therefore, the implementation in this patch is simpler, nor hurts
KCSAN's main use-case (normal data race detection); it also implicitly
increases scoped-access race-detection-ability due to increased
probability of setting up watchpoints by repeatedly calling
__kcsan_check_access() throughout the scope of the access.

The implementation required adding an additional conditional branch to
the fast-path. Using the microbenchmark, however, a *speedup* of ~5% of
the fast-path is measured. This appears to be due to subtly improved
codegen by GCC from moving get_ctx() and associated load of
preempt_count earlier.

Suggested-by: Boqun Feng <boqun.feng@gmail.com>
Suggested-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kcsan-checks.h | 57 +++++++++++++++++++++++++
 include/linux/kcsan.h        |  3 ++
 init/init_task.c             |  1 +
 kernel/kcsan/core.c          | 83 ++++++++++++++++++++++++++++++++----
 kernel/kcsan/report.c        | 33 +++++++++-----
 5 files changed, 158 insertions(+), 19 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 3cd8bb03eb41..b24253d3a442 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -3,6 +3,8 @@
 #ifndef _LINUX_KCSAN_CHECKS_H
 #define _LINUX_KCSAN_CHECKS_H
 
+/* Note: Only include what is already included by compiler.h. */
+#include <linux/compiler_attributes.h>
 #include <linux/types.h>
 
 /*
@@ -12,10 +14,12 @@
  *   WRITE : write access;
  *   ATOMIC: access is atomic;
  *   ASSERT: access is not a regular access, but an assertion;
+ *   SCOPED: access is a scoped access;
  */
 #define KCSAN_ACCESS_WRITE  0x1
 #define KCSAN_ACCESS_ATOMIC 0x2
 #define KCSAN_ACCESS_ASSERT 0x4
+#define KCSAN_ACCESS_SCOPED 0x8
 
 /*
  * __kcsan_*: Always calls into the runtime when KCSAN is enabled. This may be used
@@ -78,6 +82,52 @@ void kcsan_atomic_next(int n);
  */
 void kcsan_set_access_mask(unsigned long mask);
 
+/* Scoped access information. */
+struct kcsan_scoped_access {
+	struct list_head list;
+	const volatile void *ptr;
+	size_t size;
+	int type;
+};
+/*
+ * Automatically call kcsan_end_scoped_access() when kcsan_scoped_access goes
+ * out of scope; relies on attribute "cleanup", which is supported by all
+ * compilers that support KCSAN.
+ */
+#define __kcsan_cleanup_scoped                                                 \
+	__maybe_unused __attribute__((__cleanup__(kcsan_end_scoped_access)))
+
+/**
+ * kcsan_begin_scoped_access - begin scoped access
+ *
+ * Begin scoped access and initialize @sa, which will cause KCSAN to
+ * continuously check the memory range in the current thread until
+ * kcsan_end_scoped_access() is called for @sa.
+ *
+ * Scoped accesses are implemented by appending @sa to an internal list for the
+ * current execution context, and then checked on every call into the KCSAN
+ * runtime.
+ *
+ * @ptr: address of access
+ * @size: size of access
+ * @type: access type modifier
+ * @sa: struct kcsan_scoped_access to use for the scope of the access
+ */
+struct kcsan_scoped_access *
+kcsan_begin_scoped_access(const volatile void *ptr, size_t size, int type,
+			  struct kcsan_scoped_access *sa);
+
+/**
+ * kcsan_end_scoped_access - end scoped access
+ *
+ * End a scoped access, which will stop KCSAN checking the memory range.
+ * Requires that kcsan_begin_scoped_access() was previously called once for @sa.
+ *
+ * @sa: a previously initialized struct kcsan_scoped_access
+ */
+void kcsan_end_scoped_access(struct kcsan_scoped_access *sa);
+
+
 #else /* CONFIG_KCSAN */
 
 static inline void __kcsan_check_access(const volatile void *ptr, size_t size,
@@ -90,6 +140,13 @@ static inline void kcsan_flat_atomic_end(void)		{ }
 static inline void kcsan_atomic_next(int n)		{ }
 static inline void kcsan_set_access_mask(unsigned long mask) { }
 
+struct kcsan_scoped_access { };
+#define __kcsan_cleanup_scoped __maybe_unused
+static inline struct kcsan_scoped_access *
+kcsan_begin_scoped_access(const volatile void *ptr, size_t size, int type,
+			  struct kcsan_scoped_access *sa) { return sa; }
+static inline void kcsan_end_scoped_access(struct kcsan_scoped_access *sa) { }
+
 #endif /* CONFIG_KCSAN */
 
 /*
diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
index 3b84606e1e67..17ae59e4b685 100644
--- a/include/linux/kcsan.h
+++ b/include/linux/kcsan.h
@@ -40,6 +40,9 @@ struct kcsan_ctx {
 	 * Access mask for all accesses if non-zero.
 	 */
 	unsigned long access_mask;
+
+	/* List of scoped accesses. */
+	struct list_head scoped_accesses;
 };
 
 /**
diff --git a/init/init_task.c b/init/init_task.c
index 096191d177d5..198943851caf 100644
--- a/init/init_task.c
+++ b/init/init_task.c
@@ -168,6 +168,7 @@ struct task_struct init_task
 		.atomic_nest_count	= 0,
 		.in_flat_atomic		= false,
 		.access_mask		= 0,
+		.scoped_accesses	= {LIST_POISON1, NULL},
 	},
 #endif
 #ifdef CONFIG_TRACE_IRQFLAGS
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 4d8ea0fca5f1..a572aae61b98 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -6,6 +6,7 @@
 #include <linux/export.h>
 #include <linux/init.h>
 #include <linux/kernel.h>
+#include <linux/list.h>
 #include <linux/moduleparam.h>
 #include <linux/percpu.h>
 #include <linux/preempt.h>
@@ -42,6 +43,7 @@ static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
 	.atomic_nest_count	= 0,
 	.in_flat_atomic		= false,
 	.access_mask		= 0,
+	.scoped_accesses	= {LIST_POISON1, NULL},
 };
 
 /*
@@ -191,12 +193,23 @@ static __always_inline struct kcsan_ctx *get_ctx(void)
 	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
 }
 
+/* Check scoped accesses; never inline because this is a slow-path! */
+static noinline void kcsan_check_scoped_accesses(void)
+{
+	struct kcsan_ctx *ctx = get_ctx();
+	struct list_head *prev_save = ctx->scoped_accesses.prev;
+	struct kcsan_scoped_access *scoped_access;
+
+	ctx->scoped_accesses.prev = NULL;  /* Avoid recursion. */
+	list_for_each_entry(scoped_access, &ctx->scoped_accesses, list)
+		__kcsan_check_access(scoped_access->ptr, scoped_access->size, scoped_access->type);
+	ctx->scoped_accesses.prev = prev_save;
+}
+
 /* Rules for generic atomic accesses. Called from fast-path. */
 static __always_inline bool
-is_atomic(const volatile void *ptr, size_t size, int type)
+is_atomic(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *ctx)
 {
-	struct kcsan_ctx *ctx;
-
 	if (type & KCSAN_ACCESS_ATOMIC)
 		return true;
 
@@ -213,7 +226,6 @@ is_atomic(const volatile void *ptr, size_t size, int type)
 	    IS_ALIGNED((unsigned long)ptr, size))
 		return true; /* Assume aligned writes up to word size are atomic. */
 
-	ctx = get_ctx();
 	if (ctx->atomic_next > 0) {
 		/*
 		 * Because we do not have separate contexts for nested
@@ -233,7 +245,7 @@ is_atomic(const volatile void *ptr, size_t size, int type)
 }
 
 static __always_inline bool
-should_watch(const volatile void *ptr, size_t size, int type)
+should_watch(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *ctx)
 {
 	/*
 	 * Never set up watchpoints when memory operations are atomic.
@@ -242,7 +254,7 @@ should_watch(const volatile void *ptr, size_t size, int type)
 	 * should not count towards skipped instructions, and (2) to actually
 	 * decrement kcsan_atomic_next for consecutive instruction stream.
 	 */
-	if (is_atomic(ptr, size, type))
+	if (is_atomic(ptr, size, type, ctx))
 		return false;
 
 	if (this_cpu_dec_return(kcsan_skip) >= 0)
@@ -563,8 +575,14 @@ static __always_inline void check_access(const volatile void *ptr, size_t size,
 	if (unlikely(watchpoint != NULL))
 		kcsan_found_watchpoint(ptr, size, type, watchpoint,
 				       encoded_watchpoint);
-	else if (unlikely(should_watch(ptr, size, type)))
-		kcsan_setup_watchpoint(ptr, size, type);
+	else {
+		struct kcsan_ctx *ctx = get_ctx(); /* Call only once in fast-path. */
+
+		if (unlikely(should_watch(ptr, size, type, ctx)))
+			kcsan_setup_watchpoint(ptr, size, type);
+		else if (unlikely(ctx->scoped_accesses.prev))
+			kcsan_check_scoped_accesses();
+	}
 }
 
 /* === Public interface ===================================================== */
@@ -660,6 +678,55 @@ void kcsan_set_access_mask(unsigned long mask)
 }
 EXPORT_SYMBOL(kcsan_set_access_mask);
 
+struct kcsan_scoped_access *
+kcsan_begin_scoped_access(const volatile void *ptr, size_t size, int type,
+			  struct kcsan_scoped_access *sa)
+{
+	struct kcsan_ctx *ctx = get_ctx();
+
+	__kcsan_check_access(ptr, size, type);
+
+	ctx->disable_count++; /* Disable KCSAN, in case list debugging is on. */
+
+	INIT_LIST_HEAD(&sa->list);
+	sa->ptr = ptr;
+	sa->size = size;
+	sa->type = type;
+
+	if (!ctx->scoped_accesses.prev) /* Lazy initialize list head. */
+		INIT_LIST_HEAD(&ctx->scoped_accesses);
+	list_add(&sa->list, &ctx->scoped_accesses);
+
+	ctx->disable_count--;
+	return sa;
+}
+EXPORT_SYMBOL(kcsan_begin_scoped_access);
+
+void kcsan_end_scoped_access(struct kcsan_scoped_access *sa)
+{
+	struct kcsan_ctx *ctx = get_ctx();
+
+	if (WARN(!ctx->scoped_accesses.prev, "Unbalanced %s()?", __func__))
+		return;
+
+	ctx->disable_count++; /* Disable KCSAN, in case list debugging is on. */
+
+	list_del(&sa->list);
+	if (list_empty(&ctx->scoped_accesses))
+		/*
+		 * Ensure we do not enter kcsan_check_scoped_accesses()
+		 * slow-path if unnecessary, and avoids requiring list_empty()
+		 * in the fast-path (to avoid a READ_ONCE() and potential
+		 * uaccess warning).
+		 */
+		ctx->scoped_accesses.prev = NULL;
+
+	ctx->disable_count--;
+
+	__kcsan_check_access(sa->ptr, sa->size, sa->type);
+}
+EXPORT_SYMBOL(kcsan_end_scoped_access);
+
 void __kcsan_check_access(const volatile void *ptr, size_t size, int type)
 {
 	check_access(ptr, size, type);
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index ae0a383238ea..ddc18f1224a4 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -205,6 +205,20 @@ skip_report(enum kcsan_value_change value_change, unsigned long top_frame)
 
 static const char *get_access_type(int type)
 {
+	if (type & KCSAN_ACCESS_ASSERT) {
+		if (type & KCSAN_ACCESS_SCOPED) {
+			if (type & KCSAN_ACCESS_WRITE)
+				return "assert no accesses (scoped)";
+			else
+				return "assert no writes (scoped)";
+		} else {
+			if (type & KCSAN_ACCESS_WRITE)
+				return "assert no accesses";
+			else
+				return "assert no writes";
+		}
+	}
+
 	switch (type) {
 	case 0:
 		return "read";
@@ -214,17 +228,14 @@ static const char *get_access_type(int type)
 		return "write";
 	case KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
 		return "write (marked)";
-
-	/*
-	 * ASSERT variants:
-	 */
-	case KCSAN_ACCESS_ASSERT:
-	case KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_ATOMIC:
-		return "assert no writes";
-	case KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE:
-	case KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
-		return "assert no accesses";
-
+	case KCSAN_ACCESS_SCOPED:
+		return "read (scoped)";
+	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_ATOMIC:
+		return "read (marked, scoped)";
+	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE:
+		return "write (scoped)";
+	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
+		return "write (marked, scoped)";
 	default:
 		BUG();
 	}
-- 
2.25.1.696.g5e7596f4ac-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200325164158.195303-1-elver%40google.com.
