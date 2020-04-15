Return-Path: <kasan-dev+bncBAABBKFH3X2AKGQEJ5EESCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F5AE1AB0CB
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 20:34:17 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id a15sf6041382ilh.20
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 11:34:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586975656; cv=pass;
        d=google.com; s=arc-20160816;
        b=eiiWBhQL7CIQQiLaRwk0cAYWdnL9xBwlGdo3OCr6/GDkERJfFIw/0R1EBj/P/om1LY
         PhL3dvfDRAXvrYhsi6hBHy9+Gef7j/z0g4vDYlB+P0QwCeLTJtRX+o0WcqmyfZF/S9ko
         BF+idGznmqax+hSfgUSKc3TnUf5vU9Y+9MAWukWnGiLQx6boZag7+h1GWCf0G1+7n9Dk
         N34HDLn64F/3wjn7mFIKT/lGhCl/qJO+b6hi0UmLO37ZrNpojRqwsVqlTxs1gmRx4SdI
         F/ATIvkuyhYooUae3QVfLRrEU2IfRXMiB4jI+G4VMJcoTM0773pHO5mIlDXqBmr7zm5O
         X6YQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=Hue51j7g561MOUSq18lEib14hmqZXn3oy0UO2CtrIRk=;
        b=s82FUcLAKbMqKyug6LlfnVIhLY/bAquo9uFPN+HXo3Dktzfd4d/iEKvJHhcsIPsuF6
         xtDRad+y2BXBsDFqQq6giNtXRYnxinEVsClT/Heg5BCsdCNBq7MFA1gtqau9SZIqt1DC
         q3glDLH8lpx5il5DViIugC5NI+T97VMJ1FrVlU1PLl7xbzkMN1u2vgmhrWrB5ADXfeYn
         F433mH/tZmQkID+3ceOyjSCdbDzkJ57p5P0VmP/I1ZYmVNJLy2huhAAqGM3Zf/EJPlkr
         Kp5zkT9OwKpLHaAV0KhiXUofknmV65jvEntYJnMfyxBWh8elAE01K/tV+jbdS7t1IIgt
         WVkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="OL/sNkRf";
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hue51j7g561MOUSq18lEib14hmqZXn3oy0UO2CtrIRk=;
        b=HsXa/XciY4OHiJaHvFDiYS6/VtVkGoIEsDLoTu0NkmGLUFfHW4DBzKx9mqTs+HIz+r
         8AxDdLPIAHFEHQ647A/fGy8MsQL/Avq0ZkWLCTarweagAaNx8PqpAyvaz7vTLYwY9tBT
         N61aZZryZebM7QuPM0nZQvL6AeCuPJnjBEyKmF2YWM0NKPsXrvB0Z4VykdQqQ5scrRO+
         2dT5InFcBRNc5zX+diRSZErMizGFknbujqUyMQzqaFFhKImQGG9Fc1djhDo2S0YtsrKd
         h1IO+6/OG2OHpbLIl9nM/Vt2A1IamaOXeKbVZSl9SHJiovbMcZfrrWLF1i8W6YV65+Rq
         PMNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hue51j7g561MOUSq18lEib14hmqZXn3oy0UO2CtrIRk=;
        b=jaz9eODx7UqY+8OskSlqgwSjL3jakyeh5d5lWF71eCSwviJNF2/XIRoQqlAZtS7Ruy
         /sP5XcmA1AD4IFTnQyd7B57RK65YsQYjFh6rIZBlRpwFUGKFLJ3zWZj/yYKEdHhewPJF
         2so+Pv1lhGfmwwSsvdY3B0ooBIVC5Zp0Ty+U1hliac+SHEwhWEiF82gLfDcfazhNor5f
         EMoX9MugmQgE7bZPkAXMTvSjsfuJ9ChokBXYcluauEbT8h5I9Hua6JdrKfm+OW346ccO
         8WnSYqxsjgdsnLzrPc/daEz09ZOXv+pmWve/N3fFDnSwH7SsbX0JI1d6NXzBxv2Tew9s
         XVbQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYrNCxg36m6jsaXFpRTQ103f4m/C5XYHNuThx0CDP+ToKrAQ494
	+GJphWYFp4ekvf8bYwZUDIE=
X-Google-Smtp-Source: APiQypJKXJ1kZMc2nk/6EpyP6AievDCaXsFC34EF91cvgn8HGKHo5Yldt78FWLncY3O8nX4fFBg7rQ==
X-Received: by 2002:a92:c6c4:: with SMTP id v4mr6352096ilm.18.1586975656385;
        Wed, 15 Apr 2020 11:34:16 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c84c:: with SMTP id b12ls3798095ilq.5.gmail; Wed, 15 Apr
 2020 11:34:16 -0700 (PDT)
X-Received: by 2002:a92:5ed9:: with SMTP id f86mr6716632ilg.31.1586975656117;
        Wed, 15 Apr 2020 11:34:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586975656; cv=none;
        d=google.com; s=arc-20160816;
        b=kVvpA2z4uAhKylmm+A03x6wkEEyiAPfS2LrzZ85sLJTu9tRx/MuLSMrObgi0iCefLQ
         Y5nAvqZUVjckISiqGe6BvvSZyl+Bi1QMIvKyBydPUe8a8R/6dLTTQ5GAn/Y43yOpcrax
         SL+dTC4YTP59wKr9vGumEvLa/SHpOiwekJdYva/se1WKJQjPHSruwAGpCnijdSgSVqp0
         OO4vguOW2D/ZgxSvobaQ1tytpCgLu8aI/XJ4pDoTw3dHr8k8ZiQUDgRjIqkTWEjMQOhq
         79+vvF7HefzrfRyhc9v/xDn0/yIp5Je9yXwvVbSjiEDMS53OPLT9BwuTHqYfKsqjPpx9
         e71g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=E4MDhvt9sSp32AnKupyPJ5px9a6lorYz0jHcAv/cFXQ=;
        b=RF0lYRgU1+/ZDC9+Cwl3oPqXoyYcDG5AT9ezEyeEnb+02HZ1Iq3KuDG8D8/UT+2rgz
         Whax3V3wI+JHg2Da2xqT9HcFtoRdL0itfqSMYAk+02nulE/IE372s2WvKxEy6fDAyMFh
         mEsYNYjz95uf8npZS3z2mtjPbLMzkXoJdghJC8wm93ibQB3lki+RAbQLbizV9GeBP8va
         DTGteISlqHpdZCroorxOMR6RKM+DvbteDRY99tnRzB0tT85mS+q4kV5og1mRN154rHhe
         3DrPMTfpKPP0Z6DirQyZ6YbEf373P8EJiWVN0ZiQBwwgLImww53nFytSBC6ME4J4Dl84
         NTyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="OL/sNkRf";
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g17si809865ioe.0.2020.04.15.11.34.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 11:34:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 4F453217BA;
	Wed, 15 Apr 2020 18:34:15 +0000 (UTC)
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
Subject: [PATCH v4 tip/core/rcu 09/15] kcsan: Add support for scoped accesses
Date: Wed, 15 Apr 2020 11:34:05 -0700
Message-Id: <20200415183411.12368-9-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200415183343.GA12265@paulmck-ThinkPad-P72>
References: <20200415183343.GA12265@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="OL/sNkRf";       spf=pass
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

This adds support for scoped accesses, where the memory range is checked
for the duration of the scope. The feature is implemented by inserting
the relevant access information into a list of scoped accesses for
the current execution context, which are then checked (until removed)
on every call (through instrumentation) into the KCSAN runtime.

An alternative, more complex, implementation could set up a watchpoint for
the scoped access, and keep the watchpoint set up. This, however, would
require first exposing a handle to the watchpoint, as well as dealing
with cases such as accesses by the same thread while the watchpoint is
still set up (and several more cases). It is also doubtful if this would
provide any benefit, since the majority of delay where the watchpoint
is set up is likely due to the injected delays by KCSAN.  Therefore,
the implementation in this patch is simpler and avoids hurting KCSAN's
main use-case (normal data race detection); it also implicitly increases
scoped-access race-detection-ability due to increased probability of
setting up watchpoints by repeatedly calling __kcsan_check_access()
throughout the scope of the access.

The implementation required adding an additional conditional branch to
the fast-path. However, the microbenchmark showed a *speedup* of ~5%
on the fast-path. This appears to be due to subtly improved codegen by
GCC from moving get_ctx() and associated load of preempt_count earlier.

Suggested-by: Boqun Feng <boqun.feng@gmail.com>
Suggested-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/kcsan-checks.h | 57 ++++++++++++++++++++++++++++++
 include/linux/kcsan.h        |  3 ++
 init/init_task.c             |  1 +
 kernel/kcsan/core.c          | 83 +++++++++++++++++++++++++++++++++++++++-----
 kernel/kcsan/report.c        | 33 ++++++++++++------
 5 files changed, 158 insertions(+), 19 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 3cd8bb0..b24253d 100644
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
index 3b84606..17ae59e 100644
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
index 096191d..1989438 100644
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
index 4d8ea0f..a572aae 100644
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
index ae0a383..ddc18f1 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415183411.12368-9-paulmck%40kernel.org.
