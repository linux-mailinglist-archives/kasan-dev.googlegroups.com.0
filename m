Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOXA6CFAMGQENV7EWXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id C5CA7422426
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:10 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id d13-20020adf9b8d000000b00160a94c235asf1997125wrc.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431610; cv=pass;
        d=google.com; s=arc-20160816;
        b=e51dC3FO2TJD/6kNah6gVvRHe8ta0fZNitgieX8uUXRKhQVPzqDV34mEVqda3dSI4c
         zepDiGsHGW5OPjwuEOGaNWumLIRaB8+fMUGqJMsJqdeaNLkgoH7jfaNTbqjO8dgy+rMe
         z1siA3LHNYaoeqasMZb4tj3cn0cohtIFBeKrM2K7ezu7qPyNXhHZoK0ELX3bBgJpCBmt
         wzhIRoo6NxUUGtT4HRdfZ63Q2mI2X2uy1BlqtPIu2E7hQnkXzTkA6Vnk2nR8zPJmq+73
         xUUhRPMzEIjXONJI+pmL+fMQMAd5nZTca2lxpATZ8cgMRWjlFvcOPoYV9dBHzHbxI2tH
         16PQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=hJ2F6G1qyaO4YW+StAa1FNhFX1kYdON5jUAnl/v1kKw=;
        b=MXAwtejN2hYVG61FUC7CfZ1FTpujdtFt0MWCzwbYZRyN9mXE/5rj0g6QKIugCpyKzo
         PG6PGgJ/nx1cm+w+awjSV4FML/j4aTeHLgXuVb4nxE/4pV11sJmp2Ugm05Tup9EZdx33
         Gz6r4gC/5URNdLFbJ36UEwvTa/65Y6Tb9OhvACS7PR9Xt8ituB3y0xu3Wc9asI1redHD
         KgHl2hWS7CIahoRznhSyIgRctPtDqJMPQQ7vQT9jWF/apW46H/4XEcbaple/5gv4CZTf
         822Guwg6ECgehBa5wL6Ba8r1RK4VkH8ez7CrzBhpovTN4CX5kmSXiFpEio7zLDa4bLtS
         JC4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DKByp7rh;
       spf=pass (google.com: domain of 3odbcyqukcrs5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=3ODBcYQUKCRs5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hJ2F6G1qyaO4YW+StAa1FNhFX1kYdON5jUAnl/v1kKw=;
        b=PwuezCFHfKuTBQcoZLaVgnPDJWUnFVDr5BKud9DtOp/z8yVPqOQvlJ9OcIxsdCtMSa
         im5NLqV7u4wddpoiNI6M0qNCqPXSw2gr0RXplJFNDnAtoxvY7m3SEiTRXnAOSuHZDmbd
         sybXxOGQgznewK85HjQdO7wybyQB/PRw+n4tZkF2Nx1v9lbJeV23DsHvXJnxXN8iobYv
         rzteDsrtijmyEqogEMNS7dWE6aGt9f9M7jH6thCifnNwo8oPvQKyEfh+tMS3E7odFZic
         /fUrKpH3MArIfDxpvC+KXJFkmoonEd+QB5L5gM41/nC5BWt826nIX9ckRehhIfy1ho4Q
         wDEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hJ2F6G1qyaO4YW+StAa1FNhFX1kYdON5jUAnl/v1kKw=;
        b=Unbl3fZegBVkIZ+xj3kMBKivWgg2Y0cK9/3ixjDZbD42aFWKcqrmZLhOGhZEgpeZa6
         LNbOYhGxoT3nwvXLg4aF+IoDs7jPD9Db6KdkLj30VoDTUMfQ8XDhHNa92gkGZyFB/FVO
         6mYsS4iJnfda02JRbJWv4eufHWNvGeOjcAltGKhQeHVDSeBAipicrLhPQTd0tk49h51S
         JjSkk7P4pCYO85zUatvi0eP7yiUqbMn5DAfwQDjuwy2XRAIWohJRMg8NIIOzMPdrly3l
         OLPCUnw1L8W7oCoBZg1KHcxqaHeiBWQnpTv00V2eSMET18Io6DG6b/HtL2DGAK/Xm8YF
         ManQ==
X-Gm-Message-State: AOAM531ykfvo9QJpQu2GTJRmvpKsNF52/ooKOvg+lqFrbFtWx8mlFY7/
	1ECR/6URH8yilCm2zWLtrXo=
X-Google-Smtp-Source: ABdhPJxuJ7kRkJ2GJqrVmR9Tcyk9815fYKpfVTpT2D9bjbY895Wzb8hzvgmaU7QeKj4G8OBpM0fY/Q==
X-Received: by 2002:a05:6000:1052:: with SMTP id c18mr3961095wrx.294.1633431610540;
        Tue, 05 Oct 2021 04:00:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a285:: with SMTP id s5ls1836735wra.1.gmail; Tue, 05 Oct
 2021 04:00:09 -0700 (PDT)
X-Received: by 2002:adf:8b84:: with SMTP id o4mr16678411wra.108.1633431609529;
        Tue, 05 Oct 2021 04:00:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431609; cv=none;
        d=google.com; s=arc-20160816;
        b=mla41jQ9eGiwpBjAf1pqdqyR/ssKFPrL4+/0w4IWRZICO4hZx7MHDSf7FXL3MOnEPr
         TvRnRuhgsqyAMgSSACAMegFAbsOtuiBvauriruYMFLjxtF4AIy2N9gIIgjEYzlAg610e
         AOGLQSnVkDsYIlmby2nDsYKJ337ujelswF6vc96QzuzTbyVf3FiZnwMrUZ4lD3hJ/uWl
         bBQmO60FZwJYYkuzlHd1Z2d85Jc+/MfCpWe/dHsL48H+uztOPNc2Jg5FPWi4aCXkdI4v
         hh4wVKLuSeizUjJbx7nC//8f/AiPiWdpnaZVl9Il0I6BwlTdZcqG7hZ7h4ET+G4ulQJP
         Bwew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ZtjlTRd9cPGbU2ksHL1X0mLktYMB6yEg4HDsxE/XxIE=;
        b=DurulqM3QLjy4jDgTyyyQwk3Il5DnZQnJksdB2nnkYG/sfCRgVYPAk07mkjIQEV9JP
         0mNHsTXJP9CX4N8hp5yylm+LRw7AlqPqy+IAIMQiIr3gtkkYINpobyCUa70GTh73xJit
         xQOW7cNMypoaOWGSa7fRWZUPW1Ui4JhunnJH8N6HI+yV3fgCCYF5Ysbyv12S/qMScR7t
         eApMJvrHuMyFdrTsggGs7sKXLggvEdEiBI52hwYemDi5yvmI25SYe4Lx1mhcrotjKtCf
         OX8mHcnUP5on1I1K3IwOdbL2LlCnFZrLrAYGnH6cECzQ/VPxQ5Q247C3tTvvy5ri49MO
         2Kwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DKByp7rh;
       spf=pass (google.com: domain of 3odbcyqukcrs5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=3ODBcYQUKCRs5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x14a.google.com (mail-lf1-x14a.google.com. [2a00:1450:4864:20::14a])
        by gmr-mx.google.com with ESMTPS id e2si999265wrj.4.2021.10.05.04.00.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:00:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3odbcyqukcrs5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::14a as permitted sender) client-ip=2a00:1450:4864:20::14a;
Received: by mail-lf1-x14a.google.com with SMTP id n22-20020a0565120ad600b003fcc09af59fso16616484lfu.21
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:00:09 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a05:6512:b0f:: with SMTP id
 w15mr2729100lfu.164.1633431608867; Tue, 05 Oct 2021 04:00:08 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:53 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-12-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 11/23] kcsan: test: Add test cases for memory
 barrier instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DKByp7rh;       spf=pass
 (google.com: domain of 3odbcyqukcrs5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::14a as permitted sender) smtp.mailfrom=3ODBcYQUKCRs5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
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

Adds test cases to check that memory barriers are instrumented
correctly, and detection of missing memory barriers is working as
intended if CONFIG_KCSAN_STRICT=y.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan_test.c | 320 ++++++++++++++++++++++++++++++++++++++
 1 file changed, 320 insertions(+)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index ec054879201b..469f3044a5b3 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -16,9 +16,12 @@
 #define pr_fmt(fmt) "kcsan_test: " fmt
 
 #include <kunit/test.h>
+#include <linux/atomic.h>
+#include <linux/bitops.h>
 #include <linux/jiffies.h>
 #include <linux/kcsan-checks.h>
 #include <linux/kernel.h>
+#include <linux/mutex.h>
 #include <linux/sched.h>
 #include <linux/seqlock.h>
 #include <linux/spinlock.h>
@@ -305,6 +308,16 @@ static DEFINE_SEQLOCK(test_seqlock);
 __no_kcsan
 static noinline void sink_value(long v) { WRITE_ONCE(test_sink, v); }
 
+/*
+ * Generates a delay and some accesses that enter the runtime but do not produce
+ * data races.
+ */
+static noinline void test_delay(int iter)
+{
+	while (iter--)
+		sink_value(READ_ONCE(test_sink));
+}
+
 static noinline void test_kernel_read(void) { sink_value(test_var); }
 
 static noinline void test_kernel_write(void)
@@ -466,8 +479,220 @@ static noinline void test_kernel_xor_1bit(void)
 	kcsan_nestable_atomic_end();
 }
 
+#define TEST_KERNEL_LOCKED(name, acquire, release)		\
+	static noinline void test_kernel_##name(void)		\
+	{							\
+		long *flag = &test_struct.val[0];		\
+		long v = 0;					\
+		if (!(acquire))					\
+			return;					\
+		while (v++ < 100) {				\
+			test_var++;				\
+			barrier();				\
+		}						\
+		release;					\
+		test_delay(10);					\
+	}
+
+TEST_KERNEL_LOCKED(with_memorder,
+		   cmpxchg_acquire(flag, 0, 1) == 0,
+		   smp_store_release(flag, 0));
+TEST_KERNEL_LOCKED(wrong_memorder,
+		   cmpxchg_relaxed(flag, 0, 1) == 0,
+		   WRITE_ONCE(*flag, 0));
+TEST_KERNEL_LOCKED(atomic_builtin_with_memorder,
+		   __atomic_compare_exchange_n(flag, &v, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED),
+		   __atomic_store_n(flag, 0, __ATOMIC_RELEASE));
+TEST_KERNEL_LOCKED(atomic_builtin_wrong_memorder,
+		   __atomic_compare_exchange_n(flag, &v, 1, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED),
+		   __atomic_store_n(flag, 0, __ATOMIC_RELAXED));
+
 /* ===== Test cases ===== */
 
+/*
+ * Tests that various barriers have the expected effect on internal state. Not
+ * exhaustive on atomic_t operations. Unlike the selftest, also checks for
+ * too-strict barrier instrumentation; these can be tolerated, because it does
+ * not cause false positives, but at least we should be aware of such cases.
+ */
+__no_kcsan
+static void test_barrier_nothreads(struct kunit *test)
+{
+#ifdef CONFIG_KCSAN_WEAK_MEMORY
+	struct kcsan_scoped_access *reorder_access = &current->kcsan_ctx.reorder_access;
+#else
+	struct kcsan_scoped_access *reorder_access = NULL;
+#endif
+	arch_spinlock_t arch_spinlock = __ARCH_SPIN_LOCK_UNLOCKED;
+	DEFINE_SPINLOCK(spinlock);
+	DEFINE_MUTEX(mutex);
+	atomic_t dummy;
+
+	KCSAN_TEST_REQUIRES(test, reorder_access != NULL);
+	KCSAN_TEST_REQUIRES(test, IS_ENABLED(CONFIG_SMP));
+
+#define __KCSAN_EXPECT_BARRIER(access_type, barrier, order_before, name)			\
+	do {											\
+		reorder_access->type = (access_type) | KCSAN_ACCESS_SCOPED;			\
+		reorder_access->size = sizeof(test_var);					\
+		barrier;									\
+		KUNIT_EXPECT_EQ_MSG(test, reorder_access->size,					\
+				    order_before ? 0 : sizeof(test_var),			\
+				    "improperly instrumented type=(" #access_type "): " name);	\
+	} while (0)
+#define KCSAN_EXPECT_READ_BARRIER(b, o)  __KCSAN_EXPECT_BARRIER(0, b, o, #b)
+#define KCSAN_EXPECT_WRITE_BARRIER(b, o) __KCSAN_EXPECT_BARRIER(KCSAN_ACCESS_WRITE, b, o, #b)
+#define KCSAN_EXPECT_RW_BARRIER(b, o)    __KCSAN_EXPECT_BARRIER(KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE, b, o, #b)
+
+	/* Force creating a valid entry in reorder_access first. */
+	test_var = 0;
+	while (test_var++ < 1000000 && reorder_access->size != sizeof(test_var))
+		__kcsan_check_read(&test_var, sizeof(test_var));
+	KUNIT_ASSERT_EQ(test, reorder_access->size, sizeof(test_var));
+
+	kcsan_nestable_atomic_begin(); /* No watchpoints in called functions. */
+
+	KCSAN_EXPECT_READ_BARRIER(mb(), true);
+	KCSAN_EXPECT_READ_BARRIER(wmb(), false);
+	KCSAN_EXPECT_READ_BARRIER(rmb(), true);
+	KCSAN_EXPECT_READ_BARRIER(smp_mb(), true);
+	KCSAN_EXPECT_READ_BARRIER(smp_wmb(), false);
+	KCSAN_EXPECT_READ_BARRIER(smp_rmb(), true);
+	KCSAN_EXPECT_READ_BARRIER(dma_wmb(), false);
+	KCSAN_EXPECT_READ_BARRIER(dma_rmb(), true);
+	KCSAN_EXPECT_READ_BARRIER(smp_mb__before_atomic(), true);
+	KCSAN_EXPECT_READ_BARRIER(smp_mb__after_atomic(), true);
+	KCSAN_EXPECT_READ_BARRIER(smp_mb__after_spinlock(), true);
+	KCSAN_EXPECT_READ_BARRIER(smp_store_mb(test_var, 0), true);
+	KCSAN_EXPECT_READ_BARRIER(smp_load_acquire(&test_var), false);
+	KCSAN_EXPECT_READ_BARRIER(smp_store_release(&test_var, 0), true);
+	KCSAN_EXPECT_READ_BARRIER(xchg(&test_var, 0), true);
+	KCSAN_EXPECT_READ_BARRIER(xchg_release(&test_var, 0), true);
+	KCSAN_EXPECT_READ_BARRIER(xchg_relaxed(&test_var, 0), false);
+	KCSAN_EXPECT_READ_BARRIER(cmpxchg(&test_var, 0,  0), true);
+	KCSAN_EXPECT_READ_BARRIER(cmpxchg_release(&test_var, 0,  0), true);
+	KCSAN_EXPECT_READ_BARRIER(cmpxchg_relaxed(&test_var, 0,  0), false);
+	KCSAN_EXPECT_READ_BARRIER(atomic_read(&dummy), false);
+	KCSAN_EXPECT_READ_BARRIER(atomic_read_acquire(&dummy), false);
+	KCSAN_EXPECT_READ_BARRIER(atomic_set(&dummy, 0), false);
+	KCSAN_EXPECT_READ_BARRIER(atomic_set_release(&dummy, 0), true);
+	KCSAN_EXPECT_READ_BARRIER(atomic_add(1, &dummy), false);
+	KCSAN_EXPECT_READ_BARRIER(atomic_add_return(1, &dummy), true);
+	KCSAN_EXPECT_READ_BARRIER(atomic_add_return_acquire(1, &dummy), false);
+	KCSAN_EXPECT_READ_BARRIER(atomic_add_return_release(1, &dummy), true);
+	KCSAN_EXPECT_READ_BARRIER(atomic_add_return_relaxed(1, &dummy), false);
+	KCSAN_EXPECT_READ_BARRIER(atomic_fetch_add(1, &dummy), true);
+	KCSAN_EXPECT_READ_BARRIER(atomic_fetch_add_acquire(1, &dummy), false);
+	KCSAN_EXPECT_READ_BARRIER(atomic_fetch_add_release(1, &dummy), true);
+	KCSAN_EXPECT_READ_BARRIER(atomic_fetch_add_relaxed(1, &dummy), false);
+	KCSAN_EXPECT_READ_BARRIER(test_and_set_bit(0, &test_var), true);
+	KCSAN_EXPECT_READ_BARRIER(test_and_clear_bit(0, &test_var), true);
+	KCSAN_EXPECT_READ_BARRIER(test_and_change_bit(0, &test_var), true);
+	KCSAN_EXPECT_READ_BARRIER(clear_bit_unlock(0, &test_var), true);
+	KCSAN_EXPECT_READ_BARRIER(__clear_bit_unlock(0, &test_var), true);
+	KCSAN_EXPECT_READ_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var), true);
+	KCSAN_EXPECT_READ_BARRIER(arch_spin_lock(&arch_spinlock), false);
+	KCSAN_EXPECT_READ_BARRIER(arch_spin_unlock(&arch_spinlock), true);
+	KCSAN_EXPECT_READ_BARRIER(spin_lock(&spinlock), false);
+	KCSAN_EXPECT_READ_BARRIER(spin_unlock(&spinlock), true);
+	KCSAN_EXPECT_READ_BARRIER(mutex_lock(&mutex), false);
+	KCSAN_EXPECT_READ_BARRIER(mutex_unlock(&mutex), true);
+
+	KCSAN_EXPECT_WRITE_BARRIER(mb(), true);
+	KCSAN_EXPECT_WRITE_BARRIER(wmb(), true);
+	KCSAN_EXPECT_WRITE_BARRIER(rmb(), false);
+	KCSAN_EXPECT_WRITE_BARRIER(smp_mb(), true);
+	KCSAN_EXPECT_WRITE_BARRIER(smp_wmb(), true);
+	KCSAN_EXPECT_WRITE_BARRIER(smp_rmb(), false);
+	KCSAN_EXPECT_WRITE_BARRIER(dma_wmb(), true);
+	KCSAN_EXPECT_WRITE_BARRIER(dma_rmb(), false);
+	KCSAN_EXPECT_WRITE_BARRIER(smp_mb__before_atomic(), true);
+	KCSAN_EXPECT_WRITE_BARRIER(smp_mb__after_atomic(), true);
+	KCSAN_EXPECT_WRITE_BARRIER(smp_mb__after_spinlock(), true);
+	KCSAN_EXPECT_WRITE_BARRIER(smp_store_mb(test_var, 0), true);
+	KCSAN_EXPECT_WRITE_BARRIER(smp_load_acquire(&test_var), false);
+	KCSAN_EXPECT_WRITE_BARRIER(smp_store_release(&test_var, 0), true);
+	KCSAN_EXPECT_WRITE_BARRIER(xchg(&test_var, 0), true);
+	KCSAN_EXPECT_WRITE_BARRIER(xchg_release(&test_var, 0), true);
+	KCSAN_EXPECT_WRITE_BARRIER(xchg_relaxed(&test_var, 0), false);
+	KCSAN_EXPECT_WRITE_BARRIER(cmpxchg(&test_var, 0,  0), true);
+	KCSAN_EXPECT_WRITE_BARRIER(cmpxchg_release(&test_var, 0,  0), true);
+	KCSAN_EXPECT_WRITE_BARRIER(cmpxchg_relaxed(&test_var, 0,  0), false);
+	KCSAN_EXPECT_WRITE_BARRIER(atomic_read(&dummy), false);
+	KCSAN_EXPECT_WRITE_BARRIER(atomic_read_acquire(&dummy), false);
+	KCSAN_EXPECT_WRITE_BARRIER(atomic_set(&dummy, 0), false);
+	KCSAN_EXPECT_WRITE_BARRIER(atomic_set_release(&dummy, 0), true);
+	KCSAN_EXPECT_WRITE_BARRIER(atomic_add(1, &dummy), false);
+	KCSAN_EXPECT_WRITE_BARRIER(atomic_add_return(1, &dummy), true);
+	KCSAN_EXPECT_WRITE_BARRIER(atomic_add_return_acquire(1, &dummy), false);
+	KCSAN_EXPECT_WRITE_BARRIER(atomic_add_return_release(1, &dummy), true);
+	KCSAN_EXPECT_WRITE_BARRIER(atomic_add_return_relaxed(1, &dummy), false);
+	KCSAN_EXPECT_WRITE_BARRIER(atomic_fetch_add(1, &dummy), true);
+	KCSAN_EXPECT_WRITE_BARRIER(atomic_fetch_add_acquire(1, &dummy), false);
+	KCSAN_EXPECT_WRITE_BARRIER(atomic_fetch_add_release(1, &dummy), true);
+	KCSAN_EXPECT_WRITE_BARRIER(atomic_fetch_add_relaxed(1, &dummy), false);
+	KCSAN_EXPECT_WRITE_BARRIER(test_and_set_bit(0, &test_var), true);
+	KCSAN_EXPECT_WRITE_BARRIER(test_and_clear_bit(0, &test_var), true);
+	KCSAN_EXPECT_WRITE_BARRIER(test_and_change_bit(0, &test_var), true);
+	KCSAN_EXPECT_WRITE_BARRIER(clear_bit_unlock(0, &test_var), true);
+	KCSAN_EXPECT_WRITE_BARRIER(__clear_bit_unlock(0, &test_var), true);
+	KCSAN_EXPECT_WRITE_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var), true);
+	KCSAN_EXPECT_WRITE_BARRIER(arch_spin_lock(&arch_spinlock), false);
+	KCSAN_EXPECT_WRITE_BARRIER(arch_spin_unlock(&arch_spinlock), true);
+	KCSAN_EXPECT_WRITE_BARRIER(spin_lock(&spinlock), false);
+	KCSAN_EXPECT_WRITE_BARRIER(spin_unlock(&spinlock), true);
+	KCSAN_EXPECT_WRITE_BARRIER(mutex_lock(&mutex), false);
+	KCSAN_EXPECT_WRITE_BARRIER(mutex_unlock(&mutex), true);
+
+	KCSAN_EXPECT_RW_BARRIER(mb(), true);
+	KCSAN_EXPECT_RW_BARRIER(wmb(), true);
+	KCSAN_EXPECT_RW_BARRIER(rmb(), true);
+	KCSAN_EXPECT_RW_BARRIER(smp_mb(), true);
+	KCSAN_EXPECT_RW_BARRIER(smp_wmb(), true);
+	KCSAN_EXPECT_RW_BARRIER(smp_rmb(), true);
+	KCSAN_EXPECT_RW_BARRIER(dma_wmb(), true);
+	KCSAN_EXPECT_RW_BARRIER(dma_rmb(), true);
+	KCSAN_EXPECT_RW_BARRIER(smp_mb__before_atomic(), true);
+	KCSAN_EXPECT_RW_BARRIER(smp_mb__after_atomic(), true);
+	KCSAN_EXPECT_RW_BARRIER(smp_mb__after_spinlock(), true);
+	KCSAN_EXPECT_RW_BARRIER(smp_store_mb(test_var, 0), true);
+	KCSAN_EXPECT_RW_BARRIER(smp_load_acquire(&test_var), false);
+	KCSAN_EXPECT_RW_BARRIER(smp_store_release(&test_var, 0), true);
+	KCSAN_EXPECT_RW_BARRIER(xchg(&test_var, 0), true);
+	KCSAN_EXPECT_RW_BARRIER(xchg_release(&test_var, 0), true);
+	KCSAN_EXPECT_RW_BARRIER(xchg_relaxed(&test_var, 0), false);
+	KCSAN_EXPECT_RW_BARRIER(cmpxchg(&test_var, 0,  0), true);
+	KCSAN_EXPECT_RW_BARRIER(cmpxchg_release(&test_var, 0,  0), true);
+	KCSAN_EXPECT_RW_BARRIER(cmpxchg_relaxed(&test_var, 0,  0), false);
+	KCSAN_EXPECT_RW_BARRIER(atomic_read(&dummy), false);
+	KCSAN_EXPECT_RW_BARRIER(atomic_read_acquire(&dummy), false);
+	KCSAN_EXPECT_RW_BARRIER(atomic_set(&dummy, 0), false);
+	KCSAN_EXPECT_RW_BARRIER(atomic_set_release(&dummy, 0), true);
+	KCSAN_EXPECT_RW_BARRIER(atomic_add(1, &dummy), false);
+	KCSAN_EXPECT_RW_BARRIER(atomic_add_return(1, &dummy), true);
+	KCSAN_EXPECT_RW_BARRIER(atomic_add_return_acquire(1, &dummy), false);
+	KCSAN_EXPECT_RW_BARRIER(atomic_add_return_release(1, &dummy), true);
+	KCSAN_EXPECT_RW_BARRIER(atomic_add_return_relaxed(1, &dummy), false);
+	KCSAN_EXPECT_RW_BARRIER(atomic_fetch_add(1, &dummy), true);
+	KCSAN_EXPECT_RW_BARRIER(atomic_fetch_add_acquire(1, &dummy), false);
+	KCSAN_EXPECT_RW_BARRIER(atomic_fetch_add_release(1, &dummy), true);
+	KCSAN_EXPECT_RW_BARRIER(atomic_fetch_add_relaxed(1, &dummy), false);
+	KCSAN_EXPECT_RW_BARRIER(test_and_set_bit(0, &test_var), true);
+	KCSAN_EXPECT_RW_BARRIER(test_and_clear_bit(0, &test_var), true);
+	KCSAN_EXPECT_RW_BARRIER(test_and_change_bit(0, &test_var), true);
+	KCSAN_EXPECT_RW_BARRIER(clear_bit_unlock(0, &test_var), true);
+	KCSAN_EXPECT_RW_BARRIER(__clear_bit_unlock(0, &test_var), true);
+	KCSAN_EXPECT_RW_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var), true);
+	KCSAN_EXPECT_RW_BARRIER(arch_spin_lock(&arch_spinlock), false);
+	KCSAN_EXPECT_RW_BARRIER(arch_spin_unlock(&arch_spinlock), true);
+	KCSAN_EXPECT_RW_BARRIER(spin_lock(&spinlock), false);
+	KCSAN_EXPECT_RW_BARRIER(spin_unlock(&spinlock), true);
+	KCSAN_EXPECT_RW_BARRIER(mutex_lock(&mutex), false);
+	KCSAN_EXPECT_RW_BARRIER(mutex_unlock(&mutex), true);
+
+	kcsan_nestable_atomic_end();
+}
+
 /* Simple test with normal data race. */
 __no_kcsan
 static void test_basic(struct kunit *test)
@@ -1039,6 +1264,90 @@ static void test_1bit_value_change(struct kunit *test)
 		KUNIT_EXPECT_TRUE(test, match);
 }
 
+__no_kcsan
+static void test_correct_barrier(struct kunit *test)
+{
+	struct expect_report expect = {
+		.access = {
+			{ test_kernel_with_memorder, &test_var, sizeof(test_var), __KCSAN_ACCESS_RW(KCSAN_ACCESS_WRITE) },
+			{ test_kernel_with_memorder, &test_var, sizeof(test_var), __KCSAN_ACCESS_RW(0) },
+		},
+	};
+	bool match_expect = false;
+
+	test_struct.val[0] = 0; /* init unlocked */
+	begin_test_checks(test_kernel_with_memorder, test_kernel_with_memorder);
+	do {
+		match_expect = report_matches_any_reordered(&expect);
+	} while (!end_test_checks(match_expect));
+	KUNIT_EXPECT_FALSE(test, match_expect);
+}
+
+__no_kcsan
+static void test_missing_barrier(struct kunit *test)
+{
+	struct expect_report expect = {
+		.access = {
+			{ test_kernel_wrong_memorder, &test_var, sizeof(test_var), __KCSAN_ACCESS_RW(KCSAN_ACCESS_WRITE) },
+			{ test_kernel_wrong_memorder, &test_var, sizeof(test_var), __KCSAN_ACCESS_RW(0) },
+		},
+	};
+	bool match_expect = false;
+
+	test_struct.val[0] = 0; /* init unlocked */
+	begin_test_checks(test_kernel_wrong_memorder, test_kernel_wrong_memorder);
+	do {
+		match_expect = report_matches_any_reordered(&expect);
+	} while (!end_test_checks(match_expect));
+	if (IS_ENABLED(CONFIG_KCSAN_WEAK_MEMORY))
+		KUNIT_EXPECT_TRUE(test, match_expect);
+	else
+		KUNIT_EXPECT_FALSE(test, match_expect);
+}
+
+__no_kcsan
+static void test_atomic_builtins_correct_barrier(struct kunit *test)
+{
+	struct expect_report expect = {
+		.access = {
+			{ test_kernel_atomic_builtin_with_memorder, &test_var, sizeof(test_var), __KCSAN_ACCESS_RW(KCSAN_ACCESS_WRITE) },
+			{ test_kernel_atomic_builtin_with_memorder, &test_var, sizeof(test_var), __KCSAN_ACCESS_RW(0) },
+		},
+	};
+	bool match_expect = false;
+
+	test_struct.val[0] = 0; /* init unlocked */
+	begin_test_checks(test_kernel_atomic_builtin_with_memorder,
+			  test_kernel_atomic_builtin_with_memorder);
+	do {
+		match_expect = report_matches_any_reordered(&expect);
+	} while (!end_test_checks(match_expect));
+	KUNIT_EXPECT_FALSE(test, match_expect);
+}
+
+__no_kcsan
+static void test_atomic_builtins_missing_barrier(struct kunit *test)
+{
+	struct expect_report expect = {
+		.access = {
+			{ test_kernel_atomic_builtin_wrong_memorder, &test_var, sizeof(test_var), __KCSAN_ACCESS_RW(KCSAN_ACCESS_WRITE) },
+			{ test_kernel_atomic_builtin_wrong_memorder, &test_var, sizeof(test_var), __KCSAN_ACCESS_RW(0) },
+		},
+	};
+	bool match_expect = false;
+
+	test_struct.val[0] = 0; /* init unlocked */
+	begin_test_checks(test_kernel_atomic_builtin_wrong_memorder,
+			  test_kernel_atomic_builtin_wrong_memorder);
+	do {
+		match_expect = report_matches_any_reordered(&expect);
+	} while (!end_test_checks(match_expect));
+	if (IS_ENABLED(CONFIG_KCSAN_WEAK_MEMORY))
+		KUNIT_EXPECT_TRUE(test, match_expect);
+	else
+		KUNIT_EXPECT_FALSE(test, match_expect);
+}
+
 /*
  * Generate thread counts for all test cases. Values generated are in interval
  * [2, 5] followed by exponentially increasing thread counts from 8 to 32.
@@ -1088,6 +1397,7 @@ static const void *nthreads_gen_params(const void *prev, char *desc)
 
 #define KCSAN_KUNIT_CASE(test_name) KUNIT_CASE_PARAM(test_name, nthreads_gen_params)
 static struct kunit_case kcsan_test_cases[] = {
+	KUNIT_CASE(test_barrier_nothreads),
 	KCSAN_KUNIT_CASE(test_basic),
 	KCSAN_KUNIT_CASE(test_concurrent_races),
 	KCSAN_KUNIT_CASE(test_novalue_change),
@@ -1112,6 +1422,10 @@ static struct kunit_case kcsan_test_cases[] = {
 	KCSAN_KUNIT_CASE(test_seqlock_noreport),
 	KCSAN_KUNIT_CASE(test_atomic_builtins),
 	KCSAN_KUNIT_CASE(test_1bit_value_change),
+	KCSAN_KUNIT_CASE(test_correct_barrier),
+	KCSAN_KUNIT_CASE(test_missing_barrier),
+	KCSAN_KUNIT_CASE(test_atomic_builtins_correct_barrier),
+	KCSAN_KUNIT_CASE(test_atomic_builtins_missing_barrier),
 	{},
 };
 
@@ -1176,6 +1490,9 @@ static int test_init(struct kunit *test)
 	observed.nlines = 0;
 	spin_unlock_irqrestore(&observed.lock, flags);
 
+	if (strstr(test->name, "nothreads"))
+		return 0;
+
 	if (!torture_init_begin((char *)test->name, 1))
 		return -EBUSY;
 
@@ -1218,6 +1535,9 @@ static void test_exit(struct kunit *test)
 	struct task_struct **stop_thread;
 	int i;
 
+	if (strstr(test->name, "nothreads"))
+		return;
+
 	if (torture_cleanup_begin())
 		return;
 
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-12-elver%40google.com.
