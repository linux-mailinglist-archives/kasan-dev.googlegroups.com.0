Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7VJ4SGQMGQEPKJXLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id C1AEC474D83
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:46 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id n18-20020a0565120ad200b004036c43a0ddsf9199406lfu.2
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519486; cv=pass;
        d=google.com; s=arc-20160816;
        b=HR6jJSwaf0edz8eXr8Cm+xXfsa6PR3BDKmoyZOk/mbIgIKErGHqQriX7e1+7N0gSa0
         QqaqvdRngonxXpd2yf55WBCg2AtFX0Yln3UyCEgQvAz5+PdMj0UJibDxtV2pc9txA1SH
         Rnyj2ynfQO5A2PUWKi+mkIcBH2g3NdCVoqq9ehaUPWExY8arNSH1rRUEYSlcIiKFsWbP
         Lz0Am7PwrrVVIMHHWGD+Ex9L+PWdxkQM7QIBQOWP9bik9R9Dadkjv+psIEuM5PsYDt8X
         k41hmjVkoPa2NMofsABuX0+sh3NJlLtsNph5EeZAnPE4DNfyiJqcBGzMOoeE4hgFKyUR
         ee7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EYWZfzSEUNCY8SvFJ8e9RFMPMH24/wFikHruKZPTZC4=;
        b=EsGrfkHctUc9UiLlAvkIXv2F4cmOhV8OwWVOS8X3KwXDliEJhR77B/1CulzSlCfVr8
         WOgELHoRREJhIJd7943bllfZTOvchuF03WdHf+hpkAOBxMqoEn88CxeJBIqtaRdyETxx
         qqTxfqoZ0uNPvDP3iKH3U+ilpggpmjIOZhIaNQzF9Ljfq/lQM+YDasyKkWmHcYQJ3Wui
         GttRBJOF/j8G24GbmaS9sSkcGabZjSt8QIZ7XQ2v6XvCAeHwef3LtHzrrU01BRICBJxp
         6qxN7eC8hxNgQfRi+rQoKAIDOsfWYkgFmcgYUNgFg37TCrPrHrMjIB6GzNXUYiNzk82/
         o5nQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cHGYq5E6;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EYWZfzSEUNCY8SvFJ8e9RFMPMH24/wFikHruKZPTZC4=;
        b=Ay6I72FC3vegJKxwA5jSOtwH7YbjilcsbjzAYYXStJaxmzYUkEUU0do6/6wg7Ebfke
         79Ex+tKnDp/4qpYsCeQsb92b7QXM3GFOb02k49sWn52PogVSWkR3HyE7CfNM2GrtyGYj
         Hb4Nl+sqQ9npxTrsnq7M6XMu6KbccV4tIgbc575QVmzWkPRrtXl8msmnhEcKFmlQ64kh
         AZe35MtCeoGJ8mwvrTo33c6VemigkdNwhUnyosB95LkjfFy+N5tzEmI6D/INhrRvIjh7
         1Iy/NFjq5ALJXMAMJuOJHStiLOqEoflyZnIWNViO8+t8e865wV+fIqX4pj79PbN8w44X
         87SA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EYWZfzSEUNCY8SvFJ8e9RFMPMH24/wFikHruKZPTZC4=;
        b=SRljtCGR6mP486OgQGf3Eqn70BvattfE/HkEYHkWeZ7peLO8tU/xDxxAqVIuSzZzPV
         okj09hIz3f/WneAQe780QiY2q6lUIue/CH9OVKswomQ62+9u5di2L6cqdA66bFMaumhH
         VE+O1KF/53UwEO9A74HHbUT7/95q8yHUGrSScfLhNaV4jHcZemoQW1pvAJYccZeKBcBm
         WyccZiEKK9QSGIk2CgsZrg2ivZnnfa+m/xZszsl4OP9t2E/+tBP5zU9NG0AGPPLsqXc7
         R9MtxAg/qfFYs4wWgYiubjbtWvSlMczpP7EoBqaIFoNojHH54oBBsQmln/taWBFmTGeD
         sn/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533uuthgC54+dj0uUoSXQx5u1XAqpcucBl4fQSK0iAmqiFFk3wN+
	x2sxoXwZn2z1wW40njCfSVQ=
X-Google-Smtp-Source: ABdhPJypiDT+oqlRSsT7ualHmhfBxhSiqOyeh/Zq3wwzoEGjDikuYA/O3gXn2rnYXmkhwUppk+ZUKA==
X-Received: by 2002:a05:6512:3117:: with SMTP id n23mr7262186lfb.16.1639519486358;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a378:: with SMTP id i24ls32873ljn.3.gmail; Tue, 14 Dec
 2021 14:04:45 -0800 (PST)
X-Received: by 2002:a05:651c:1305:: with SMTP id u5mr7292000lja.15.1639519485145;
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519485; cv=none;
        d=google.com; s=arc-20160816;
        b=u9eCX4a/vompNpOGzSjU/fG24+ApQuBGkmo/hgWAOERzrYrucQv2K96iS+1GPHsCcL
         hJzqT4WR58SqUplxt7mherFZ8nK61+PBxMc5MiKxi4SFOs4uZKTfAT3FonSYQH9Bfnxf
         cZFx4EictqxJ/5/rD9Y+ziYWuwTqWKL+/XSwBYtSnxCp4j+BPE0/2PuVFdwtcI2tYxTZ
         KzAfNB3ft7WF5TE6a/o9IfuCsF6yUpdV/gFs5SuZyB/zcRoR7hy6LAayLuq8nedh5WeO
         xEddth8AUR0dap2HTJtRLGtkY5fg+rr7iB/a+PzZm+8ofYZ8S5AePOBMi3FHjOZ1zNn/
         ptPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GYL4n6bc1wAO/3SW7yFi1/CP+CBt1TxrutYsvaIMPlE=;
        b=00jnxAV1/eRTAYDqTzR0fY9wPJGA4E8wIcHx5RCrQ24rTg8YFLTNAtDVxv8G6QH57x
         q+/EitS9+AkrPly0uHjcxGzxb74Wyp/tgFsFBG0k10H0uCrnPmH0L+lcp8FgntXv/9rS
         thmhaNIUqlDNDMAupzY/lyHILMaz7PUnsCicgZnnKERR4x7rLdh+65Gw2nGNVmeejgDT
         cNyqspHkEBiRXGcojFXZqgU2dCFBXLSM/Gp6uBXrUch1maNm1n5PKmaT4rcjbzI9kK49
         NyuoYvi/84nC1c1xk3V/eVBEw/WZArhn59JsRpxGRueAdbNwD3qhNwMfAP/khjWqnXyg
         vwbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cHGYq5E6;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id b29si2849ljf.6.2021.12.14.14.04.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 870946172E;
	Tue, 14 Dec 2021 22:04:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E911CC34619;
	Tue, 14 Dec 2021 22:04:41 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 6EE515C1657; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
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
Subject: [PATCH kcsan 11/29] kcsan: test: Add test cases for memory barrier instrumentation
Date: Tue, 14 Dec 2021 14:04:21 -0800
Message-Id: <20211214220439.2236564-11-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cHGYq5E6;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Adds test cases to check that memory barriers are instrumented
correctly, and detection of missing memory barriers is working as
intended if CONFIG_KCSAN_STRICT=y.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/kcsan_test.c | 319 ++++++++++++++++++++++++++++++++++++++
 1 file changed, 319 insertions(+)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index ec054879201b3..5bf94550bcdf6 100644
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
@@ -466,8 +479,219 @@ static noinline void test_kernel_xor_1bit(void)
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
@@ -1039,6 +1263,90 @@ static void test_1bit_value_change(struct kunit *test)
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
@@ -1088,6 +1396,7 @@ static const void *nthreads_gen_params(const void *prev, char *desc)
 
 #define KCSAN_KUNIT_CASE(test_name) KUNIT_CASE_PARAM(test_name, nthreads_gen_params)
 static struct kunit_case kcsan_test_cases[] = {
+	KUNIT_CASE(test_barrier_nothreads),
 	KCSAN_KUNIT_CASE(test_basic),
 	KCSAN_KUNIT_CASE(test_concurrent_races),
 	KCSAN_KUNIT_CASE(test_novalue_change),
@@ -1112,6 +1421,10 @@ static struct kunit_case kcsan_test_cases[] = {
 	KCSAN_KUNIT_CASE(test_seqlock_noreport),
 	KCSAN_KUNIT_CASE(test_atomic_builtins),
 	KCSAN_KUNIT_CASE(test_1bit_value_change),
+	KCSAN_KUNIT_CASE(test_correct_barrier),
+	KCSAN_KUNIT_CASE(test_missing_barrier),
+	KCSAN_KUNIT_CASE(test_atomic_builtins_correct_barrier),
+	KCSAN_KUNIT_CASE(test_atomic_builtins_missing_barrier),
 	{},
 };
 
@@ -1176,6 +1489,9 @@ static int test_init(struct kunit *test)
 	observed.nlines = 0;
 	spin_unlock_irqrestore(&observed.lock, flags);
 
+	if (strstr(test->name, "nothreads"))
+		return 0;
+
 	if (!torture_init_begin((char *)test->name, 1))
 		return -EBUSY;
 
@@ -1218,6 +1534,9 @@ static void test_exit(struct kunit *test)
 	struct task_struct **stop_thread;
 	int i;
 
+	if (strstr(test->name, "nothreads"))
+		return;
+
 	if (torture_cleanup_begin())
 		return;
 
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-11-paulmck%40kernel.org.
