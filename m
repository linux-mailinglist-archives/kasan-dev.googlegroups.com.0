Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWU5TCGQMGQE3USAFRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B1264632DE
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:31 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id k25-20020a05600c1c9900b00332f798ba1dsf13613877wms.4
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272731; cv=pass;
        d=google.com; s=arc-20160816;
        b=m98/TFj6Gslzh7ny7T+7FXHfor89kfu5H6O48bWNAkPhRCuXbtsRthjLggF+LYR6f6
         afUo2gyNUK6vPTeNzXJW0yFZ0VT7XMIclVAHpolOgFZAwQjDqJ5Mft4j8YMSn/YoSgH0
         QRkGMoQzFSQZgd9JGEmkcI2vYlBeYLrDXMT+NafAHbBxb6wETnWwFABlJvIX2V/2G79T
         Bi0Jee3xAYO7fc3sj55YIHYaCMvUSQ1xNgbyh8VLDNYES/WZpMXgKO2gmxGZH1bMyuiC
         S01YkcfPVpSaa8kdY35g7Pfx+wiqN4XGRNq9v4exhaGDcoGeYqgiBUvN2QUs/u8T14/Y
         mGpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=TrqK/GsxFFZzBdeQqVFsKN9kJc5LRnzhxdwhBOd2fnQ=;
        b=G++QHmdzIab9qq6X/y3Dl1FqnsbP/u4W2KdMdjcGAVz/FybPba9iReQsU14eroeiGQ
         gTkRmSG19Hz+noF6U41FkD2SG5J+y/J57I9wE1y4nuqhSMWmOq5jLhuHFwYReuAeJtKS
         u6KDPXRiVwZJ8OOBITRQme0Q/AzZxcd33IDi+6FDT8jpiHHmkGOE8eB+idc1MnxPr3Hl
         v57YkoVP7ZKvzDp6mNyxgHYeXkky47T8BaAYvTfS4Z2nfcIo7M88EOolQh9FL9VkQ/Lb
         DzVbYQjlCcHOStOkCHgwMX87//Eoiq6QNSMIlD/pz1I1uQAmB7HXY8ayV4IXcbnTDxcD
         ztrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hXfoeu4g;
       spf=pass (google.com: domain of 32q6myqukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=32Q6mYQUKCaIGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TrqK/GsxFFZzBdeQqVFsKN9kJc5LRnzhxdwhBOd2fnQ=;
        b=YIrgSSk/FxeMVXZF/dRZemD7VFxdeXA3rM3+4IuF5OhufraIOu9GsPQWVH66ymLbzA
         MRfpk6FbdK6zrCfNaCs+XjHt8p/FJqKcbwF0E+5Eemxm7pVETYzon0OiQiJk03cKTrV0
         Hvh1DWHldNjNZ7cDbZ58NlXim+scmb2rs3Bh4Jim/XmcIxndLM1prFKC1Uhz/Dv7V59g
         01xmHOxC32IOf4kRn7eDrYiEw8ePyBAJpJn1HkKmYT64A/5OY0Y72xU3Mf6sd0fUVkAN
         TggGLOSTza4+R9BFocdrK2s9+emHfkE7FK4Cw12X3Z05zAzZjGiv4DOK7hDki6tP6SW2
         XekA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TrqK/GsxFFZzBdeQqVFsKN9kJc5LRnzhxdwhBOd2fnQ=;
        b=Kgi6uNx/kCyCW/jClfvWSNzkEPIfY7gNBT+kkJP3dm94zXo3WFJQjxFW3QtbPv6bWC
         zWPa7lznvfs2qfV1C41V+H9YjDSuaj2xXWzNtEaXvlvMtZTixnovUFkY+CnI9FtB3k+H
         Ok7vCeIRJddoox+Uz1iBc3gHVlMTKvJqLBI5UqXCKFBBIRGp5k68mgf3VeqTjLMQmqpP
         WqBro2UE0zVxhv4fT/NvbX6PJnQUatg1JsK5r6q5hVHBuqWo5gvGlnDAWu11zJjRnKat
         gM468lIhfCwUwUjUsJ6vTATz9cj9vSN/IdhHeEVmKTmcotlBnTyyToYknGPXCtdl8x0x
         n7ng==
X-Gm-Message-State: AOAM532LnJPi+6ZdNfVygf8flMg1cPqiIYbSeuDZY2wn0iAxGEXy6CUC
	W0xu2Fu5yobuJ/3fHUaMuDg=
X-Google-Smtp-Source: ABdhPJy1NTWcjrwj1Qc0TGl803GghpTap4Y9tKi7UZnPwW+U7lTCSq797F8gTi5Krfu666AK8wNAZA==
X-Received: by 2002:a5d:6e8d:: with SMTP id k13mr41433760wrz.449.1638272731119;
        Tue, 30 Nov 2021 03:45:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls13080391wrp.1.gmail; Tue, 30
 Nov 2021 03:45:30 -0800 (PST)
X-Received: by 2002:adf:e84e:: with SMTP id d14mr39339363wrn.472.1638272730262;
        Tue, 30 Nov 2021 03:45:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272730; cv=none;
        d=google.com; s=arc-20160816;
        b=emECp/RR9BkCbZQ8zdoIcF6ylUM1fF4zo/+Ws4vijGlxCNGKd7GLjrliZ/8pd6dVXQ
         3Mh1SQdo9lEk9NOMcbO35hsW4YGcmx4ebgmXArATHSDhmsGGxDgA8OEUjud3WAjk9a4N
         AGCMc0W8dkqzLBitbAa43oU8OA7xQcfeHHnW5P/v4mrYBh1XIE2LLFfKTRRGDJMK6T5T
         zyR4LZeMRXlNxZk95Z1lcOPBui0Tet4CH2wNs0wbAupahzrvDhqrVHqgqDBc+jiiiHkr
         A979YiXLbSmVl2FrWgGAYII52FvuNoj++nF7heInJzgEXvweVkyx2FVzHggvrRByAlcK
         beHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ueZBGQAcZiHgxT7Io+0KmuSM9UUBjHQcOH6LTEM0h4A=;
        b=bXZ6xR/v3R7Nov7hvVrD6NFoTunybu9T2x+WZl2mtJuOCnaXyMvrTRytBfDeb/H7sl
         Sp9Sn40KWMEGP+fYlc6j3alcqiA7jV1iJBpZX6QY3Qi8+fWP63fgQ9aUOkOAnb5P1qgo
         9YZZE4kq6oOfDWOJ5eDd6eXik7aGQ0y0MyfC9YCVehPZ8f6x54k4gxjFJ5WEyKXcwmoU
         SeouSsuutEFpJhrvfpwEjUX5o5PMDNI29747KPHCfu/am0qPDwOU5tDjYRruXhojSMk5
         DF65QjRqrRBfptLf8sWkB79AXlHuP4WY06VxbE7XHz/XMkr7rcRnnBfDz+Z57AV8EKmb
         R+BQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hXfoeu4g;
       spf=pass (google.com: domain of 32q6myqukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=32Q6mYQUKCaIGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id r6si1120497wrj.2.2021.11.30.03.45.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:30 -0800 (PST)
Received-SPF: pass (google.com: domain of 32q6myqukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id b1-20020a5d6341000000b001901ddd352eso3539212wrw.7
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:30 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:2117:: with SMTP id
 u23mr4424316wml.19.1638272729928; Tue, 30 Nov 2021 03:45:29 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:19 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-12-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 11/25] kcsan: test: Add test cases for memory barrier instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hXfoeu4g;       spf=pass
 (google.com: domain of 32q6myqukcaignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=32Q6mYQUKCaIGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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
v3:
* Remove __no_kcsan from barrier test, given __no_kcsan would now remove
  barrier instrumentation, too.
---
 kernel/kcsan/kcsan_test.c | 319 ++++++++++++++++++++++++++++++++++++++
 1 file changed, 319 insertions(+)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index ec054879201b..5bf94550bcdf 100644
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
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-12-elver%40google.com.
