Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYE5TCGQMGQEQSNR5ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id E17014632E5
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:36 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id y11-20020a2e978b000000b00218df7f76fesf7535122lji.11
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272736; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gp5Davtk7MKbhMLup0YH3bdaz6NBvkAtdw4Rhf0mfLjB8cc2X7CfRf6bXuVwS8Wseg
         gWfhqfI+ddq9cKoJYC4W98Trwdk2WIBkBd6rZFeq/tbcWix9ldysPy5PG1xp383xpZ87
         pu/LmLPfe9rj29x14RPDpxeHbkZ/7RvK6TghmGwubIcWlbVmzxIVCF9zSStKROxI6WGk
         OcnQpbBOWwuDu1tSL+XrpYC9ca+eqFHRBWsqO119y0Dp3GcO081jc/QlcbXiA2wdvfJD
         AUln8hwpkvUzgadyXA6MDvUh1mWunYL8MlWkfOtZe3ST5cBI3Oe+rBpR8BqfmMCDE5Dh
         3uyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=hCdjS5YcsL1dkJd95dxt0QCf54IwtJEJoDzmNn57nqc=;
        b=vCnPTGYncbq3RAuRqhTPzm9r4v6Wdejb+IMyrrAyWbfJQFGw2Q5+hkWJJDAySTO/Sn
         acDSDW2CmDybzFF2rSk1Z25IfKikuJdbNZ5uYfJqVoz7j+DxL1uCr/0vFMBtnvFrc3Pr
         wqpX7ZW/b/9CRQL9bIy3iZ+sZP9t+1+tqexZTIEl+qRcdVH0pu02guIUtaeji4LBCh01
         hi9XsDpVQUg8n5hQd3FPP3ep3WZGw9ixTcR/xOZfHAutq5bioe2bAwBSj8o43kINy5Rp
         JB4BnEwMqkILZ6ikUqEKhNNx220/tH14emCDC+/uT+heu6+Ca7AOxTYCrSl07OBdsiu2
         T5JA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="J8vmyXS/";
       spf=pass (google.com: domain of 33g6myqukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=33g6mYQUKCacLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hCdjS5YcsL1dkJd95dxt0QCf54IwtJEJoDzmNn57nqc=;
        b=el6UGiIbzoTvazo99huehesCelkmClsIE695eIEeOXvZ7RYXz8x3k5/8pN2PhwdigA
         GXQB6vYx/f6OVoIdpDygsXxjNSuRlyKSJmXO2HjVTEvMNr4jm9kLcGSUz6Fw61qVIVaj
         Gr5Et0jwpkVSbvNMV5dQC4sxLTGdGQmfxGVEc+4qwaX0VwtV1oE3zjVuqgjEnBTSpWb2
         hOtXyopeTS4bf+t+dy0UsGDZ0g0I3bNpee8ynezU9GoOCXYpmVlA3TEPKqqaMT4yyPCK
         IUvAcR+HPZM+NxkWj4i+274yNmwNryP2f4jH1WSOfkXSqR49BGDqV9Ba3vh5hzhY2joc
         4GQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hCdjS5YcsL1dkJd95dxt0QCf54IwtJEJoDzmNn57nqc=;
        b=3oN5SeelDvFPUYiYgPXJzEYITdUKr9sysO/+qbEpaQQK9N0r34gWuuo/WjSxVHLeMC
         V1rHXN3Syk3nnlCGpqCCO97WrwG0C7ijln3ReKzqB0NqJ6pcVts9GxKp9b8DfJuxdNUD
         KSxynUXbcHhzv71BdhQH3L1jgdNjKpr+LYhZ7uZGDSIv1iJThH0wOnEYcXg6l+y/HuYT
         1XaEDmw+S5VGFF6mXHBW9FxyaYKh7u4HDi3LKFSpGv+BS66K3YvF5vcFyLnjt3OX0u8z
         YMzSvj8NPiLjwGA5nAGM9KNj2JRA/xqDPeF4AeQ90515knUngHDQMv1ebIuanfEKXQVi
         vxQQ==
X-Gm-Message-State: AOAM532Pt40wyIaU1jsE4w2gWy1ak+H1Pj41x9HEr/X+L/HCFzzQZBQc
	l4WhbawTIC+hYR0XZDDh8n4=
X-Google-Smtp-Source: ABdhPJzgNorKpgFIIC6+7QBa3nXZuWEZiLbokhAc0M9l329JlDUQy9v2GSDMXTyaOsgm6iO84vOJSQ==
X-Received: by 2002:ac2:53ad:: with SMTP id j13mr51854684lfh.225.1638272736491;
        Tue, 30 Nov 2021 03:45:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e10:: with SMTP id i16ls453878lfv.3.gmail; Tue, 30
 Nov 2021 03:45:35 -0800 (PST)
X-Received: by 2002:a05:6512:1107:: with SMTP id l7mr52258847lfg.318.1638272735439;
        Tue, 30 Nov 2021 03:45:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272735; cv=none;
        d=google.com; s=arc-20160816;
        b=NxxWZMKt2TRkXdMT+jJkMqqa8e1ZI16qjsAa5NJedJdCUelBMTe7cmQZJX7agY7G7U
         49lFro2iIseT028MAxsqhqLcLMSALGZa1FwEi3f5i+E/Vv9MHjWzPBchPCjsyS6fgwse
         iDmzMS4QuLzEfIV4rhoX8jSaoxq99aBESvpRuwAbcI9eui9ykqTcm+OE9RrD9DRQRYlX
         69h/pHnl4TPO96sMaW3xSWryO52uKRBxcgyEv72KjrCNnMCkTIOlakPRWm8KuQ9vlVUs
         rzEPpZsFJ6PBw4YHKVmaRxLDHpWy9nxTgzWO99EdMKurq0Sfh3JhfPZUmLzIZMVSxJCJ
         4MrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Iys8lzbI1Nma9PwE1F52pU9iK1Hh8M3Ac0otxw9nSQU=;
        b=DHqHmDtErT473q5QdMZKcArYOIOk/ZKQGCYyhqefA9Y1YMR8eDjTPR00akiNllqR7n
         +G2jDO8H/Ou90EzBn9C0uaGzwhOZq15mxfUPgOcN/v5jJuANqR5owcRG9Z986aAE0tjF
         s+kQO7RpWNW5gEd/lvsY3g3DATo1ovFRgAxlhP12FqRIcbteEb6apPclRXuvd+1qUJd3
         pUMPEjOexJP8omKkDj3B9hReePOHOLSaGAntG4gZNCPBY1ySx5XEkCgryXAM7hLmtlA9
         q5zOrn2YBdZKXrfLVuI5Tyx7TmnFJrUq6cZ9nOY3IlzlgOXkuYEXuJSaWw+LokqbwV5i
         +FGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="J8vmyXS/";
       spf=pass (google.com: domain of 33g6myqukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=33g6mYQUKCacLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id b29si1453334ljf.6.2021.11.30.03.45.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 33g6myqukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id h13-20020adfa4cd000000b001883fd029e8so3536574wrb.11
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:35 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:1993:: with SMTP id
 t19mr4402473wmq.21.1638272734879; Tue, 30 Nov 2021 03:45:34 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:21 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-14-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 13/25] kcsan: selftest: Add test case to check memory
 barrier instrumentation
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
 header.i=@google.com header.s=20210112 header.b="J8vmyXS/";       spf=pass
 (google.com: domain of 33g6myqukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=33g6mYQUKCacLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
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

Memory barrier instrumentation is crucial to avoid false positives. To
avoid surprises, run a simple test case in the boot-time selftest to
ensure memory barriers are still instrumented correctly.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/Makefile   |   2 +
 kernel/kcsan/selftest.c | 141 ++++++++++++++++++++++++++++++++++++++++
 2 files changed, 143 insertions(+)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index c2bb07f5bcc7..ff47e896de3b 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -11,6 +11,8 @@ CFLAGS_core.o := $(call cc-option,-fno-conserve-stack) \
 	-fno-stack-protector -DDISABLE_BRANCH_PROFILING
 
 obj-y := core.o debugfs.o report.o
+
+KCSAN_INSTRUMENT_BARRIERS_selftest.o := y
 obj-$(CONFIG_KCSAN_SELFTEST) += selftest.o
 
 CFLAGS_kcsan_test.o := $(CFLAGS_KCSAN) -g -fno-omit-frame-pointer
diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
index b4295a3892b7..08c6b84b9ebe 100644
--- a/kernel/kcsan/selftest.c
+++ b/kernel/kcsan/selftest.c
@@ -7,10 +7,15 @@
 
 #define pr_fmt(fmt) "kcsan: " fmt
 
+#include <linux/atomic.h>
+#include <linux/bitops.h>
 #include <linux/init.h>
+#include <linux/kcsan-checks.h>
 #include <linux/kernel.h>
 #include <linux/printk.h>
 #include <linux/random.h>
+#include <linux/sched.h>
+#include <linux/spinlock.h>
 #include <linux/types.h>
 
 #include "encoding.h"
@@ -103,6 +108,141 @@ static bool __init test_matching_access(void)
 	return true;
 }
 
+/*
+ * Correct memory barrier instrumentation is critical to avoiding false
+ * positives: simple test to check at boot certain barriers are always properly
+ * instrumented. See kcsan_test for a more complete test.
+ */
+static bool __init test_barrier(void)
+{
+#ifdef CONFIG_KCSAN_WEAK_MEMORY
+	struct kcsan_scoped_access *reorder_access = &current->kcsan_ctx.reorder_access;
+#else
+	struct kcsan_scoped_access *reorder_access = NULL;
+#endif
+	bool ret = true;
+	arch_spinlock_t arch_spinlock = __ARCH_SPIN_LOCK_UNLOCKED;
+	DEFINE_SPINLOCK(spinlock);
+	atomic_t dummy;
+	long test_var;
+
+	if (!reorder_access || !IS_ENABLED(CONFIG_SMP))
+		return true;
+
+#define __KCSAN_CHECK_BARRIER(access_type, barrier, name)					\
+	do {											\
+		reorder_access->type = (access_type) | KCSAN_ACCESS_SCOPED;			\
+		reorder_access->size = 1;							\
+		barrier;									\
+		if (reorder_access->size != 0) {						\
+			pr_err("improperly instrumented type=(" #access_type "): " name "\n");	\
+			ret = false;								\
+		}										\
+	} while (0)
+#define KCSAN_CHECK_READ_BARRIER(b)  __KCSAN_CHECK_BARRIER(0, b, #b)
+#define KCSAN_CHECK_WRITE_BARRIER(b) __KCSAN_CHECK_BARRIER(KCSAN_ACCESS_WRITE, b, #b)
+#define KCSAN_CHECK_RW_BARRIER(b)    __KCSAN_CHECK_BARRIER(KCSAN_ACCESS_WRITE | KCSAN_ACCESS_COMPOUND, b, #b)
+
+	kcsan_nestable_atomic_begin(); /* No watchpoints in called functions. */
+
+	KCSAN_CHECK_READ_BARRIER(mb());
+	KCSAN_CHECK_READ_BARRIER(rmb());
+	KCSAN_CHECK_READ_BARRIER(smp_mb());
+	KCSAN_CHECK_READ_BARRIER(smp_rmb());
+	KCSAN_CHECK_READ_BARRIER(dma_rmb());
+	KCSAN_CHECK_READ_BARRIER(smp_mb__before_atomic());
+	KCSAN_CHECK_READ_BARRIER(smp_mb__after_atomic());
+	KCSAN_CHECK_READ_BARRIER(smp_mb__after_spinlock());
+	KCSAN_CHECK_READ_BARRIER(smp_store_mb(test_var, 0));
+	KCSAN_CHECK_READ_BARRIER(smp_store_release(&test_var, 0));
+	KCSAN_CHECK_READ_BARRIER(xchg(&test_var, 0));
+	KCSAN_CHECK_READ_BARRIER(xchg_release(&test_var, 0));
+	KCSAN_CHECK_READ_BARRIER(cmpxchg(&test_var, 0,  0));
+	KCSAN_CHECK_READ_BARRIER(cmpxchg_release(&test_var, 0,  0));
+	KCSAN_CHECK_READ_BARRIER(atomic_set_release(&dummy, 0));
+	KCSAN_CHECK_READ_BARRIER(atomic_add_return(1, &dummy));
+	KCSAN_CHECK_READ_BARRIER(atomic_add_return_release(1, &dummy));
+	KCSAN_CHECK_READ_BARRIER(atomic_fetch_add(1, &dummy));
+	KCSAN_CHECK_READ_BARRIER(atomic_fetch_add_release(1, &dummy));
+	KCSAN_CHECK_READ_BARRIER(test_and_set_bit(0, &test_var));
+	KCSAN_CHECK_READ_BARRIER(test_and_clear_bit(0, &test_var));
+	KCSAN_CHECK_READ_BARRIER(test_and_change_bit(0, &test_var));
+	KCSAN_CHECK_READ_BARRIER(clear_bit_unlock(0, &test_var));
+	KCSAN_CHECK_READ_BARRIER(__clear_bit_unlock(0, &test_var));
+	KCSAN_CHECK_READ_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var));
+	arch_spin_lock(&arch_spinlock);
+	KCSAN_CHECK_READ_BARRIER(arch_spin_unlock(&arch_spinlock));
+	spin_lock(&spinlock);
+	KCSAN_CHECK_READ_BARRIER(spin_unlock(&spinlock));
+
+	KCSAN_CHECK_WRITE_BARRIER(mb());
+	KCSAN_CHECK_WRITE_BARRIER(wmb());
+	KCSAN_CHECK_WRITE_BARRIER(smp_mb());
+	KCSAN_CHECK_WRITE_BARRIER(smp_wmb());
+	KCSAN_CHECK_WRITE_BARRIER(dma_wmb());
+	KCSAN_CHECK_WRITE_BARRIER(smp_mb__before_atomic());
+	KCSAN_CHECK_WRITE_BARRIER(smp_mb__after_atomic());
+	KCSAN_CHECK_WRITE_BARRIER(smp_mb__after_spinlock());
+	KCSAN_CHECK_WRITE_BARRIER(smp_store_mb(test_var, 0));
+	KCSAN_CHECK_WRITE_BARRIER(smp_store_release(&test_var, 0));
+	KCSAN_CHECK_WRITE_BARRIER(xchg(&test_var, 0));
+	KCSAN_CHECK_WRITE_BARRIER(xchg_release(&test_var, 0));
+	KCSAN_CHECK_WRITE_BARRIER(cmpxchg(&test_var, 0,  0));
+	KCSAN_CHECK_WRITE_BARRIER(cmpxchg_release(&test_var, 0,  0));
+	KCSAN_CHECK_WRITE_BARRIER(atomic_set_release(&dummy, 0));
+	KCSAN_CHECK_WRITE_BARRIER(atomic_add_return(1, &dummy));
+	KCSAN_CHECK_WRITE_BARRIER(atomic_add_return_release(1, &dummy));
+	KCSAN_CHECK_WRITE_BARRIER(atomic_fetch_add(1, &dummy));
+	KCSAN_CHECK_WRITE_BARRIER(atomic_fetch_add_release(1, &dummy));
+	KCSAN_CHECK_WRITE_BARRIER(test_and_set_bit(0, &test_var));
+	KCSAN_CHECK_WRITE_BARRIER(test_and_clear_bit(0, &test_var));
+	KCSAN_CHECK_WRITE_BARRIER(test_and_change_bit(0, &test_var));
+	KCSAN_CHECK_WRITE_BARRIER(clear_bit_unlock(0, &test_var));
+	KCSAN_CHECK_WRITE_BARRIER(__clear_bit_unlock(0, &test_var));
+	KCSAN_CHECK_WRITE_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var));
+	arch_spin_lock(&arch_spinlock);
+	KCSAN_CHECK_WRITE_BARRIER(arch_spin_unlock(&arch_spinlock));
+	spin_lock(&spinlock);
+	KCSAN_CHECK_WRITE_BARRIER(spin_unlock(&spinlock));
+
+	KCSAN_CHECK_RW_BARRIER(mb());
+	KCSAN_CHECK_RW_BARRIER(wmb());
+	KCSAN_CHECK_RW_BARRIER(rmb());
+	KCSAN_CHECK_RW_BARRIER(smp_mb());
+	KCSAN_CHECK_RW_BARRIER(smp_wmb());
+	KCSAN_CHECK_RW_BARRIER(smp_rmb());
+	KCSAN_CHECK_RW_BARRIER(dma_wmb());
+	KCSAN_CHECK_RW_BARRIER(dma_rmb());
+	KCSAN_CHECK_RW_BARRIER(smp_mb__before_atomic());
+	KCSAN_CHECK_RW_BARRIER(smp_mb__after_atomic());
+	KCSAN_CHECK_RW_BARRIER(smp_mb__after_spinlock());
+	KCSAN_CHECK_RW_BARRIER(smp_store_mb(test_var, 0));
+	KCSAN_CHECK_RW_BARRIER(smp_store_release(&test_var, 0));
+	KCSAN_CHECK_RW_BARRIER(xchg(&test_var, 0));
+	KCSAN_CHECK_RW_BARRIER(xchg_release(&test_var, 0));
+	KCSAN_CHECK_RW_BARRIER(cmpxchg(&test_var, 0,  0));
+	KCSAN_CHECK_RW_BARRIER(cmpxchg_release(&test_var, 0,  0));
+	KCSAN_CHECK_RW_BARRIER(atomic_set_release(&dummy, 0));
+	KCSAN_CHECK_RW_BARRIER(atomic_add_return(1, &dummy));
+	KCSAN_CHECK_RW_BARRIER(atomic_add_return_release(1, &dummy));
+	KCSAN_CHECK_RW_BARRIER(atomic_fetch_add(1, &dummy));
+	KCSAN_CHECK_RW_BARRIER(atomic_fetch_add_release(1, &dummy));
+	KCSAN_CHECK_RW_BARRIER(test_and_set_bit(0, &test_var));
+	KCSAN_CHECK_RW_BARRIER(test_and_clear_bit(0, &test_var));
+	KCSAN_CHECK_RW_BARRIER(test_and_change_bit(0, &test_var));
+	KCSAN_CHECK_RW_BARRIER(clear_bit_unlock(0, &test_var));
+	KCSAN_CHECK_RW_BARRIER(__clear_bit_unlock(0, &test_var));
+	KCSAN_CHECK_RW_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var));
+	arch_spin_lock(&arch_spinlock);
+	KCSAN_CHECK_RW_BARRIER(arch_spin_unlock(&arch_spinlock));
+	spin_lock(&spinlock);
+	KCSAN_CHECK_RW_BARRIER(spin_unlock(&spinlock));
+
+	kcsan_nestable_atomic_end();
+
+	return ret;
+}
+
 static int __init kcsan_selftest(void)
 {
 	int passed = 0;
@@ -120,6 +260,7 @@ static int __init kcsan_selftest(void)
 	RUN_TEST(test_requires);
 	RUN_TEST(test_encode_decode);
 	RUN_TEST(test_matching_access);
+	RUN_TEST(test_barrier);
 
 	pr_info("selftest: %d/%d tests passed\n", passed, total);
 	if (passed != total)
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-14-elver%40google.com.
