Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMUV3CGAMGQECKBJDZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 457F7455670
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:31 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id z1-20020a056512308100b003ff78e6402bsf3435167lfd.4
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223091; cv=pass;
        d=google.com; s=arc-20160816;
        b=gHejvORbgzo4ldVacqZUZvUEbP8hHtuQFa3GnKIvO0Imnw+jDD3IZLRPWSPxUqzWjh
         Ta0d1zo/aUkykAn2VhSXPBSgeDPyLIW4M0UKQ/xoIRE8CqjnHaEQ4dzfovnFbp3DBHlT
         VxB9KDdseLzRn3aS5pROw7NG02Uq3il2rPRbk3VvBWteu9nHBOtzMESysV2DkNWZMSUD
         tK8I7JQ/zqEzbUI9y/SubF4myxuncK/nBR7YPmE8x3f6l2U4XWa435MOQ2E4AjJ0ugoU
         8UJiQwbwbq8fVPEL48iovv3SwtbPnH11U2Cy4D9eNqC/mTWTKc5QGhfys3BkXruT/eqg
         4BAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=TZvjuIIinu6+Mh10qNHZoJdXkA69w3ObKOeTvkjOjlU=;
        b=MBWgmFpwigOi5kX5vIxlKR/KKLwkNsQdrff92+BvyVBdt45TWQdzFexpd0UnJUka7U
         ZsYU3tCuIeTClLETpGGbksuQgDh42o/WLZAIHCby0BM9gxQAPNtDgFtiIxiQ1eHY3djF
         V431hw5Z4pV8YwdJe03Y2CyCx8r0rZkD+4SIk7LJJlO/ePkgYwBsYRO2kuOCDuI7LGdF
         TRH50X12INCoWLE8PHzcgIB0a4SoIWBj1LEgs8GlaO6RvYqTPRNQrOfy2dLnbNL3Axxa
         r4q3JOgOkO3XG4i8rMJpgxDAoPAPz3rmx9F3jqdmFH2mGNoL/gf/rXhkG8ASU+Mh7b9h
         7H/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PWqWLyLi;
       spf=pass (google.com: domain of 3sqqwyqukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3sQqWYQUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TZvjuIIinu6+Mh10qNHZoJdXkA69w3ObKOeTvkjOjlU=;
        b=VqWMYlye6fYl99w6+Xq/+ODukmOYbA9eheEFiS2U8otErirTn0M3m3mFfur6+FaSlq
         UfcSmfcIBEQACc2NdCtC3MByCyOQ7YwDzRuK3WvhVnaYav4Wh/WUTchTk3xQ2oIYsffd
         +TXjMML1T6ooFi/FX+dG525/TvqIWkgwWfWrWsOmiwBxq2jAtQ0Efr3neh4wUqi/anC2
         DfkPLQ8zGxj0QIoDInB6NW7anxYDFprIy688XfzGQftZvr7IaSfdesi04cM+gFjMPXSK
         Xun8IY2XZFYK+d7GjMH7Y2omziGpkO+xrmlOOw2nOXmt7B4ZosPPDSjsrk92eVr87c5P
         mL6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TZvjuIIinu6+Mh10qNHZoJdXkA69w3ObKOeTvkjOjlU=;
        b=7tDVAVKbEoH3RhaZFQp1APyjy7mOM+hWy6gTuvpY6QMIYjvJ0kHuMobjvadGJTVzCE
         zqxAiXaEQFN/MsiwOnhpqMGf4f0SwvV3Nn4yT9JGSUBxUiMmYVCwAeoXobeP1xfz1NAy
         WlK4TcCblFi7hTyGgsvGYZEl6DudUnnEZ6rFzqNLgLe1obW7UMFy6H7p/YGYTIPT5Vih
         vIolZUs2XbQII6seFQ12zjL35TV8pbqgMCgwDJDDTw9xm4rgktZQBOVdpGNgbFDicMBQ
         GpZ71mB8BBRlZUKE841HhW04jhFR6DkQN9we/Cu/QnFLtrZOmw+VBwjqTduiQ5biMfTX
         u0SA==
X-Gm-Message-State: AOAM532n+FMIneGgOP0WEDgwGTWYnIV6JzsMOzkeFeTCs5JQN3eVo/3x
	ojL+K7FLRKkA3upBgyoXr8E=
X-Google-Smtp-Source: ABdhPJwQZpOwDfn/kNhGhjI7bEKft4xxSYhcbthA+NZg/fD3QvhjlNG+3RxHCFyYCc+LPItP9ZwbkQ==
X-Received: by 2002:ac2:5d4a:: with SMTP id w10mr22518180lfd.584.1637223090885;
        Thu, 18 Nov 2021 00:11:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b1f:: with SMTP id b31ls405063ljr.0.gmail; Thu, 18
 Nov 2021 00:11:29 -0800 (PST)
X-Received: by 2002:a2e:a376:: with SMTP id i22mr15060376ljn.201.1637223089763;
        Thu, 18 Nov 2021 00:11:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223089; cv=none;
        d=google.com; s=arc-20160816;
        b=sFAmL5hExLWo4YlxIhRh1pYJovcsANwBAygdfOblOoTGuAOZQHYSr1cPbgDssTPVae
         XOao4MFeuX7B7gSgyg81sq5PTdbcUCIhQT8h9LmdpbiVC6ifq3iqpnVMO02yFHDYonBM
         sDqhyf9BYYXCurnGhTA2bUKh7ke6KXv13w8QqCNb40W1TBNpAWIP52HFuFT1M4L7s2Q2
         e4i+M3dDRU1BvpJZ/E/+uzPgaW7kg7lJjY7hyz6PzJLy02tEE8eWgDlsBem+n3I/psO7
         7T75xqxgLbirTxlSfy9YXvCvD7FmPteAYCJWfF5WFJ9VRsblbuTTxjfvlZ88kLdhQ2Sx
         Be8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Iys8lzbI1Nma9PwE1F52pU9iK1Hh8M3Ac0otxw9nSQU=;
        b=PdcQZY9BqSeYCEWe0/PhWzey7cvZha+ohPnxaZqOk0C2HWq+oK8scLr09E+veUgWJE
         L4PySi1+4T5VPTTLAQTOH+ZL5pb0wKtCjAb39w6a9sY5ESzvBYN2XscaQjav2N95EKQO
         luLdnEjIpLF1UVYAgjuDzZJwWBDmdaBOnsa51rQ3fZAluCWfk0EVIwQ3segz75pR7STU
         v4qva/eUDy20oYlCcEnydYuyWcYyeoQQzOKsv4PsWlhJkpI45b6j/XbOJu04ol9Zqp/S
         WW+G0xYpWllmHRZnXTEusx5fOFEG48o8Te7p8Hrd/m6PvlJFQO+NiL4hiFZLon4mbcko
         0HoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PWqWLyLi;
       spf=pass (google.com: domain of 3sqqwyqukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3sQqWYQUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id c11si137552ljr.8.2021.11.18.00.11.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sqqwyqukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id l4-20020a05600c1d0400b00332f47a0fa3so2708810wms.8
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:29 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a1c:447:: with SMTP id 68mr7770078wme.69.1637223089466;
 Thu, 18 Nov 2021 00:11:29 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:17 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-14-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 13/23] kcsan: selftest: Add test case to check memory
 barrier instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
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
 header.i=@google.com header.s=20210112 header.b=PWqWLyLi;       spf=pass
 (google.com: domain of 3sqqwyqukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3sQqWYQUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-14-elver%40google.com.
