Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7VJ4SGQMGQEPKJXLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 12486474D86
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:47 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id i19-20020a05640242d300b003e7d13ebeedsf18275145edc.7
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519486; cv=pass;
        d=google.com; s=arc-20160816;
        b=n3w6faTXIl6pMU6bqmgoDLOMyY984cJpXg00F9RmXFDWf8HJ9OB50+Wu3qqap62PHj
         rD7S056rNWObrThqj19+GK6FTn5ajUb/L828frW/eVVJSpM6lKDiZrdhOLkWWjCkGjhh
         8C/kRbErUFJDZC4aZkMKcE0zFz+gOCkKMWgGJNRU1iu5eOROGVAB8KWgvBudywDp3giY
         bXhO9/UkFKICMRj6xNcOxag2XPSdNbIZlxVufXIb6TIv0kSBuDys5WNxsVCeiMBAgSwd
         K4V1NTLpquLd8aXGqHqd59KEdwWfSTPSRH+lo4Ap8Ztrq5ym9M0rEFg35fwcKc1N5MvJ
         0AXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=E2kpOTNRXlcWeLtspFFcfvjSwpg2Kzh5Nszfdc8oO74=;
        b=c89DaKp2TEkiFb0IyiwojzEk39UdfTJfZrC2lKSjGR6ERf1ok7eDXZhZJ7xHPROa/f
         TD5C3TsXzcrxMV4eWEn5M9r0G8mXwL0kGtIyxf5C/SvwvbIf00RdPwfI0+KzVkzhDTgN
         AADIoOqqo2yoMrnc8gCSMX3D7MnaWVMkfLXDUqB6Pxuhz1khA3fpivIt9vCaGt6NgVC3
         6HxINaWHsQ/Fg8qiqDwxiq8WkFtnU8e9nx4E17frt9wVTpMa9B75izKESn//7ztljVsD
         o3PV5kifiEHa89xxUjMJtkOhOaA6PYRIKj0niqlr6AM05e/w9Koh1JvvwCKG4wovIeUD
         8jQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jcea4MSl;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E2kpOTNRXlcWeLtspFFcfvjSwpg2Kzh5Nszfdc8oO74=;
        b=HrqWQP7po7Oq99lrFzQ68GnR6yvNsKV0NYQMqzqEkqfAUUMEVXwQDJdjHCbkbeIhrt
         SSYXBA6dJf5dZwiCrGsi3VLNJRpEJN3EEbLAJSHYNBfH7hCwobDbk3KahCHWTqVe6w2O
         Z6LN0RjvdKhwR0A+ezHF1DMjHbk9X/iP9MBGLkQVLxF1f+RxUJUltNkVpZMVoEdHVNYI
         dSRsZNAOi8f8ivLdwQbMBulzLc3848tDMAGZzc/F41WMbydXm8j/S+o5ReVkGamgRZQZ
         i2Pu+Wtuhe16seiEBx4yOZrMXdBTxgFjV7XMZ4matbK5jYSgMkp/Lcq+IX7eQmGWLiSg
         TqWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E2kpOTNRXlcWeLtspFFcfvjSwpg2Kzh5Nszfdc8oO74=;
        b=acDa4Dzk1RXoACP4QvlbP/O809a/rsYS2Xpe+fD5CCROLc6qzwVDLLnR2gIt4mclg2
         x8iDcgoNe1dfFkV4GM6fgLQ0T7oWBzxYzO6lYW7njDhQLl0rMLcIzJPwa5Lr3B5Q5mOp
         htyIm6ImLxC1t9g+6xoG/RkRE46hgbldu13YJk3S49iwVvMug+l7Nzt33z6HFHAn6Duz
         R1Ih77qJq4xJTeQKFsJkPic9vOmtiL7Ed3BqwbS7migkx6vbx9nxJnskS+XJ6PSkn/Vn
         BxxoEPbrODNXsxAnP9bxQT0FtV2Devu655C7UCTaJmQMclooqu7nea09gG3j0RBjhxxc
         7/Uw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532FZwvMc5ghl8gHc7DmkP+uUHT1HfrJVZEKWY/V3mY0Ovk/qHw0
	goF/+NNqxqQMBRE/PddRO8k=
X-Google-Smtp-Source: ABdhPJxU0xDYlZV3Z1PAU7kwTEHKpOIf+AijAwyX+Ino+LFVD7JAHlteBQSUk7lOrvIfL9SYLG4qPg==
X-Received: by 2002:a05:6402:2693:: with SMTP id w19mr11402196edd.266.1639519486866;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7b98:: with SMTP id ne24ls32091ejc.1.gmail; Tue, 14
 Dec 2021 14:04:45 -0800 (PST)
X-Received: by 2002:a17:906:71cc:: with SMTP id i12mr4175360ejk.457.1639519485802;
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519485; cv=none;
        d=google.com; s=arc-20160816;
        b=ybG8vLdsnu7LMVvXGgGW3U8z8ZUAk5Bl7Oznwwm24x6ll88X4IdILrg5uFBPzzy39N
         j4/BDyUVu8a0N3t+s1qBft7zj9dPWgvRUUxgnV49SQCgozjv00N5v7ssqrqyjtjbZbmf
         MeDcYKddFPYsCrAzvU20IF32wjrqxKPOesd5DRtYxw9N7glk8mynWxmMK7UY/ikUjuoH
         DDMqJT+9gu14rQlzcJqh0Np8y4l0rXeOniD8ucpnMA343RMjO/gV1RSWU57PQq946I1S
         OE4Ybsi23L5WQca/Cmw82dpeeYZY7/d6oPujJTDdGgKQTP9XVqbS3UAMofbhSt5dwFpT
         fzQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xf2otNj09nCdBh090zihMB0lc6NlmY0+9Bc9pmyWMsc=;
        b=g6ouV6UXjUpJhZ7aLVg1iQfQl+bMl2bxdxuxZGnsU/7p4J0y0bosk0Q5OiRw+cCA1F
         XY2UpJJRrBn64s+zJmpIp4cP16jAV/quV3DIxPt8fodSOxfm/G00jPWkvgyOmyZ6roP/
         a7J7lGwel5qyeJ6N9nweq4SXCIZhR/uYH2eziZW5dNSlPhaRlui20ss9OD7guk6iiB8k
         3XpY1ypKNlHC8cPsnhX9jxKGZdV9eHfr2rPmAie+DlEMvVPhu8ZsYAqVquVYq7USHR7s
         XXcF+bd46swxQXk5wk7guwRETGGk6pCycNpMY6pAoEMPIHWoZmGRNpSxIheIFC/xPzA3
         trUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jcea4MSl;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id nd40si3353ejc.1.2021.12.14.14.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id ADCFA616FB;
	Tue, 14 Dec 2021 22:04:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 00CEBC3461E;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 730AB5C1718; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
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
Subject: [PATCH kcsan 13/29] kcsan: selftest: Add test case to check memory barrier instrumentation
Date: Tue, 14 Dec 2021 14:04:23 -0800
Message-Id: <20211214220439.2236564-13-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jcea4MSl;       spf=pass
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

Memory barrier instrumentation is crucial to avoid false positives. To
avoid surprises, run a simple test case in the boot-time selftest to
ensure memory barriers are still instrumented correctly.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/Makefile   |   2 +
 kernel/kcsan/selftest.c | 141 ++++++++++++++++++++++++++++++++++++++++
 2 files changed, 143 insertions(+)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index c2bb07f5bcc72..ff47e896de3ba 100644
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
index b4295a3892b7c..08c6b84b9ebed 100644
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
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-13-paulmck%40kernel.org.
