Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7VJ4SGQMGQEPKJXLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 6817F474D8D
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:47 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id t25-20020a2e8e79000000b0021b5c659213sf6029478ljk.10
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519487; cv=pass;
        d=google.com; s=arc-20160816;
        b=pUK/pogn3STck8gBJsa1mCMo5OThV4tZgad7uHSjXhk0Jr/KHGjXurK/PEhXJzMs1y
         t/uj0SZRZBabwmdXaIrxSRN6Iea7ZRjZGnv/+vMIt7+dNmGcE6ghE0sPzST3SfHFLYCI
         ocGrPUDOUB9oPgyhiUGBrWozZxWgdt20m/lcEr19Z57NOjOVCqvsmI7bcria7Wyi+N8s
         rnNu/rX0m5je56WMvJRcTpMzx8ClwN3XIbIXDBmw8uLn3kwJEucwxlOF8M4+V8/fTkSn
         nAp583XzhYifjnfK+U8VJwtwSP8evlrDXltV7O8OPnaj77F+EoxLqAAwOET9xdI5qFMB
         g4ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mgeoBM3w0xlykIkbvV0ZSrOkk1Yywl5OSFrEZFzxVb4=;
        b=UXjMC4/6wjDJyCImX14eeqrAp4hGkSqyPC+KZR5vStwRBO9/Uxb3mytsT4Dk6CY+KZ
         rens54Uv8Ef5g+2KXz+NaYbjtJu4Ky3US+liK3kUwbNRdsjto5BUIeHXYKOPbztPYuZa
         os6b4VWHqy3FIxW+GP+2iuQKVTn3gxS7ZfBdNSrsrcPkrXpXHYy4xzZfliEVkk7QgvdB
         qM9TyTl28e/F1X+oO5NBDWtkOamBCYVNURkzek1SdAkfziClI5VME3qPQ8h4dJp5Pm86
         XnWxMmgH4WN0rQ1uRLqSFYq/vnn59v3bFvOZ1eBM15wj4idyi2Mgd89WyoVqBdy5QmA9
         a0zA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kYKDFmh4;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mgeoBM3w0xlykIkbvV0ZSrOkk1Yywl5OSFrEZFzxVb4=;
        b=W/D+Jq2hJAxskluK8GpZtNVIFxuLcrCZMmp/Fg7yZ7Qkeera5xcCcxUO3b9SCuNYib
         4O3pKTsetqjbxjCTmAkF6bj5xMNO3saF9Se+4ZUttlBUMQI4XtUFCPOB76FRR0bkKyiN
         Emt7hQdfGU4GOc7ujX8+hBi9lejk9q7kstzD1bzXFbTxOr1kl/HfJ+sws5zkLuT6/b6D
         ZdDkQWyBkXh6gARJhkVicFOjQu9dZHT02BMruINbiDTkYzrYiutbtv5EZSbRk6PbxMPn
         TarTjcgvPIhGU3Ohu6Vpn+JHiTFIbTgvadCkjHpKRit3KxW41MnSkt1rGCKa8Z8upMKZ
         9ufA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mgeoBM3w0xlykIkbvV0ZSrOkk1Yywl5OSFrEZFzxVb4=;
        b=03UXlEuShNo7OTtTSW62WfeAf1qFJ46SIPsLC1pfa0Z4jURVr/vXiR6JeorXaj4x6C
         3LUNfYF7qBHAH6YTh+J0cCks2F8W3K+2dsng/du1dMpinS6znLcUnZ9/Qg7ul32gzNL7
         yylvVh4HDHr4O8h+V/6/jSBuefigkiDc34d09AT+dck4eJ6Rb8iYJxn/GUhOAeTDmzr5
         Ypys407EtI51soMGjhEhB/qK7lfMK0TUHOB1taCw6LsF8TMCaYdilICgPn/9/qRha8Q2
         w0gI0cL17eUbdTm+CY1zSOuqaTqh2WrgocDKWrRUZHJXsX4Vf+Bvx/M3/02ZienrGaCB
         5G0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532c9pgn1azogoTHVGjDTcWHSX6CVtR4J1HZ02GW9UqQPbguDJyy
	amO3qpOucWeDX9lPipSW9F8=
X-Google-Smtp-Source: ABdhPJyZSK0caKPKCPtCwvHK94Ot7noBKzQl0SSaGUkx1goZYuwIjZ8X71NIsPMa3g/HZ/b83dR7wg==
X-Received: by 2002:a05:6512:6d0:: with SMTP id u16mr3490623lff.626.1639519486976;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c4:: with SMTP id x4ls30232ljp.8.gmail; Tue, 14 Dec
 2021 14:04:45 -0800 (PST)
X-Received: by 2002:a05:651c:c3:: with SMTP id 3mr7053389ljr.170.1639519485797;
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519485; cv=none;
        d=google.com; s=arc-20160816;
        b=oyYnS3cwJxiz3WzrywRqwcfbUPing0mzk4dwffDqIVcz/4Z9dAlf5GbRqjRR7eR1/F
         kRpIXEasYFcY7ro+J+H3uEudNV9su87E53T7mImuqV3e60OJIA2s2qlbK+cwCEsmmrfZ
         e83K6RlY1c722/QIF2Aw9sV9GH9nbQjyZdFjjeSiftKnwl09kVHnJuSJFW61VHsZgAje
         SHEcwL5rrcBIxaafARjxAcjVHamoHk+ahHjxm3eKavi47yEXw49SZQ2Xt4WiZR54aGvQ
         /sSUNE2ng1+rZqxMDd25CMmXyXjXNkBsyL8nO9wUyb2jXwle6K8lajjusW8AhVCCfLki
         6q5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gniQnUWsJtG+zSCVYN4SNGkbZsoW9TQyGEQeaSSjlco=;
        b=iBz+XZi/PMsGW1n+dnCD3HfAuNMT3+mVYSBYfyLdAGSQoYJZgX9X7nKsBnVHXr+mu3
         mb643KdwoaXB3z0KgKNRwZ5FB8ce/SsyYdB0okawE+4KoGX4ZiAxeo2ZywqfM84RPsoR
         pCO9eg4er6mwHu94Hu3hwB5YWsmcY4jxAHWxs5E9U797sOKxZykEYlF/cyZI/pCNWLoE
         xXaOVh7WdCniXOC80v9uZI7OtcnYPyYim749VfUyK/sBpm23GCXyXTTPgFUgshMUoqaE
         JeXJR/8D8TIVRTPK7Co+5H6H8Bd6p/Gt2I/wZK+psKG/kukyYgPKDGz8Kg+NGvlt34YC
         zc6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kYKDFmh4;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id b29si2849ljf.6.2021.12.14.14.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 663E561765;
	Tue, 14 Dec 2021 22:04:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3ED49C004DD;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 8C0185C2699; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
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
Subject: [PATCH kcsan 26/29] kcsan: Make barrier tests compatible with lockdep
Date: Tue, 14 Dec 2021 14:04:36 -0800
Message-Id: <20211214220439.2236564-26-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kYKDFmh4;       spf=pass
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

The barrier tests in selftest and the kcsan_test module only need the
spinlock and mutex to test correct barrier instrumentation. Therefore,
these were initially placed on the stack.

However, lockdep asserts that locks are in static storage, and will
generate this warning:

 | INFO: trying to register non-static key.
 | The code is fine but needs lockdep annotation, or maybe
 | you didn't initialize this object before use?
 | turning off the locking correctness validator.
 | CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.16.0-rc1+ #3208
 | Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.13.0-1ubuntu1.1 04/01/2014
 | Call Trace:
 |  <TASK>
 |  dump_stack_lvl+0x88/0xd8
 |  dump_stack+0x15/0x1b
 |  register_lock_class+0x6b3/0x840
 |  ...
 |  test_barrier+0x490/0x14c7
 |  kcsan_selftest+0x47/0xa0
 |  ...

To fix, move the test locks into static storage.

Fixing the above also revealed that lock operations are strengthened on
first use with lockdep enabled, due to lockdep calling out into
non-instrumented files (recall that kernel/locking/lockdep.c is not
instrumented with KCSAN).

Only kcsan_test checks for over-instrumentation of *_lock() operations,
where we can simply "warm up" the test locks to avoid the test case
failing with lockdep.

Reported-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/kcsan_test.c | 37 +++++++++++++++++++++++--------------
 kernel/kcsan/selftest.c   | 14 +++++++-------
 2 files changed, 30 insertions(+), 21 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 5bf94550bcdf6..2bad0820f73ad 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -300,6 +300,8 @@ static struct {
 	long val[8];
 } test_struct;
 static DEFINE_SEQLOCK(test_seqlock);
+static DEFINE_SPINLOCK(test_spinlock);
+static DEFINE_MUTEX(test_mutex);
 
 /*
  * Helper to avoid compiler optimizing out reads, and to generate source values
@@ -523,8 +525,6 @@ static void test_barrier_nothreads(struct kunit *test)
 	struct kcsan_scoped_access *reorder_access = NULL;
 #endif
 	arch_spinlock_t arch_spinlock = __ARCH_SPIN_LOCK_UNLOCKED;
-	DEFINE_SPINLOCK(spinlock);
-	DEFINE_MUTEX(mutex);
 	atomic_t dummy;
 
 	KCSAN_TEST_REQUIRES(test, reorder_access != NULL);
@@ -543,6 +543,15 @@ static void test_barrier_nothreads(struct kunit *test)
 #define KCSAN_EXPECT_WRITE_BARRIER(b, o) __KCSAN_EXPECT_BARRIER(KCSAN_ACCESS_WRITE, b, o, #b)
 #define KCSAN_EXPECT_RW_BARRIER(b, o)    __KCSAN_EXPECT_BARRIER(KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE, b, o, #b)
 
+	/*
+	 * Lockdep initialization can strengthen certain locking operations due
+	 * to calling into instrumented files; "warm up" our locks.
+	 */
+	spin_lock(&test_spinlock);
+	spin_unlock(&test_spinlock);
+	mutex_lock(&test_mutex);
+	mutex_unlock(&test_mutex);
+
 	/* Force creating a valid entry in reorder_access first. */
 	test_var = 0;
 	while (test_var++ < 1000000 && reorder_access->size != sizeof(test_var))
@@ -592,10 +601,10 @@ static void test_barrier_nothreads(struct kunit *test)
 	KCSAN_EXPECT_READ_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var), true);
 	KCSAN_EXPECT_READ_BARRIER(arch_spin_lock(&arch_spinlock), false);
 	KCSAN_EXPECT_READ_BARRIER(arch_spin_unlock(&arch_spinlock), true);
-	KCSAN_EXPECT_READ_BARRIER(spin_lock(&spinlock), false);
-	KCSAN_EXPECT_READ_BARRIER(spin_unlock(&spinlock), true);
-	KCSAN_EXPECT_READ_BARRIER(mutex_lock(&mutex), false);
-	KCSAN_EXPECT_READ_BARRIER(mutex_unlock(&mutex), true);
+	KCSAN_EXPECT_READ_BARRIER(spin_lock(&test_spinlock), false);
+	KCSAN_EXPECT_READ_BARRIER(spin_unlock(&test_spinlock), true);
+	KCSAN_EXPECT_READ_BARRIER(mutex_lock(&test_mutex), false);
+	KCSAN_EXPECT_READ_BARRIER(mutex_unlock(&test_mutex), true);
 
 	KCSAN_EXPECT_WRITE_BARRIER(mb(), true);
 	KCSAN_EXPECT_WRITE_BARRIER(wmb(), true);
@@ -638,10 +647,10 @@ static void test_barrier_nothreads(struct kunit *test)
 	KCSAN_EXPECT_WRITE_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var), true);
 	KCSAN_EXPECT_WRITE_BARRIER(arch_spin_lock(&arch_spinlock), false);
 	KCSAN_EXPECT_WRITE_BARRIER(arch_spin_unlock(&arch_spinlock), true);
-	KCSAN_EXPECT_WRITE_BARRIER(spin_lock(&spinlock), false);
-	KCSAN_EXPECT_WRITE_BARRIER(spin_unlock(&spinlock), true);
-	KCSAN_EXPECT_WRITE_BARRIER(mutex_lock(&mutex), false);
-	KCSAN_EXPECT_WRITE_BARRIER(mutex_unlock(&mutex), true);
+	KCSAN_EXPECT_WRITE_BARRIER(spin_lock(&test_spinlock), false);
+	KCSAN_EXPECT_WRITE_BARRIER(spin_unlock(&test_spinlock), true);
+	KCSAN_EXPECT_WRITE_BARRIER(mutex_lock(&test_mutex), false);
+	KCSAN_EXPECT_WRITE_BARRIER(mutex_unlock(&test_mutex), true);
 
 	KCSAN_EXPECT_RW_BARRIER(mb(), true);
 	KCSAN_EXPECT_RW_BARRIER(wmb(), true);
@@ -684,10 +693,10 @@ static void test_barrier_nothreads(struct kunit *test)
 	KCSAN_EXPECT_RW_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var), true);
 	KCSAN_EXPECT_RW_BARRIER(arch_spin_lock(&arch_spinlock), false);
 	KCSAN_EXPECT_RW_BARRIER(arch_spin_unlock(&arch_spinlock), true);
-	KCSAN_EXPECT_RW_BARRIER(spin_lock(&spinlock), false);
-	KCSAN_EXPECT_RW_BARRIER(spin_unlock(&spinlock), true);
-	KCSAN_EXPECT_RW_BARRIER(mutex_lock(&mutex), false);
-	KCSAN_EXPECT_RW_BARRIER(mutex_unlock(&mutex), true);
+	KCSAN_EXPECT_RW_BARRIER(spin_lock(&test_spinlock), false);
+	KCSAN_EXPECT_RW_BARRIER(spin_unlock(&test_spinlock), true);
+	KCSAN_EXPECT_RW_BARRIER(mutex_lock(&test_mutex), false);
+	KCSAN_EXPECT_RW_BARRIER(mutex_unlock(&test_mutex), true);
 
 	kcsan_nestable_atomic_end();
 }
diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
index 08c6b84b9ebed..b6d4da07d80a1 100644
--- a/kernel/kcsan/selftest.c
+++ b/kernel/kcsan/selftest.c
@@ -113,6 +113,7 @@ static bool __init test_matching_access(void)
  * positives: simple test to check at boot certain barriers are always properly
  * instrumented. See kcsan_test for a more complete test.
  */
+static DEFINE_SPINLOCK(test_spinlock);
 static bool __init test_barrier(void)
 {
 #ifdef CONFIG_KCSAN_WEAK_MEMORY
@@ -122,7 +123,6 @@ static bool __init test_barrier(void)
 #endif
 	bool ret = true;
 	arch_spinlock_t arch_spinlock = __ARCH_SPIN_LOCK_UNLOCKED;
-	DEFINE_SPINLOCK(spinlock);
 	atomic_t dummy;
 	long test_var;
 
@@ -172,8 +172,8 @@ static bool __init test_barrier(void)
 	KCSAN_CHECK_READ_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var));
 	arch_spin_lock(&arch_spinlock);
 	KCSAN_CHECK_READ_BARRIER(arch_spin_unlock(&arch_spinlock));
-	spin_lock(&spinlock);
-	KCSAN_CHECK_READ_BARRIER(spin_unlock(&spinlock));
+	spin_lock(&test_spinlock);
+	KCSAN_CHECK_READ_BARRIER(spin_unlock(&test_spinlock));
 
 	KCSAN_CHECK_WRITE_BARRIER(mb());
 	KCSAN_CHECK_WRITE_BARRIER(wmb());
@@ -202,8 +202,8 @@ static bool __init test_barrier(void)
 	KCSAN_CHECK_WRITE_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var));
 	arch_spin_lock(&arch_spinlock);
 	KCSAN_CHECK_WRITE_BARRIER(arch_spin_unlock(&arch_spinlock));
-	spin_lock(&spinlock);
-	KCSAN_CHECK_WRITE_BARRIER(spin_unlock(&spinlock));
+	spin_lock(&test_spinlock);
+	KCSAN_CHECK_WRITE_BARRIER(spin_unlock(&test_spinlock));
 
 	KCSAN_CHECK_RW_BARRIER(mb());
 	KCSAN_CHECK_RW_BARRIER(wmb());
@@ -235,8 +235,8 @@ static bool __init test_barrier(void)
 	KCSAN_CHECK_RW_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var));
 	arch_spin_lock(&arch_spinlock);
 	KCSAN_CHECK_RW_BARRIER(arch_spin_unlock(&arch_spinlock));
-	spin_lock(&spinlock);
-	KCSAN_CHECK_RW_BARRIER(spin_unlock(&spinlock));
+	spin_lock(&test_spinlock);
+	KCSAN_CHECK_RW_BARRIER(spin_unlock(&test_spinlock));
 
 	kcsan_nestable_atomic_end();
 
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-26-paulmck%40kernel.org.
