Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5GUVKGQMGQEX7ZT2UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FC5B4680B2
	for <lists+kasan-dev@lfdr.de>; Sat,  4 Dec 2021 00:38:28 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id k25-20020a05600c1c9900b00332f798ba1dsf4178333wms.4
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 15:38:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638574708; cv=pass;
        d=google.com; s=arc-20160816;
        b=frdJgLVSCQR6BYntxFXWAHLJr+9Gi90hjkP0cc6FTHUcZ+juf0LFZCTCBIzwYvXvq4
         fVjKr+nNJrMW7YBy8e05wkUR77gZp2o3JAiff991imQgvTIdxJNg+pRuBXA0AHj7+fkW
         bCcizhKzjnBRzxEsRtGmfGx3T970euU+HR5uJxACWPSO3VnavCzKJKyGHsQQsXcXJ1Jd
         TSQsiAt8wsu7u2PUFUuyT+vYfGX8N1ySFjJkRdEnoG7UuNhAsEECULpxJxISEYwv2aIt
         TmoKmJSeAN7ndW5Lm20p96GOmh1ssK71oJdGzuwq5gB0z5e3871CIqxyjzBdduWK7/bs
         703w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=7CEXBVACrdQdfVvIxJinD1rsnPDeJJKuRacL5siAwTs=;
        b=KIfXO5RGaLaVKqvAYsZI6ncVHkOp5t5XB5Pmv+uGFPpfCLTDvdA/b+a4fskwy9Lf1I
         4rIi+j+kD+mkGW3Btjp5/11fgcKMWD8qCt9S5OqTj+V5mMTcAjKvi8g7xdowkur6sAJK
         AYRel+5nBxu0Y5xGPTrGT/vetNO3Z76OP+r8WxNKn2HhXt6apnaW1HRaNLYVcu15AIPo
         ofaxWfOVwuojq5NyuW3VOGox3ppJIg9hjAuAlhgsCwsatGFrZjp29mr9njVIstwamKpl
         dQAWSYZAEc26a0jjrpnPYar5QCN3bc1tOAyBMyTwilZ3aNSg1AX7+CWF/kCVeMon6MKo
         OhaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pay3ge79;
       spf=pass (google.com: domain of 3cqqqyqukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3cqqqYQUKCYUnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=7CEXBVACrdQdfVvIxJinD1rsnPDeJJKuRacL5siAwTs=;
        b=V0D7EFosuLIHLINpzTRfHNnBeWIGj/GnB1vNieBbm4rvSPPvygPBTvQnFy4zeVjdc2
         2jtTWswaZ380M2xGcLK6w6vY1jW+H3NXGJzYZknqTyLC80cuNa0/53zmd5H+atoC6o1I
         r6CI8dmJb9M8WFueW+pIcKaPxWfu/Q1tfWvlu6AUY/j1XGtOXAZ8loRf95VR5rOdrKUF
         7GmRnFtPLutzfiUGGjlExla2rhsdszzu0+ZZ/UiqjQEiFOKd1S40junIjCqwIMpGRKir
         jYZEseWgFJ0bitHDwRRuLFZwpmVEm5eR8eae/2kjHnV7P0ssILwrWw5Amse9jdew6wu5
         E9Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7CEXBVACrdQdfVvIxJinD1rsnPDeJJKuRacL5siAwTs=;
        b=tJqjDYzQH7EMACkELC5Ud7Q+e+ZgZGuZoqBZlM/ongggiXhfbsCXfSWs2jN9/fD5Pt
         H45HqTSHgVYNhjj6qCshKEOgQRXjh4R9WCc7lcB5V5JR660tyYkOyGdkEWdSGHnwgrlv
         YZKVND1qVcqBl30rS9QGs84xFu1Np/E3HP+q/6Qz5J8MmJdMV3i//+Xf7s0C2bdk8m4P
         g1JFtChGOKJvomNdU+tY5b2VuNiJdn+L4/fmLE5n2yG/kqbtK975YwUrzNxkA5zqSRV8
         jgfUZXsJFAANR5FjC1onHYDKg7BqtcEnQajUT6fwnplQasl+QXqWtsERxcbjbZCa8Xu+
         omcg==
X-Gm-Message-State: AOAM531Ih0WOZXjYRXRmTTlpK17I0Y1qn7BKpdOxhlYF+/eWY91Zf71Y
	tRvE6Rd1TuQhtgBkho8XOWA=
X-Google-Smtp-Source: ABdhPJw87OSIWxXI7Y+u4rhnqDxuvJTLmit4YgtPZ3LFNHsFmYgBayGFLNJZUl93B6G+yxFngFIfaA==
X-Received: by 2002:a1c:208b:: with SMTP id g133mr19182161wmg.128.1638574708321;
        Fri, 03 Dec 2021 15:38:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9d85:: with SMTP id g127ls140725wme.1.experimental-gmail;
 Fri, 03 Dec 2021 15:38:27 -0800 (PST)
X-Received: by 2002:a05:600c:511c:: with SMTP id o28mr19392269wms.96.1638574707215;
        Fri, 03 Dec 2021 15:38:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638574707; cv=none;
        d=google.com; s=arc-20160816;
        b=s84lp88t+71xnVO6sINUtQoaagwXBDjbjJu85We8v+floctSavgtFr5TxfqsWU8Z1p
         MYePgKSsefGCktLDxQxqROXK1m2PGjaNV6qEvQMu+m6K3r8jMMTX1a0JpvOROQYPL1Xj
         DLgJ6abrhF03fpQUtkAP7dAovA05155dDiw7Kt/dIWzCWy++eFU5wTf8PU+W/ljFyzFU
         xhKDOaHl+RWiFuWDDB7FsygSxQYlUNDL8UtQGGFa0HzMneyP1SlIngYNvxUh8QG+zHVo
         LGvlP94UW89s6qCg1tsYn+9R7f/xf7WbUOTKGMTO6c4cxGhCcOphb5zNBRvQeAq6b/rc
         KuaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=xmREXnUvl8E4KQZMwmE4VO+WOMe+bIkkKyKZ1+a5fBU=;
        b=aRpBVtVjMXtjV19OSDs0xBiI359+XYKW4D0HCnEh7LyU7GljX1dtZ2jrrV4OFLNBf1
         3xmRVwMF9G2hX8woiSAb+lkXvnM7rHBZPYTXahBur4IPY0FHwrbesjl1Nh9sghyj8q/F
         YdTxXLOiTA2jbXX2g6XAixIxLoFIqH+rO6SY1jTm907K2dhazo7lZYmNpmQP0nlaUzMI
         Vmxg+O89ivsF5k4Rck1LXmfVyO4+dumccC5s65qlals76p5ayvLHXZZ0/YtGSUx0kB/F
         yYsn2n/7e4oCXosp6mOessWhEeLRvxg66luLjtRPIq6h6xux8dIQTu+GVE1XXfhlbBm5
         HAyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pay3ge79;
       spf=pass (google.com: domain of 3cqqqyqukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3cqqqYQUKCYUnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id a1si247357wrv.4.2021.12.03.15.38.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Dec 2021 15:38:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cqqqyqukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 187-20020a1c02c4000000b003335872db8dso2294525wmc.2
        for <kasan-dev@googlegroups.com>; Fri, 03 Dec 2021 15:38:27 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:565a:3964:11db:fb41])
 (user=elver job=sendgmr) by 2002:a5d:6691:: with SMTP id l17mr24686079wru.227.1638574706604;
 Fri, 03 Dec 2021 15:38:26 -0800 (PST)
Date: Sat,  4 Dec 2021 00:38:17 +0100
Message-Id: <20211203233817.2815340-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.1.400.ga245620fadb-goog
Subject: [PATCH -rcu] kcsan: Make barrier tests compatible with lockdep
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pay3ge79;       spf=pass
 (google.com: domain of 3cqqqyqukcyunu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3cqqqYQUKCYUnu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
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
---
 kernel/kcsan/kcsan_test.c | 37 +++++++++++++++++++++++--------------
 kernel/kcsan/selftest.c   | 14 +++++++-------
 2 files changed, 30 insertions(+), 21 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 5bf94550bcdf..2bad0820f73a 100644
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
index 08c6b84b9ebe..b6d4da07d80a 100644
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
2.34.1.400.ga245620fadb-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211203233817.2815340-1-elver%40google.com.
