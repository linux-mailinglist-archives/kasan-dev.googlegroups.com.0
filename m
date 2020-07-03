Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY7K7T3QKGQEK3S5UVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id EAAC4213B3F
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Jul 2020 15:40:52 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id t16sf18209189plr.22
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Jul 2020 06:40:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593783651; cv=pass;
        d=google.com; s=arc-20160816;
        b=g3Ul1BMCc1fftg9v10hqkV3g5ESx3vTI4CFfyS0KeQKBLgSs/2L/Kut0t0b66c+XUa
         A+FUrdmAWPfNH1BHHIy3WHug79QUJbhYszV23pmA1fsWM+B6hjPwX4PHkRzbj8Pe7yh/
         eCnWsBXGvVQYy1dKUn+V82+2kxJRAX/i6yN9UOAFUE0f/VyRlezXUny0G36z6MWvlFRA
         EAQUrf2gjgYLD4G/0hCTHPTf2yaZyCDEvVkFD/qyl7hxqOijmjCUayoh7jLHrcQZo7ua
         7gZ8DPt4Be2SdXqr6yv+kXIEl2JRSghYUNBGFyLZ7TShRLwFKfvj5XGplMefvhm/cPBB
         iZTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Fs4j1Uxuhro/lP0Qf4DH66HiR9Am5bjXzbDiixHf1Tc=;
        b=etyKsMK430dXtjIOT1pb2U2WDE5Oh1PIfV9MX9lx+2KqB+VVFgyydhQxH9NvuWKq53
         99qVbG1PpbWAzBVcsSBpf4FJH1wlKH049ILyFrNl4yPRiVElC2NJvFWCgxF4MyF+uVMe
         4ntG/h8tF7qlpJ9LtEER9Pt1d0SWvwA5SgGMMWVQuAigRQ3HwEhr3oB7goMC6onj31CA
         Hm3E/C7OnpitcrJko0/zU08Bob2wJDKLF14hZ21bcPMMD7sQgWM6LrKLgkvAijg5GB+m
         4j0tUdFKJr4VEH3qbflltwCSX1oN9yIW8gikbjnk89Aq+gmZVef0gG8xchpRQllMNGnN
         WjiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=diNoF7yS;
       spf=pass (google.com: domain of 3yjx_xgukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3YjX_XgUKCccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fs4j1Uxuhro/lP0Qf4DH66HiR9Am5bjXzbDiixHf1Tc=;
        b=XANrgL+iznPgGj+aYNL1ElELAjrBhzA6RdzOBAZi5GLCHBOQAyhFw+tnwXUHpPUKcI
         0h+8ytCAc3FZ9UgRLEXZK6YCHKd1mK6N+Tcsf1ZZc1VSgwoys/gqJ27kO1Xn/AqlPxk5
         iImcjwdYongtHuCO9G02QbxM//TQA/PO4iJs7LZBqISZAw84sGmA8jCoiemVwMr32KG1
         qOSAfzroK+GUig86ehFXebUhHpUHZ4FI4IieGyakc2OngTRYD2nuzd3gz0XExyAve1Yo
         0TVk7ecGoLnLwqyrzAXDtSBkxG1JqGwzeogLPVXmCjGdIwci71wwiFAG9pH7l+DdMsnd
         aPhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fs4j1Uxuhro/lP0Qf4DH66HiR9Am5bjXzbDiixHf1Tc=;
        b=aOkiseuTymfJ4WKu9yTLX0XlVg6yZODwh5pibVWvCY3RkwTjrZ8hsTi9DmsulSHWVR
         OVhsWQpo/TRj7Itts5dQS4K3cHpYIbffMcuMtEfyao89nHi1kWA7PnkiZLCC3PZ6Mc7u
         IB+zDBh+VIMtT/oXN5qW0hK4MTnLB1IqhvXKNTPUOsvdakW5sGY/YrtKEMwppfp51URS
         UxY/dlhYMAR+ROY91c+cZEn5Y4TPH8r35nlb7vsLESYIUyPnMq64szwa8Q1Ew/akb6aF
         SnGdnpbrjDCd71QxpB/5Kboa89jMQcIktPOxsXbh2u4xDlxdtwmYvNH4gO3AEWnmwRaC
         00fA==
X-Gm-Message-State: AOAM532ApM7OFkKTRMRqIcW5G+AtooFUHxrPJNAlPI+XAmEXWBD1OOQF
	ufKcqUvVKRogjPWkj8VZ9lY=
X-Google-Smtp-Source: ABdhPJxCEsDLp8i6bJEizAfZbu+QeTx5AblwcSOfdCu11TnHtwfaQYCV+XXLInOytJ+PLkTXlTuiQQ==
X-Received: by 2002:a17:90b:916:: with SMTP id bo22mr38813383pjb.100.1593783651406;
        Fri, 03 Jul 2020 06:40:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:e59:: with SMTP id 25ls1073322pgo.9.gmail; Fri, 03 Jul
 2020 06:40:51 -0700 (PDT)
X-Received: by 2002:a63:7f5a:: with SMTP id p26mr29187670pgn.117.1593783650948;
        Fri, 03 Jul 2020 06:40:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593783650; cv=none;
        d=google.com; s=arc-20160816;
        b=zxjIOH/6dyInBXJFQXA2pTxfoAD7VrD785e7c+txdI2Hchw7Cz+lCLOTALMzJ2sIFu
         0bOcID6iwxBmHdkzc8h65GH0CI5EymYBf7ZUrOxhGr+MdfrE7pm3Dv/AmiHtebNTx5M2
         /w1dRkVryl8wYXIHPL7SQdIJgNQUl6UxLgkLPltyL2mGYaJ2giwss1cRbKI7nryf+iqp
         1X4gnWMZr3NYFuXKcNVj/ts8KKw6Fsem/jZt0aAlDIdIZVy4T1E43lmoyk9MhpKP/zS3
         nDUxcPjJEqownXCGEdySUASrOsMQCi+9cRI5wmLvAFXOnSaIiWgOgUVcnocFeiyndzYN
         eCrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=3Gmx+1m3BOyGv6VzEOTfZTqEoVFzEpPgTLwNy+kSFG4=;
        b=BBidsbdPD4bJCKQZX1jCzEGRddYseYqnuf56CJuLPH6sVnYN/lc05oo7lM68aShHoF
         /ZdlFjTqxHtSIIetlMFEneXvOA7RvcMuVkoLEqTVtJHUOApa8fV+8IZrEFCg122+u2SA
         H/+lgyFrgfmjHpIIKVcSnnJURluE8vfHj7D77rpIPC6QW6xmuWsfGJRotXf+Jolx0EoF
         iBKWY+WavO06X120twZCeW3HqO6Jav5aujwY4JHzTsG9uT+q8dSKPn9Bt5YKrKCahD3X
         vl5njdsYGwxAmFeMZ74HCnOrnmwKpu9BkL5zR/86W/CQuEsj4eN/hJgOOftp8/t2zs8n
         Ieuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=diNoF7yS;
       spf=pass (google.com: domain of 3yjx_xgukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3YjX_XgUKCccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id q13si731719pfc.6.2020.07.03.06.40.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Jul 2020 06:40:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yjx_xgukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id s9so33439329ybj.18
        for <kasan-dev@googlegroups.com>; Fri, 03 Jul 2020 06:40:50 -0700 (PDT)
X-Received: by 2002:a25:ac4d:: with SMTP id r13mr19733119ybd.171.1593783650090;
 Fri, 03 Jul 2020 06:40:50 -0700 (PDT)
Date: Fri,  3 Jul 2020 15:40:31 +0200
In-Reply-To: <20200703134031.3298135-1-elver@google.com>
Message-Id: <20200703134031.3298135-3-elver@google.com>
Mime-Version: 1.0
References: <20200703134031.3298135-1-elver@google.com>
X-Mailer: git-send-email 2.27.0.212.ge8ba1cc988-goog
Subject: [PATCH 3/3] kcsan: Add atomic builtin test case
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=diNoF7yS;       spf=pass
 (google.com: domain of 3yjx_xgukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3YjX_XgUKCccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
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

Adds test case to kcsan-test module, to test atomic builtin
instrumentation works.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan-test.c | 63 +++++++++++++++++++++++++++++++++++++++
 1 file changed, 63 insertions(+)

diff --git a/kernel/kcsan/kcsan-test.c b/kernel/kcsan/kcsan-test.c
index fed6fcb5768c..721180cbbab1 100644
--- a/kernel/kcsan/kcsan-test.c
+++ b/kernel/kcsan/kcsan-test.c
@@ -390,6 +390,15 @@ static noinline void test_kernel_seqlock_writer(void)
 	write_sequnlock_irqrestore(&test_seqlock, flags);
 }
 
+static noinline void test_kernel_atomic_builtins(void)
+{
+	/*
+	 * Generate concurrent accesses, expecting no reports, ensuring KCSAN
+	 * treats builtin atomics as actually atomic.
+	 */
+	__atomic_load_n(&test_var, __ATOMIC_RELAXED);
+}
+
 /* ===== Test cases ===== */
 
 /* Simple test with normal data race. */
@@ -852,6 +861,59 @@ static void test_seqlock_noreport(struct kunit *test)
 	KUNIT_EXPECT_FALSE(test, match_never);
 }
 
+/*
+ * Test atomic builtins work and required instrumentation functions exist. We
+ * also test that KCSAN understands they're atomic by racing with them via
+ * test_kernel_atomic_builtins(), and expect no reports.
+ *
+ * The atomic builtins _SHOULD NOT_ be used in normal kernel code!
+ */
+static void test_atomic_builtins(struct kunit *test)
+{
+	bool match_never = false;
+
+	begin_test_checks(test_kernel_atomic_builtins, test_kernel_atomic_builtins);
+	do {
+		long tmp;
+
+		kcsan_enable_current();
+
+		__atomic_store_n(&test_var, 42L, __ATOMIC_RELAXED);
+		KUNIT_EXPECT_EQ(test, 42L, __atomic_load_n(&test_var, __ATOMIC_RELAXED));
+
+		KUNIT_EXPECT_EQ(test, 42L, __atomic_exchange_n(&test_var, 20, __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, 20L, test_var);
+
+		tmp = 20L;
+		KUNIT_EXPECT_TRUE(test, __atomic_compare_exchange_n(&test_var, &tmp, 30L,
+								    0, __ATOMIC_RELAXED,
+								    __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, tmp, 20L);
+		KUNIT_EXPECT_EQ(test, test_var, 30L);
+		KUNIT_EXPECT_FALSE(test, __atomic_compare_exchange_n(&test_var, &tmp, 40L,
+								     1, __ATOMIC_RELAXED,
+								     __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, tmp, 30L);
+		KUNIT_EXPECT_EQ(test, test_var, 30L);
+
+		KUNIT_EXPECT_EQ(test, 30L, __atomic_fetch_add(&test_var, 1, __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, 31L, __atomic_fetch_sub(&test_var, 1, __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, 30L, __atomic_fetch_and(&test_var, 0xf, __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, 14L, __atomic_fetch_xor(&test_var, 0xf, __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, 1L, __atomic_fetch_or(&test_var, 0xf0, __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, 241L, __atomic_fetch_nand(&test_var, 0xf, __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, -2L, test_var);
+
+		__atomic_thread_fence(__ATOMIC_SEQ_CST);
+		__atomic_signal_fence(__ATOMIC_SEQ_CST);
+
+		kcsan_disable_current();
+
+		match_never = report_available();
+	} while (!end_test_checks(match_never));
+	KUNIT_EXPECT_FALSE(test, match_never);
+}
+
 /*
  * Each test case is run with different numbers of threads. Until KUnit supports
  * passing arguments for each test case, we encode #threads in the test case
@@ -891,6 +953,7 @@ static struct kunit_case kcsan_test_cases[] = {
 	KCSAN_KUNIT_CASE(test_assert_exclusive_access_scoped),
 	KCSAN_KUNIT_CASE(test_jiffies_noreport),
 	KCSAN_KUNIT_CASE(test_seqlock_noreport),
+	KCSAN_KUNIT_CASE(test_atomic_builtins),
 	{},
 };
 
-- 
2.27.0.212.ge8ba1cc988-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200703134031.3298135-3-elver%40google.com.
