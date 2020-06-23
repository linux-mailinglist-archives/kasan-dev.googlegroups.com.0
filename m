Return-Path: <kasan-dev+bncBAABBONAYX3QKGQENUM4KHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id DF997204601
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 02:43:38 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id o7sf979730pjw.8
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 17:43:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592873017; cv=pass;
        d=google.com; s=arc-20160816;
        b=w+lKgZNbVLeBLDEJKUEWmjR/Z68udImJj5e99tY9kL7FYi3Hvye+fWALr/mVwGd17a
         vHRjMkR6d6Yct74uCjVfOHMs4o8d3Q94nbhtML/n+rXDEUznVPLmgZwcTspy0Vg13e7n
         UANRn2Apq60tkJZj/r11hS+gmmopkprzPmNzrVgwDKwipqHtTSKVN36ZSd1vI/+SnYMV
         4Qkb0cI3EurcsgIqKoTnoZAJL90te5n8+La2v9DusX+qAaet+aYNSNqYx38tXy9LLxOR
         2Qw0u+2iAzfUuzbRTbTajd4a+TGpkxg3feyN4Xiypqg3gjz6eWmJoo2vHoEXaDjrr4EC
         H4og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=4Md8IruHRqrpiXGpNFQgQ9MkEbgSxuycnJnldKiXwnE=;
        b=smrfb2TLuSaQLLvKSBba6tsUYSi6OYULUXH1X6nltt6xP/7dc783u3qDycsOy77JbF
         t15AnyDW8P9Rv09iQknzI0/CQTdIexpFQ9M1sdXvnF2kCF2kN2O2sF/Quk5qd/RPq768
         w97oBGW61FOVJUCgoNtW+H3MRCTVy2O0+2PAs834xdKKemMBTxnDjxPy7WOf6wGkFjQ8
         XYDfYsgyAIp9ufLrCfTxRbMVBO2MKtqz0BH8R/h/yAMvLjxP75Zxn7wCK6OKBMOvMaaB
         MqeWFrJs37Dcst0Z99i34jclrmailn0vjjoqTZ2Q+8F9Xh6KTLg7p3Sm7UaIuWRPLtrT
         Z3Sw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=iH5UN9HS;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4Md8IruHRqrpiXGpNFQgQ9MkEbgSxuycnJnldKiXwnE=;
        b=RnDh4aM1I+os6T2zj6eUG/v6cc58wnUdEbL7v+AKa1MWkxC/iIU6P/nNstjthWnFdw
         g9b3wBx/9e3BDblgg5Wy4k1hnAMNUZhmKAM/kuuZfpAPwTE6Kro/S7QHSQ3mw+rCvrub
         /5/r5DHdT3NQymSCuKO9D+WRjBwphQ3hkqrYj6PV20/l6pxMtQB7dlflo5DWZniVtEUt
         ambhEk3t5hleLbt6f7c/+7aVNXrjvQZkX+9FQwEyeONls9GCQvmoQNzRBOer6v+yO0yx
         RLQdPqjsup/FpCts8Vsr/C09j8OyX9g7NRvBVCCxghoDhEbhZAYpNyA86jTLmZHahjn8
         c4Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4Md8IruHRqrpiXGpNFQgQ9MkEbgSxuycnJnldKiXwnE=;
        b=D9Q75SxYyMR7haPr2c71pky11NA/p6ReZH79XGGUWrKjrxzCQcibVJVOWgxqkjVZQP
         hp7t3Zo+6AojC6bm1Pe7Pjzv3X1kqDd9Ki807Hgx5m+32PtLXZZGeGarG2ikyXJyZw4R
         4W4xBqY0SUK7cKt6+KpHypIxnYn4qHlFudMnzrt2QbIlKYZp7BZFp8XBNHOXd+YebQrX
         B2Q8O9sjeo+qJ2QI5I7LHml0QsILW8ftXHOIiy/PE7eTc0hTyC8JwgY0bNAe3YoC4RnM
         Ad0DTuIsoErcbYZqm0sm+/ARv0ojAeXTa97q1f1U5ClwMezYdSjBDUw0E7wijYw1h9YV
         XdDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5311RR+3y7m9rc5+fqzvvzCEQP35yhkzRUYAsdHtD2VCW73Y/Jmf
	92qu7sY8Vl02azGPHSCF6pw=
X-Google-Smtp-Source: ABdhPJwTce2aE5iP+iColv73APkyVz56WHzV/fQluGdlQyUOVXSykWSEoknE+EsJqSbSArQtsA8fVQ==
X-Received: by 2002:a17:902:8b86:: with SMTP id ay6mr21189004plb.329.1592873017559;
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7b91:: with SMTP id w17ls6933120pll.10.gmail; Mon,
 22 Jun 2020 17:43:37 -0700 (PDT)
X-Received: by 2002:a17:902:c402:: with SMTP id k2mr21307590plk.184.1592873017211;
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592873017; cv=none;
        d=google.com; s=arc-20160816;
        b=GfBA1ZdU8C0V/uxq512LivLjX7zOj54nO1RFpWLqo9Zfq8KFA2TpFonFcYi4i+OfiU
         tVQMjbVeSMlldqcPWROLw+LRO2ScE33ccO2AD0ksBtpx/1lqWa1+Bc0tLC9nwYQkRYrZ
         f7GIXLLWoGV90TPvvSbHjgGLWkw8Vb2QF4DxTq0n6fP/1oo62I1fvsCsXjYMqIAdpX5K
         4YeKRlE3r6Z5FTOi0a1RtrOBW3u4mm7URjcjMFUc+nD3GhOfHknlmOlPOAFfOGAM6E8y
         wQ9RSPF4vx5W6TECvES2wJOjyzTIQYEU4A5Y8SUkUQVXW6q2383hGP4WsRiJOAAnRxlD
         Mwdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=Cp2GmvVzfsnA/1YHoFEzj/R/qdINa5xsjrGbuyn1mlU=;
        b=IV03Ze8KWjfxMgRQWlgHLTl+d829QH30lxmhTtnvNez/QBMXsqQpBruaLjaO7LSvT6
         01cJd1NONIPMnKaOVJkTb7ZLk89s1+qcQKdfJlYliSwu3BQqtGETOMLuXMGiRaEvUROF
         QsLMrE7en2e63Y02JlwFqlTBU5n0kPzBQ8VCZ5pbLSm1GBkoyQ25poa66v9CAwUEGytK
         WIW2Im/u7QIC24s7waL0XVNpYwHn9i3EZGQUtmySTD/+J/v4y5P5C3TCPUQZG0yzgzAW
         0WDP6ctOqnmzXR9MU+CWp8nOjSpDH/ScI/NXJ2TtJgVbNJwgSzOfuDjXtYDyvC+B6dmf
         JjHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=iH5UN9HS;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w13si52597pll.2.2020.06.22.17.43.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E8433208C9;
	Tue, 23 Jun 2020 00:43:36 +0000 (UTC)
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
Subject: [PATCH tip/core/rcu 10/10] kcsan: Add jiffies test to test suite
Date: Mon, 22 Jun 2020 17:43:33 -0700
Message-Id: <20200623004333.27227-10-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200623003731.GA26717@paulmck-ThinkPad-P72>
References: <20200623003731.GA26717@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=iH5UN9HS;       spf=pass
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

Add a test that KCSAN nor the compiler gets confused about accesses to
jiffies on different architectures.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/kcsan-test.c | 23 +++++++++++++++++++++++
 1 file changed, 23 insertions(+)

diff --git a/kernel/kcsan/kcsan-test.c b/kernel/kcsan/kcsan-test.c
index 3af420a..fed6fcb 100644
--- a/kernel/kcsan/kcsan-test.c
+++ b/kernel/kcsan/kcsan-test.c
@@ -366,6 +366,11 @@ static noinline void test_kernel_read_struct_zero_size(void)
 	kcsan_check_read(&test_struct.val[3], 0);
 }
 
+static noinline void test_kernel_jiffies_reader(void)
+{
+	sink_value((long)jiffies);
+}
+
 static noinline void test_kernel_seqlock_reader(void)
 {
 	unsigned int seq;
@@ -817,6 +822,23 @@ static void test_assert_exclusive_access_scoped(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, match_expect_inscope);
 }
 
+/*
+ * jiffies is special (declared to be volatile) and its accesses are typically
+ * not marked; this test ensures that the compiler nor KCSAN gets confused about
+ * jiffies's declaration on different architectures.
+ */
+__no_kcsan
+static void test_jiffies_noreport(struct kunit *test)
+{
+	bool match_never = false;
+
+	begin_test_checks(test_kernel_jiffies_reader, test_kernel_jiffies_reader);
+	do {
+		match_never = report_available();
+	} while (!end_test_checks(match_never));
+	KUNIT_EXPECT_FALSE(test, match_never);
+}
+
 /* Test that racing accesses in seqlock critical sections are not reported. */
 __no_kcsan
 static void test_seqlock_noreport(struct kunit *test)
@@ -867,6 +889,7 @@ static struct kunit_case kcsan_test_cases[] = {
 	KCSAN_KUNIT_CASE(test_assert_exclusive_bits_nochange),
 	KCSAN_KUNIT_CASE(test_assert_exclusive_writer_scoped),
 	KCSAN_KUNIT_CASE(test_assert_exclusive_access_scoped),
+	KCSAN_KUNIT_CASE(test_jiffies_noreport),
 	KCSAN_KUNIT_CASE(test_seqlock_noreport),
 	{},
 };
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623004333.27227-10-paulmck%40kernel.org.
