Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVMBRCQAMGQESJ7RLYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id A8AE66A992D
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Mar 2023 15:14:46 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id x37-20020a2ea9a5000000b00295b9da42d6sf649747ljq.18
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Mar 2023 06:14:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677852886; cv=pass;
        d=google.com; s=arc-20160816;
        b=UazsZEaZFcTT6eNC/lQ1wLSLjNHfKyVslLVbIbby1PJc035mPisZLQQY93PQd1IYYj
         05dybZdlN6tyydtYPOYsFamtjoeoDXq9DaD+Z5gQHKbFxPn32h+QvJlIwruVE956w5VB
         7aPpQ9qFiN5x12OmiAtA41rHDDBxanGjaFS2Jvsq/jTKvacOY5zPjYuPxlS/KD45UCU3
         IsLeJhn6ttOvWJmccXR160QsHNEqVXby7ibT2o7/8Eb8AJwNbWDm+w6FgeGsIDlIKnyL
         raDhPntseDjJEsAKHyQYJ0ri9vfwh1a79rIhSuLpdWwIfO7rIuFYgDKCgEkvBmtniqgN
         6UTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=OI5fGSbH8tXH4P/eL0Sb433npR3Mrqr+OTM9Mqmbdp0=;
        b=ho1gZTxNMmDtWLKfrXT335nC3iIFkRv3Dqg/T9jgtUwey42vRo3YB7vHIU0pJC1Znq
         Eg+OaYCh0FZafZpDKKqgH51dL/huZnqX39f2VZlT5Tlea32mQECYJJYvcUk2YrQMm/6+
         knkDeZmv7Inh5Gun7RrZgjc6+GG7UKMWRavl/nrFzkH6e1wwSY1TwOKGxqRpnI6r632d
         eUGpdqwsIFNqCgzW6SPfbH2jADLyXZCHXlTYsDmaIquO3QcKktjh7xdP27SyuXGPEjUx
         w3oc5Df52cOFdnwdarkNaof8I4xqVnldw9kX6NYpTwxlr20Zo83PXva+WSuGRyNUGvcS
         NOVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZfSfmqBM;
       spf=pass (google.com: domain of 30waczaykcqqkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=30wACZAYKCQQkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1677852886;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=OI5fGSbH8tXH4P/eL0Sb433npR3Mrqr+OTM9Mqmbdp0=;
        b=pH1yxSqpmdW5/qh9kltIsAbvYgC/NMUh0HDZO3sgMuwuiHtWHJcTDFoir0+5/yebEg
         eGY+/4VSZeIjp+DjEh3B0V0pC/GFCxU6E0vDc4xXMXpWZCf88oaP4ksjRUGgC6EwXGhV
         Da97Sc5igdWyNns3kjqYWj44SHvqk0nepTHRJjm0TpVcCygvmjHbdb1rKwZBwYOgQtzP
         nHEzrIrOO+ZDnHZ2HlFt2oATMPzUKcCM7c40nhWFK29dexpS5fg+U+mMFBHtnN2cDDeR
         kpvdc7smhRSIvvU16IC4fCt7fpOTjFW3vijCtn4587yveKNJqoKn5p+4+42LGc8UoFZ2
         v3Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1677852886;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=OI5fGSbH8tXH4P/eL0Sb433npR3Mrqr+OTM9Mqmbdp0=;
        b=m1tTfKx1MDF7VmKNjkqeebBrk930iScF/QxNycgDmPNa4niURwKUiIJaNZUAzAz2eW
         /XmcdvPF980G/uq2dTZdT1v4CpnHRxwzE3JInOSoxNtE2BH+qm3/WENM66CdseI4dkPD
         nG+BI59SSSVcoK0GLMjylrJTLdoybPcAn9yqUaWjOCjv0uDu8khN8LpmBinViiu4jjfh
         q72tbfwAanceIcfjHp3cMW5LCJqx2mneKc9CNIfVmIuNxfr/pM5X9mCi+T9oYe3SnWRd
         cJ376z6eFwFeFvIPsZRDF8UtuvqTG0zCRCwVCWcdVIhuTX9DbAQXp6HKEwyGd5RQkchy
         zoxA==
X-Gm-Message-State: AO0yUKXF0HfRj5KfBLi4afv/SL9fPEeJ3fosMN+o9bCftt2taac/7gLK
	nJWG4yCD9fNSlUaRmkthz3E=
X-Google-Smtp-Source: AK7set9saoal68fDAPdJIQXZadKSiCo6qWzvISA1c9BzhwfguwLhOLFlzyTeqMIo//CmmB4DaXtLDQ==
X-Received: by 2002:a05:651c:314:b0:295:944c:f335 with SMTP id a20-20020a05651c031400b00295944cf335mr602368ljp.1.1677852885868;
        Fri, 03 Mar 2023 06:14:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3ca4:b0:4db:51a5:d2e8 with SMTP id
 h36-20020a0565123ca400b004db51a5d2e8ls2528407lfv.2.-pod-prod-gmail; Fri, 03
 Mar 2023 06:14:44 -0800 (PST)
X-Received: by 2002:ac2:53a5:0:b0:4cb:4371:f14d with SMTP id j5-20020ac253a5000000b004cb4371f14dmr594454lfh.17.1677852884475;
        Fri, 03 Mar 2023 06:14:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677852884; cv=none;
        d=google.com; s=arc-20160816;
        b=aiHs/XHMEDDoq/rEXRAqgwX7bQ88jXyQEX8uMwTF+4TdWaG374mpMEYjjRCEgHc/ds
         oAQl4lzHYyy1CV2rwUXtPo0BvVm/fcZhW0SDyq+jfinG/vLcN8qWuC1kkfFyQwPPjuNb
         SuUskv7Gw1uSA7ZZAp8LukhZL5qsgCataRMcS57tf0uWAAJC862G4CR3FRAallZ/y5V7
         umRWZApxD1lYVOZp7XcTDoJKTEWit3fof7VHzPImeGHFifgWnugB9oGgi2o+IbQEvbRG
         3kfKSheHK+9lZXqTQ7v1JyTfXijnopvwAwaOVpqh0oizGNT1AXnJ0WFUukvehEXAeNfc
         PE4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=NzrUAKqOf4lIqj2sXdyqoZ2Q8eXyDe5JYgJyXOtPsCY=;
        b=c6eKJ0yoU7RJlEk1acInUwMyt9PpsIDWozztMLtw0JIVd7Da+bX4lgncVZV5oNGhqM
         /gq7J2KbDTxItSGvglU+xLUiWiQb1IGy7Rw2cjkPw9kej+8vzAYm8a4ZabkazA6wE916
         0w7Wk2rztuSS8RZ9oTnsYNopd9MGpazwuY67MjWrnGgX9A1wMh/19J6SvYbGwjfYVyjr
         Ikhi/8mDq8WlBf7yEskCzesI+S9RR+Ng9S5XKeglBkl5YF+5BaolrqpDSkhhjD6MypQ5
         4BpSpa3fsWRniKxf6LFfAqYjTyP6uj8XRySVWqj0Y3RcLepTooruMddaFZOhtO9NTl36
         Ox4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZfSfmqBM;
       spf=pass (google.com: domain of 30waczaykcqqkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=30wACZAYKCQQkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id h37-20020a0565123ca500b004dc818e448asi117288lfv.3.2023.03.03.06.14.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Mar 2023 06:14:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 30waczaykcqqkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id dn8-20020a05640222e800b004bd35dd76a9so4198269edb.13
        for <kasan-dev@googlegroups.com>; Fri, 03 Mar 2023 06:14:44 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:f11e:2fac:5069:a04d])
 (user=glider job=sendgmr) by 2002:a17:906:d041:b0:8bf:e82a:2988 with SMTP id
 bo1-20020a170906d04100b008bfe82a2988mr938462ejb.4.1677852883928; Fri, 03 Mar
 2023 06:14:43 -0800 (PST)
Date: Fri,  3 Mar 2023 15:14:31 +0100
In-Reply-To: <20230303141433.3422671-1-glider@google.com>
Mime-Version: 1.0
References: <20230303141433.3422671-1-glider@google.com>
X-Mailer: git-send-email 2.40.0.rc0.216.gc4246ad0f0-goog
Message-ID: <20230303141433.3422671-2-glider@google.com>
Subject: [PATCH 2/4] kmsan: another take at fixing memcpy tests
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, nathan@kernel.org, ndesaulniers@google.com, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZfSfmqBM;       spf=pass
 (google.com: domain of 30waczaykcqqkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=30wACZAYKCQQkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

commit 5478afc55a21 ("kmsan: fix memcpy tests") uses OPTIMIZER_HIDE_VAR()
to hide the uninitialized var from the compiler optimizations.

However OPTIMIZER_HIDE_VAR(uninit) enforces an immediate check of
@uninit, so memcpy tests did not actually check the behavior of memcpy(),
because they always contained a KMSAN report.

Replace OPTIMIZER_HIDE_VAR() with a file-local macro that just clobbers
the memory with a barrier(), and add a test case for memcpy() that does not
expect an error report.

Also reflow kmsan_test.c with clang-format.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 - replace inline assembly with a barrier(), update comments
---
 mm/kmsan/kmsan_test.c | 44 +++++++++++++++++++++++++++++++++++++------
 1 file changed, 38 insertions(+), 6 deletions(-)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 088e21a48dc4b..aeddfdd4f679f 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -407,6 +407,37 @@ static void test_printk(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
+/*
+ * Prevent the compiler from optimizing @var away. Without this, Clang may
+ * notice that @var is uninitialized and drop memcpy() calls that use it.
+ *
+ * There is OPTIMIZER_HIDE_VAR() in linux/compier.h that we cannot use here,
+ * because it is implemented as inline assembly receiving @var as a parameter
+ * and will enforce a KMSAN check. Same is true for e.g. barrier_data(var).
+ */
+#define DO_NOT_OPTIMIZE(var) barrier()
+
+/*
+ * Test case: ensure that memcpy() correctly copies initialized values.
+ * Also serves as a regression test to ensure DO_NOT_OPTIMIZE() does not cause
+ * extra checks.
+ */
+static void test_init_memcpy(struct kunit *test)
+{
+	EXPECTATION_NO_REPORT(expect);
+	volatile int src;
+	volatile int dst = 0;
+
+	DO_NOT_OPTIMIZE(src);
+	src = 1;
+	kunit_info(
+		test,
+		"memcpy()ing aligned initialized src to aligned dst (no reports)\n");
+	memcpy((void *)&dst, (void *)&src, sizeof(src));
+	kmsan_check_memory((void *)&dst, sizeof(dst));
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
 /*
  * Test case: ensure that memcpy() correctly copies uninitialized values between
  * aligned `src` and `dst`.
@@ -420,7 +451,7 @@ static void test_memcpy_aligned_to_aligned(struct kunit *test)
 	kunit_info(
 		test,
 		"memcpy()ing aligned uninit src to aligned dst (UMR report)\n");
-	OPTIMIZER_HIDE_VAR(uninit_src);
+	DO_NOT_OPTIMIZE(uninit_src);
 	memcpy((void *)&dst, (void *)&uninit_src, sizeof(uninit_src));
 	kmsan_check_memory((void *)&dst, sizeof(dst));
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
@@ -443,7 +474,7 @@ static void test_memcpy_aligned_to_unaligned(struct kunit *test)
 	kunit_info(
 		test,
 		"memcpy()ing aligned uninit src to unaligned dst (UMR report)\n");
-	OPTIMIZER_HIDE_VAR(uninit_src);
+	DO_NOT_OPTIMIZE(uninit_src);
 	memcpy((void *)&dst[1], (void *)&uninit_src, sizeof(uninit_src));
 	kmsan_check_memory((void *)dst, 4);
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
@@ -467,13 +498,14 @@ static void test_memcpy_aligned_to_unaligned2(struct kunit *test)
 	kunit_info(
 		test,
 		"memcpy()ing aligned uninit src to unaligned dst - part 2 (UMR report)\n");
-	OPTIMIZER_HIDE_VAR(uninit_src);
+	DO_NOT_OPTIMIZE(uninit_src);
 	memcpy((void *)&dst[1], (void *)&uninit_src, sizeof(uninit_src));
 	kmsan_check_memory((void *)&dst[4], sizeof(uninit_src));
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
-static noinline void fibonacci(int *array, int size, int start) {
+static noinline void fibonacci(int *array, int size, int start)
+{
 	if (start < 2 || (start == size))
 		return;
 	array[start] = array[start - 1] + array[start - 2];
@@ -482,8 +514,7 @@ static noinline void fibonacci(int *array, int size, int start) {
 
 static void test_long_origin_chain(struct kunit *test)
 {
-	EXPECTATION_UNINIT_VALUE_FN(expect,
-				    "test_long_origin_chain");
+	EXPECTATION_UNINIT_VALUE_FN(expect, "test_long_origin_chain");
 	/* (KMSAN_MAX_ORIGIN_DEPTH * 2) recursive calls to fibonacci(). */
 	volatile int accum[KMSAN_MAX_ORIGIN_DEPTH * 2 + 2];
 	int last = ARRAY_SIZE(accum) - 1;
@@ -515,6 +546,7 @@ static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_uaf),
 	KUNIT_CASE(test_percpu_propagate),
 	KUNIT_CASE(test_printk),
+	KUNIT_CASE(test_init_memcpy),
 	KUNIT_CASE(test_memcpy_aligned_to_aligned),
 	KUNIT_CASE(test_memcpy_aligned_to_unaligned),
 	KUNIT_CASE(test_memcpy_aligned_to_unaligned2),
-- 
2.40.0.rc0.216.gc4246ad0f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230303141433.3422671-2-glider%40google.com.
