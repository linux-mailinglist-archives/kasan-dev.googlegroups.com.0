Return-Path: <kasan-dev+bncBCCMH5WKTMGRB24V46TQMGQE5KPQ47I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 52289797290
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Sep 2023 15:06:53 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-64cb143d3b5sf10650136d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Sep 2023 06:06:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694092012; cv=pass;
        d=google.com; s=arc-20160816;
        b=qhvIgKrLxc0Ah3NZAONi2Cwhtjv6NJZUI9XH+ZJzBVIixDcVHT9Nokb710lpFod4H3
         jbKsjTpYyTHyakzblkRRKMOD1OsONFocez7qIaFFYfdXxuLpAkyqaScGq9sA9xEkqKk2
         rzVKHcck1OwWQP8RMWIpTUf70QBQZk19dh0+tolajSx/i4i9LsvyXPtGjCzRHHtIQlAL
         5RrADbQsTzvQshtPbG4Ohs7d9buRsyGO/ItPfSXVrZZ8hQENi1znazDv6LdxVCrC9f+o
         0wL2iTdtXu3Po6Ma/WhbFW9rU3MTSYIKSEhLAeESjHxerWUrdTPnQwQpJi+Q3pV838k9
         xTtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=4SBgH1U6/WUYj2TCn3MGZaOnoJErg289IoGD0/kqKDo=;
        fh=x/Eq99+ICi7e9grjZNFq4mA7WJOkDm5ZB5wM283JjUk=;
        b=qf5lde9khLGjkFf9rwtH6dRHmu/Dtr0egkPquSudNvWV9tKiocoHOD9EWYMl8G0lGq
         8q7P1M1N12OBAU7Pay485NBdyI446fm3FmkWjVftb0ST+sKy+jbfbv8Iub5zTWsRns8g
         IhfqLodyX9kQX1xXUR92ynz+gnVQzdLGivV3O67ZkX5gcOExzkxOi2Ci0LGhOWVDzWIp
         BPnHketD3O94z3n3+GuE1vaHz4OBzNUIQB2PcVfzjPr48fcNf0wxoHurRaLTgrn/aFo0
         KsjEdg+c7Sd/mwEWSBCjzrh+gPUCIj//jxq0v6yLKmHWVP4hleOw4DbkvXrvypUNXkdX
         T4vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="Fvrddju/";
       spf=pass (google.com: domain of 36sr5zaykczu5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=36sr5ZAYKCZU5A723G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694092012; x=1694696812; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4SBgH1U6/WUYj2TCn3MGZaOnoJErg289IoGD0/kqKDo=;
        b=bfu1ZspFP58gVQ4SADfoVk00f69w6+BS8I64qmFPOFP61hfNT5L5CbI2EQb/idzQKT
         7IssyPymCqYCXqpJk0jjEbkk2BHdUfGndPt9J5bCJhsDH56gEBtx3QVtvKic9gsxXRig
         io8M8g5QTz7zKAbyBFibpJ9AND5MY/K+xj2yPr7ZKWR/BmP03JLw2SbaFmngq2bOQjk6
         0onR1hJntEq7eH7+RYqxzUx9I81auYtDPPIXC0rtgqBMrEaiVJeRESBnfBHiO7VZIEVH
         WTi65UW1/nlAOeCzkBnLq3sBfTRpMCPebIlm0CbVsI00HTbbj3z1QnLQ8kFK50pFjIvS
         S5Jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1694092012; x=1694696812;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4SBgH1U6/WUYj2TCn3MGZaOnoJErg289IoGD0/kqKDo=;
        b=mCXY8FtM5ejEcZR6yFJMKnk8W4gYYpRfm1BH2hYVyCE1hneROQvqgwFWzOlGdkaepL
         oJ9eWf4yCaM6JMvvLn4mfmTwaZ6/iLXO4ueeUxFZapJbFgiaBor8m6agfpMgTWkeyxNt
         VxiHgPq4VSuLx0f+VQTE3C8grirULGCYPnzLr0KOrczkOiGIYqs8CaWnLNiCbbIaWsr8
         G8GJ2FLG2lGCKsaArqk8v5G3UOS6PoLbIkhHp6HPxAEQLSj0JA1RdiRa63hgyxpWy3jr
         GDiGO7PxThgIWPfm6D7MWrawOlu3rPo/v4DH/PkmWdL18Kk7eh/Yyux+bQvWh+WjhHRL
         nrNQ==
X-Gm-Message-State: AOJu0YyyhA4kaYSn2ETQTxr+CJVLcarI6iF3SC9M/2MfiTzVl46vXrmn
	b+dHM5XViPXBvZX4JN4tl2Y=
X-Google-Smtp-Source: AGHT+IEiWf+zYroFqTgrXT0UTcmdB5uA1RX3fYRBR7C3rbHXO8wUWA5+np8KsUB28kUYd67jBBeg+A==
X-Received: by 2002:a0c:8c06:0:b0:651:8efe:2a61 with SMTP id n6-20020a0c8c06000000b006518efe2a61mr19335696qvb.18.1694092012045;
        Thu, 07 Sep 2023 06:06:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e54a:0:b0:648:190c:a15d with SMTP id n10-20020a0ce54a000000b00648190ca15dls7734727qvm.1.-pod-prod-09-us;
 Thu, 07 Sep 2023 06:06:51 -0700 (PDT)
X-Received: by 2002:a05:620a:17a4:b0:76f:114:76bb with SMTP id ay36-20020a05620a17a400b0076f011476bbmr23715890qkb.53.1694092011146;
        Thu, 07 Sep 2023 06:06:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694092011; cv=none;
        d=google.com; s=arc-20160816;
        b=dDmqtL8PmkOiYt5CbenSnzHySXFrD+rPP6rVPHANnkARazpYHUrsjlqmOmbe9YRX+6
         48F16aK0RZCjdRCdcGSw0J4mwRAro0fNtbvUiFmypm58981KM6N0bZZJ0lg45PdjErVu
         XRDHRfjfcnakk8P7EcTrwY5K/s8x1KpsksSVnkG2rkl3+Ov9Jj1fURX4XfzdVWpAbEnW
         idnNqu25BR4E/qjObuTKMNDDQmKXGO5DVKojybTI2wEBT9tsYMZWc++Lmgy7LApbxITa
         713IRsuW39NfZvbmi7z25+HY/tu8GELSYuyMA3k1POWYbgbSlHonYwq/xakGRszoKpB8
         FIxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=s8i7Jhe9BViu4aMBPbLDU6gPTC4qxWjzqtUEiNX0CLE=;
        fh=x/Eq99+ICi7e9grjZNFq4mA7WJOkDm5ZB5wM283JjUk=;
        b=d+IxnkhnEpVwiBRQtOsbMl9FQRZ+N2gLR9DuoHQnfaV64CMc8X50EEhLD1sIb8kplL
         F8ZWaVWRJx4GLAdL+JA0RIpDwef/jiVnPhG3CjQCnK7EQmHkeXpndyKnCaqAU55pplzP
         DuvvaMXQQB2xPNwdF9CFCRQBYhVEwlM5kyQO6w36TzHLIZXs0vhCRXaXQw0s+uAbvA4N
         dZz6wNFvxwHRy1/+q+NO93Zbu+Yij34YBVJQFuljbBXPeR/XZvuksulQGoyuBFPiPrIm
         NI/Uw73ecVRyYVWC3ZDcrJb+D9rfZZsgz0XNdpW8YhM7QPmR8/loTIL7za4Je3azLr1P
         za1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="Fvrddju/";
       spf=pass (google.com: domain of 36sr5zaykczu5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=36sr5ZAYKCZU5A723G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id pq1-20020a05620a84c100b0076989bfc79fsi1479960qkn.1.2023.09.07.06.06.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Sep 2023 06:06:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36sr5zaykczu5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-d7e81a07ea3so921651276.2
        for <kasan-dev@googlegroups.com>; Thu, 07 Sep 2023 06:06:51 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:33dd:e36e:b6dc:1a69])
 (user=glider job=sendgmr) by 2002:a25:d20f:0:b0:d78:215f:ba5f with SMTP id
 j15-20020a25d20f000000b00d78215fba5fmr466389ybg.9.1694092010883; Thu, 07 Sep
 2023 06:06:50 -0700 (PDT)
Date: Thu,  7 Sep 2023 15:06:42 +0200
In-Reply-To: <20230907130642.245222-1-glider@google.com>
Mime-Version: 1.0
References: <20230907130642.245222-1-glider@google.com>
X-Mailer: git-send-email 2.42.0.283.g2d96d420d3-goog
Message-ID: <20230907130642.245222-2-glider@google.com>
Subject: [PATCH 2/2] kmsan: prevent optimizations in memcpy tests
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, dvyukov@google.com, elver@google.com, 
	akpm@linux-foundation.org, linux-mm@kvack.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="Fvrddju/";       spf=pass
 (google.com: domain of 36sr5zaykczu5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=36sr5ZAYKCZU5A723G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--glider.bounces.google.com;
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

Clang 18 learned to optimize away memcpy() calls of small uninitialized
scalar values. To ensure that memcpy tests in kmsan_test.c still perform
calls to memcpy() (which KMSAN replaces with __msan_memcpy()), declare a
separate memcpy_noinline() function with volatile parameters, which
won't be optimized.

Also retire DO_NOT_OPTIMIZE(), as memcpy_noinline() is apparently
enough.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/kmsan_test.c | 37 ++++++++++++++-----------------------
 1 file changed, 14 insertions(+), 23 deletions(-)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 312989aa2865c..0c32c917b489a 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -407,33 +407,25 @@ static void test_printk(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
-/*
- * Prevent the compiler from optimizing @var away. Without this, Clang may
- * notice that @var is uninitialized and drop memcpy() calls that use it.
- *
- * There is OPTIMIZER_HIDE_VAR() in linux/compier.h that we cannot use here,
- * because it is implemented as inline assembly receiving @var as a parameter
- * and will enforce a KMSAN check. Same is true for e.g. barrier_data(var).
- */
-#define DO_NOT_OPTIMIZE(var) barrier()
+/* Prevent the compiler from inlining a memcpy() call. */
+static noinline void *memcpy_noinline(volatile void *dst,
+				      const volatile void *src, size_t size)
+{
+	return memcpy(dst, src, size);
+}
 
-/*
- * Test case: ensure that memcpy() correctly copies initialized values.
- * Also serves as a regression test to ensure DO_NOT_OPTIMIZE() does not cause
- * extra checks.
- */
+/* Test case: ensure that memcpy() correctly copies initialized values. */
 static void test_init_memcpy(struct kunit *test)
 {
 	EXPECTATION_NO_REPORT(expect);
 	volatile int src;
 	volatile int dst = 0;
 
-	DO_NOT_OPTIMIZE(src);
 	src = 1;
 	kunit_info(
 		test,
 		"memcpy()ing aligned initialized src to aligned dst (no reports)\n");
-	memcpy((void *)&dst, (void *)&src, sizeof(src));
+	memcpy_noinline((void *)&dst, (void *)&src, sizeof(src));
 	kmsan_check_memory((void *)&dst, sizeof(dst));
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
@@ -451,8 +443,7 @@ static void test_memcpy_aligned_to_aligned(struct kunit *test)
 	kunit_info(
 		test,
 		"memcpy()ing aligned uninit src to aligned dst (UMR report)\n");
-	DO_NOT_OPTIMIZE(uninit_src);
-	memcpy((void *)&dst, (void *)&uninit_src, sizeof(uninit_src));
+	memcpy_noinline((void *)&dst, (void *)&uninit_src, sizeof(uninit_src));
 	kmsan_check_memory((void *)&dst, sizeof(dst));
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
@@ -474,8 +465,9 @@ static void test_memcpy_aligned_to_unaligned(struct kunit *test)
 	kunit_info(
 		test,
 		"memcpy()ing aligned uninit src to unaligned dst (UMR report)\n");
-	DO_NOT_OPTIMIZE(uninit_src);
-	memcpy((void *)&dst[1], (void *)&uninit_src, sizeof(uninit_src));
+	kmsan_check_memory(&uninit_src, sizeof(uninit_src));
+	memcpy_noinline((void *)&dst[1], (void *)&uninit_src,
+			sizeof(uninit_src));
 	kmsan_check_memory((void *)dst, 4);
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
@@ -498,8 +490,8 @@ static void test_memcpy_aligned_to_unaligned2(struct kunit *test)
 	kunit_info(
 		test,
 		"memcpy()ing aligned uninit src to unaligned dst - part 2 (UMR report)\n");
-	DO_NOT_OPTIMIZE(uninit_src);
-	memcpy((void *)&dst[1], (void *)&uninit_src, sizeof(uninit_src));
+	memcpy_noinline((void *)&dst[1], (void *)&uninit_src,
+			sizeof(uninit_src));
 	kmsan_check_memory((void *)&dst[4], sizeof(uninit_src));
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
@@ -513,7 +505,6 @@ static void test_memcpy_aligned_to_unaligned2(struct kunit *test)
                                                                             \
 		kunit_info(test,                                            \
 			   "memset" #size "() should initialize memory\n"); \
-		DO_NOT_OPTIMIZE(uninit);                                    \
 		memset##size((uint##size##_t *)&uninit, 0, 1);              \
 		kmsan_check_memory((void *)&uninit, sizeof(uninit));        \
 		KUNIT_EXPECT_TRUE(test, report_matches(&expect));           \
-- 
2.42.0.283.g2d96d420d3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230907130642.245222-2-glider%40google.com.
