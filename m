Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTOV7STQMGQEYTCU67A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 31B7179A92F
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 16:57:19 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2bf7c63c363sf18723731fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 07:57:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694444238; cv=pass;
        d=google.com; s=arc-20160816;
        b=pgKiDEEJfaJ83StlR+oJOMxU0/8lOISBIVhVS5Q+M//5+Dtz3Rr8GQbNQzbRczS25r
         xKy5Au7jJX88/XptdA4rkRCIkCQBHAmeMVx8/KA1D563+reTjWg0W0LU3NHBnUCrX8HF
         yGP7OEuzvsMksuoWW3cv5pMXFg95GB6upQxUYsLPtqFm68iqA0m0w0T0R1hpwPwUKP7q
         eAeB9qqElWwYGsFKiupIpIyTMONuF+cDVWVMfAu9bTJScN/Puuy01aexnZISMQtkkPvg
         kXEpAZVLW35D83SWGym0qxW00rX2YWdgQDBWbTkpx7r5wxJSRsXpCyLQCDPN2mvz3sxp
         6AMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=+0FMBcYoCu4eMrfv90K3U9kDpCd0RY8Ui/naDSAUb7A=;
        fh=x/Eq99+ICi7e9grjZNFq4mA7WJOkDm5ZB5wM283JjUk=;
        b=pzyesN4J0EKmuib96S0h2pylUbIsiMkeyDfbuXtyv6fycNNBfQwNoB7mMxGnvgakSB
         usY2/5Zsolm1gSJzMP4WooXmZxXvpoxl8xR/TfA+RqbH6FpA3MbQM/83Dfl9wZqCGDDO
         PhOq39zXCtMKO7lX/P746fkM5SPo0iFkXhnjb+ZE5KyyFFSCmmcFdNVSUYrjbG478LBf
         bUlDAFudeXdhrWmsUbwktPmIH/qt8MOAShL4sUP2BCa4GcHcwXZoG8/u0c9BPe+cWZmR
         yNUsg+tYcJGIBZIWHhd8bYh1gKitW0KDQI+7Tt/dum06E618k6hNO2X2yLniKiQaCEvL
         Tsog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=02pmChLO;
       spf=pass (google.com: domain of 3yyr_zaykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3yyr_ZAYKCUwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694444238; x=1695049038; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+0FMBcYoCu4eMrfv90K3U9kDpCd0RY8Ui/naDSAUb7A=;
        b=apXVsPQ6qxveg8Cx5SjH98UTLPPXYrgxkXqaBTDUMmWAIxw7dIbE6aFq6sevZEJI6Q
         iEkj3wFzNL+apAvh6mj9d5oyc4O/UjdEyzZsXTuypegqMyVYf5oSVyNZE9GG/S30aPlk
         0WMnwR5NCgOpHTs4KfKhXw1l0XvIdc+7TYSg7EepXjQZTcV5NmS8WDrLlXB0r7sw4tuw
         0Gh03AFic6u6moa1ZLKgAotm3C98gU0kXYBo0JuPzi1WSF/q30GY6PnsLJZR/NuBuMoS
         Z6Na3l3TpZjfqu2+0LzVNEzqBi4NWGCsKzqa/Trq5/Be1Ur9EitznWBde9z8DhHmjJvg
         YiYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694444238; x=1695049038;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+0FMBcYoCu4eMrfv90K3U9kDpCd0RY8Ui/naDSAUb7A=;
        b=LxMr8K6BcfjmqQy2xFamTGrOEx4AJ/G7V+4g8utHnFyDB+JxqnnoaHxWjjRPzQF3DO
         vuEpStMr1k07cThSi6OBY0edrDIQiCeqVrUvgJ6nX50hdx8q4CKbhywsMOHQl9AZ0ph7
         1mNUoCuydWh7KtgeivgrdPXMNJLYjDbtNyZpBVEdkIeZZpzc1YPjH0rVssMzc0UiNVyf
         GrI3WCaEsReeqCEpyHrndnAjheXL0pf0xial7VValrE8WPr5xKw4F1+xy5F6E389CTCH
         LbADFar7E3nSDrkpmTw6rrCB4D5eM6STfxu6c3orZsq3lKzRJbHhnQVLxM9X5+Ll+3vW
         +fNg==
X-Gm-Message-State: AOJu0YwirwPNzOwpC5yE5Z463jnkp8S49oGYlnKdAPyLPvLAfEWJrq/H
	QJxE8U7KSZz/EJdnjqAObDQ=
X-Google-Smtp-Source: AGHT+IHAZvtoISMVjTFjveavpnqi3qnNzcJ1sLMIK4pAcOz46Yqmxi5NJ/TGayQvAswhtjzwMXpV5A==
X-Received: by 2002:a2e:3016:0:b0:2b9:ecab:d924 with SMTP id w22-20020a2e3016000000b002b9ecabd924mr8389408ljw.18.1694444237705;
        Mon, 11 Sep 2023 07:57:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b90f:0:b0:2b6:9e60:5995 with SMTP id b15-20020a2eb90f000000b002b69e605995ls509725ljb.0.-pod-prod-07-eu;
 Mon, 11 Sep 2023 07:57:16 -0700 (PDT)
X-Received: by 2002:a05:6512:ba9:b0:500:a3be:1ab6 with SMTP id b41-20020a0565120ba900b00500a3be1ab6mr9809069lfv.6.1694444235991;
        Mon, 11 Sep 2023 07:57:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694444235; cv=none;
        d=google.com; s=arc-20160816;
        b=fS3rsLh5bOnuIk8hw0tboXv6KuIUTws4j7yrdt3NfyAK4A6fb80e8QJOYmlPBicNp2
         +QuubFRLFZv5bsY87F9ysffrISCO/cT863iQPiLfuRwm8xDnufdzuVEwvc5tuxrbM/y9
         2c5nMD5IhyzxeUvr0x42CyW6qtn5ZW3xok2b9uPz3fPpC7k64ZoUbPB+OvfXNvC+Fjfk
         Z/mhAyZf5fJ+rwweWtva8mcXqjBAIitGetwmM5ENhca8inURt/2Tx0j1E/3r+OEQuwiX
         PEBhAz9RlZJroXVxLt4ZRLc1pex3QBqdfco08GwBGxyCOLPwkpIWAqXXS8XuFcpyJr+p
         pp9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=TCSVjF+G/Yb3+dPBWGz9EuIiyh+/ldUAKZlZ+MbeoHM=;
        fh=x/Eq99+ICi7e9grjZNFq4mA7WJOkDm5ZB5wM283JjUk=;
        b=UbOMGrEnnq5dF+DTcdqzozCP8hjSoGsOjkIz/PI2j2Q7YmC+Ug73XYD1MUERcE/gyR
         /NDbEgA4rtocufq1maLO6LGyAnn+xGuWt0TVOuiKy43utlEy/EcXFJWffe2DbLds1CF+
         wr6SfuGgYewj/b25fPU5jMmKcZr071UkOI2FUwPXNHrYOH0+iPKk/LC7njiGsB65HTSG
         NjrszGFuJTSIhW1Nqk4r9ibK308tZTgaWR+NXGkIAoFnnYmLmT/N2iQAYuZgttr2THYi
         Df19Fxd0menNS4DfZIJBoLrNapfjcDJtekHRcu3W/efDbcOV1XVA5smFMMPFEK8olG4+
         eXUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=02pmChLO;
       spf=pass (google.com: domain of 3yyr_zaykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3yyr_ZAYKCUwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id n10-20020a05651203ea00b00500d9706548si593361lfq.12.2023.09.11.07.57.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Sep 2023 07:57:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yyr_zaykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-31f87a56b46so1414608f8f.2
        for <kasan-dev@googlegroups.com>; Mon, 11 Sep 2023 07:57:15 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:62e7:6658:cb4:b858])
 (user=glider job=sendgmr) by 2002:adf:ce84:0:b0:317:41be:d871 with SMTP id
 r4-20020adfce84000000b0031741bed871mr114853wrn.14.1694444235317; Mon, 11 Sep
 2023 07:57:15 -0700 (PDT)
Date: Mon, 11 Sep 2023 16:57:00 +0200
In-Reply-To: <20230911145702.2663753-1-glider@google.com>
Mime-Version: 1.0
References: <20230911145702.2663753-1-glider@google.com>
X-Mailer: git-send-email 2.42.0.283.g2d96d420d3-goog
Message-ID: <20230911145702.2663753-2-glider@google.com>
Subject: [PATCH v2 2/4] kmsan: prevent optimizations in memcpy tests
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, dvyukov@google.com, elver@google.com, 
	akpm@linux-foundation.org, linux-mm@kvack.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=02pmChLO;       spf=pass
 (google.com: domain of 3yyr_zaykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3yyr_ZAYKCUwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
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
v2:
 - fix W=1 warnings reported by LKP test robot
---
 mm/kmsan/kmsan_test.c | 41 ++++++++++++++++-------------------------
 1 file changed, 16 insertions(+), 25 deletions(-)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 312989aa2865c..a8d4ca4a1066d 100644
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
+	return memcpy((void *)dst, (const void *)src, size);
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
-	volatile int src;
-	volatile int dst = 0;
+	volatile long long src;
+	volatile long long dst = 0;
 
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
+	kmsan_check_memory((void *)&uninit_src, sizeof(uninit_src));
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230911145702.2663753-2-glider%40google.com.
