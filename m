Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBL5C6PCAMGQEW2HYVBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D00FB25297
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 19:53:53 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-70a928136a0sf4747676d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 10:53:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755107632; cv=pass;
        d=google.com; s=arc-20240605;
        b=cJGz1+UayHh2svsECDQ40F44hcdbJDNCONdc49Oy03UONtpjBs6apaebPtw+39oVWk
         JFKpNYTp8fFtpmoaECH2HPkE8554QpstDwXxg5OAWzntk+EyX5qM8tohNWMTD02dw3Lh
         k8z0OdzTni0rq2FzEZ/b0ExESk8Ahla4i+YXvqdWdYjANYWtyutABGG9uuNYTf4YtLy5
         uwERUOOveGRu3gUq+oyYgm+Ww24L+LK2sDRQUqM52g2ThA78ufBjlDSUajcWNaCmUnbD
         EcYc4vrHOFnDD47bSB0GX13fDoBsGN4jVX01l3DRlHVQ6EJShfzOvU5Hd0k71pgmtXmE
         vL8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OsCgqmY76c5+r2LdjkeCdGtQZO2u/SClCAV87q9umc8=;
        fh=U3wGOBTl9+DVYV4MfSkF/aDSEmFpr676/UjdXq8/Hxk=;
        b=RGiOUtFSggpUnp7S+gPcgy0rAPQrf7vtUgiLxEWw3HLrKUz1DB7JpvWFu5KLUZXAVl
         YBQ0HtrZkbV2knmdqFXsIBnqgpA3rql39Tlyu7A4IiVdpOT0NAiulxHhAAoLu97EeQj6
         REOLSAyKkXu+TPI3cTYW62dr2aMlu4ProvTqo6N3W2jgCMdBGb7pFeq9386w3FgVljvr
         HiXskFExqXotuAikPBYXpk3M3OjrJrutXSQQaBber3EMvAxQeQO+xQ5vEvZ/OOUFmbvx
         zpJqxl2n+PB3HRhDoXRmgaCOwI3anvqHrgiGvNqQWzEpm0qORSUz8P4pGatK1PCDnts0
         drnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755107632; x=1755712432; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OsCgqmY76c5+r2LdjkeCdGtQZO2u/SClCAV87q9umc8=;
        b=V/lwsh7wGcJ97E8xCkgwZNsDe51nbuS2x0T89r414+OshlwamTnQg1BgOYipUyv2cu
         vIQdLU3dzgH9k0FM/RKFoFI/nJ37/Xsls9nVMJSqoCAKZpG+Y/mL6vqt4IcQDaUgeHoD
         F/ZXK02QFeOF+UcS6HxqR70gShzmpW/2Y4nxQ1dqJU5n9Vnkdsrto6IG8W89Zygaf4jN
         1bAqVGWWPAMAmr0yYC9UihUn94KYTYxKxMMVlI2h9M7N9p8/3cHUdsp0Ivs4OjvvtUX5
         sbz+BHz2gklcYK4o9Yi8GkxRfm6dEJDvJ8whndmNErd9z7Adu6kVrVovcBuve5rgR9+9
         NNfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755107632; x=1755712432;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OsCgqmY76c5+r2LdjkeCdGtQZO2u/SClCAV87q9umc8=;
        b=jvn7ud9k5VjkPg2YygjY7pJdyO0453xZGF5/f/BcRjvwkz24MP7ohROkYZ7so2HNmk
         EGSB7gD8Nw9l4S84VudxTJ+l+QorxUDY0FfgTDIPk1Z5Hk23JivVI3zHT4aMTXyMuZ5g
         hWf4fZ9GB0kr44qtW3G4BHpAFnx+wVb238V3LjGIkFgjNlhOnUTa0QdGv13DxXI0umpS
         oV4YumBsqGMyAeM0DKXgegIupC4JubP+LXr1XZS+m7rjoFD/yoLP/iNh0JBjSQypryR3
         HJdTIBW9nhTt1hRSn+4hLLaobUD0M1ZgPaCbaipO9KR/iVGhffwjMQvslB/Fqc+HZW9P
         n5rQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUDkj+SfSgk98wQH42dcbYaa8BUTwUwgaaZbX5jLsQMwBOfEfZIdZXiPwZFmM4qicz5rL9f7g==@lfdr.de
X-Gm-Message-State: AOJu0YwjtyYeOW/5o5xPDUYFgF3omKHVVz6YpZWchz6RoN6KT/QeOXIX
	0X3X1xQuwK18jRD9am2/tT8il9YO9pBYuf/eLS74DsDMIA/D1XFOLWtR
X-Google-Smtp-Source: AGHT+IGMgb9TCGUAg3QyUvPjTpL7zAM64qDaczKuzSu6U/ymj/RwsiQkNsBY4ZmRa/BUzp4L8LyajQ==
X-Received: by 2002:ad4:5cad:0:b0:707:451e:2787 with SMTP id 6a1803df08f44-70ae701266amr3928396d6.28.1755107631584;
        Wed, 13 Aug 2025 10:53:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdIniXkwwPNfCgdul+tMiMZR+ThrXuh9YIchtBgsg8VWQ==
Received: by 2002:a05:6214:2a89:b0:709:626e:c1f5 with SMTP id
 6a1803df08f44-70aabfb708cls2220436d6.2.-pod-prod-04-us; Wed, 13 Aug 2025
 10:53:50 -0700 (PDT)
X-Received: by 2002:ae9:ee17:0:b0:7e3:28f3:899 with SMTP id af79cd13be357-7e8705753cemr25118785a.39.1755107630547;
        Wed, 13 Aug 2025 10:53:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755107630; cv=none;
        d=google.com; s=arc-20240605;
        b=Ij75D3VOrqK9ju6X56auGjeR1XmthJuV36jyor0x943OHUs7mBAJr38x67JLNHVkAw
         7pqemTwesWPTaDVP15zXkseSvRrfPjMkw/1ixam14Tinx3VgjlX9vaPSE8OCzscrO845
         0mh/MKobssHnE4e3fJ+WYAqoLK7ARLO/jHxfEbrh0afs/dHR2orZfMmoMyXihUbw7yAY
         lvyWiOBp3BWtji+TY7j37XTXWUYmZqxp2uJckM+NAgwcGPItMyyJLRFwYIu9KO7FzAaC
         2zAVcZ12w880rQ5ie5giKiXs2b8sYUgTSe3R8WkEaFNkgSECEukhC+bABMAYkLcVcewL
         9/9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=yl1aAZI639TF0ZsUC8UdMRyW4Q9Mixl6sAxJtCu1eg8=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=KKZ4NAiyEEuyPxWzPwcu5hGSGlkhtgHViJxXMsf7zzG+xDlCM0+oE3ie8Tse/YvSjp
         G+8pQALaaqgWdFJu85AGQOyDe18ZJcntxd16rOn31KTH6s1x6fRUwVGj5ji1NlcMCyAV
         h2Ht6VOuWCFjKrBD2DcpXgxx3Z6dx1upJAMnJ+jeMecLP1K1DgQHbx2uY6Fg+FiTn56k
         Drju6IYpnUDOtwWeBKiYb40+4UBRYfvrWUjejrb7HVDs3dMQVM0frqsNR9lXLABliv6W
         vrjZqgV/1c2DzZJqIAS1X8uN19lZ+i0hEbqZqI12pfVJnhPb4HHTBOlnOBK5rMXBt52i
         aygA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id af79cd13be357-7e7fe360ea4si107153885a.1.2025.08.13.10.53.50
        for <kasan-dev@googlegroups.com>;
        Wed, 13 Aug 2025 10:53:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9C08012FC;
	Wed, 13 Aug 2025 10:53:41 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id BBD5A3F5A1;
	Wed, 13 Aug 2025 10:53:45 -0700 (PDT)
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	corbet@lwn.net,
	catalin.marinas@arm.com,
	will@kernel.org,
	akpm@linux-foundation.org,
	scott@os.amperecomputing.com,
	jhubbard@nvidia.com,
	pankaj.gupta@amd.com,
	leitao@debian.org,
	kaleshsingh@google.com,
	maz@kernel.org,
	broonie@kernel.org,
	oliver.upton@linux.dev,
	james.morse@arm.com,
	ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io,
	david@redhat.com,
	yang@os.amperecomputing.com
Cc: kasan-dev@googlegroups.com,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org,
	Yeoreum Yun <yeoreum.yun@arm.com>
Subject: [PATCH v2 2/2] kasan: apply store-only mode in kasan kunit testcases
Date: Wed, 13 Aug 2025 18:53:35 +0100
Message-Id: <20250813175335.3980268-3-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250813175335.3980268-1-yeoreum.yun@arm.com>
References: <20250813175335.3980268-1-yeoreum.yun@arm.com>
MIME-Version: 1.0
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

When KASAN is configured in store-only mode,
fetch/load operations do not trigger tag check faults.

As a result, the outcome of some test cases may differ
compared to when KASAN is configured without store-only mode.

Therefore, by modifying pre-exist testcases
check the store only makes tag check fault (TCF) where
writing is perform in "allocated memory" but tag is invalid
(i.e) redzone write in atomic_set() testcases.
Otherwise check the invalid fetch/read doesn't generate TCF.

Also, skip some testcases affected by initial value
(i.e) atomic_cmpxchg() testcase maybe successd if
it passes valid atomic_t address and invalid oldaval address.
In this case, if invalid atomic_t doesn't have the same oldval,
it won't trigger store operation so the test will pass.

Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
---
 mm/kasan/kasan_test_c.c | 366 +++++++++++++++++++++++++++++++---------
 1 file changed, 286 insertions(+), 80 deletions(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 2aa12dfa427a..e5d08a6ee3a2 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -94,11 +94,13 @@ static void kasan_test_exit(struct kunit *test)
 }
 
 /**
- * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produces a
- * KASAN report; causes a KUnit test failure otherwise.
+ * _KUNIT_EXPECT_KASAN_TEMPLATE - check that the executed expression produces
+ * a KASAN report or not; a KUnit test failure when it's different from @produce.
  *
  * @test: Currently executing KUnit test.
- * @expression: Expression that must produce a KASAN report.
+ * @expr: Expression produce a KASAN report or not.
+ * @expr_str: Expression string
+ * @produce: expression should produce a KASAN report.
  *
  * For hardware tag-based KASAN, when a synchronous tag fault happens, tag
  * checking is auto-disabled. When this happens, this test handler reenables
@@ -110,25 +112,29 @@ static void kasan_test_exit(struct kunit *test)
  * Use READ/WRITE_ONCE() for the accesses and compiler barriers around the
  * expression to prevent that.
  *
- * In between KUNIT_EXPECT_KASAN_FAIL checks, test_status.report_found is kept
+ * In between _KUNIT_EXPECT_KASAN_TEMPLATE checks, test_status.report_found is kept
  * as false. This allows detecting KASAN reports that happen outside of the
  * checks by asserting !test_status.report_found at the start of
- * KUNIT_EXPECT_KASAN_FAIL and in kasan_test_exit.
+ * _KUNIT_EXPECT_KASAN_TEMPLATE and in kasan_test_exit.
  */
-#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {			\
+#define _KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, expr_str, produce)	\
+do {									\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&				\
 	    kasan_sync_fault_possible())				\
 		migrate_disable();					\
 	KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found));	\
 	barrier();							\
-	expression;							\
+	expr;								\
 	barrier();							\
 	if (kasan_async_fault_possible())				\
 		kasan_force_async_fault();				\
-	if (!READ_ONCE(test_status.report_found)) {			\
-		KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN failure "	\
-				"expected in \"" #expression		\
-				 "\", but none occurred");		\
+	if (READ_ONCE(test_status.report_found) != produce) {		\
+		KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN %s "	\
+				"expected in \"" expr_str		\
+				 "\", but %soccurred",			\
+				(produce ? "failure" : "success"),	\
+				(test_status.report_found ?		\
+				 "" : "none "));			\
 	}								\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&				\
 	    kasan_sync_fault_possible()) {				\
@@ -141,6 +147,26 @@ static void kasan_test_exit(struct kunit *test)
 	WRITE_ONCE(test_status.async_fault, false);			\
 } while (0)
 
+/*
+ * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produces a
+ * KASAN report; causes a KUnit test failure otherwise.
+ *
+ * @test: Currently executing KUnit test.
+ * @expr: Expression produce a KASAN report.
+ */
+#define KUNIT_EXPECT_KASAN_FAIL(test, expr)			\
+	_KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, #expr, true)
+
+/*
+ * KUNIT_EXPECT_KASAN_SUCCESS - check that the executed expression doesn't
+ * produces a KASAN report; causes a KUnit test failure otherwise.
+ *
+ * @test: Currently executing KUnit test.
+ * @expr: Expression doesn't produce a KASAN report.
+ */
+#define KUNIT_EXPECT_KASAN_SUCCESS(test, expr)			\
+	_KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, #expr, false)
+
 #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {			\
 	if (!IS_ENABLED(config))					\
 		kunit_skip((test), "Test requires " #config "=y");	\
@@ -183,8 +209,12 @@ static void kmalloc_oob_right(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + 5] = 'y');
 
 	/* Out-of-bounds access past the aligned kmalloc object. */
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =
-					ptr[size + KASAN_GRANULE_SIZE + 5]);
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, ptr[0] =
+						ptr[size + KASAN_GRANULE_SIZE + 5]);
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =
+						ptr[size + KASAN_GRANULE_SIZE + 5]);
 
 	kfree(ptr);
 }
@@ -198,7 +228,11 @@ static void kmalloc_oob_left(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	OPTIMIZER_HIDE_VAR(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, *ptr = *(ptr - 1));
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
+
 	kfree(ptr);
 }
 
@@ -211,7 +245,11 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	OPTIMIZER_HIDE_VAR(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, ptr[0] = ptr[size]);
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
+
 	kfree(ptr);
 }
 
@@ -291,7 +329,10 @@ static void kmalloc_large_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	kfree(ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[0]);
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 }
 
 static void kmalloc_large_invalid_free(struct kunit *test)
@@ -323,7 +364,11 @@ static void page_alloc_oob_right(struct kunit *test)
 	ptr = page_address(pages);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, ptr[0] = ptr[size]);
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
+
 	free_pages((unsigned long)ptr, order);
 }
 
@@ -338,7 +383,10 @@ static void page_alloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	free_pages((unsigned long)ptr, order);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[0]);
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 }
 
 static void krealloc_more_oob_helper(struct kunit *test,
@@ -455,10 +503,13 @@ static void krealloc_uaf(struct kunit *test)
 	ptr1 = kmalloc(size1, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
 	kfree(ptr1);
-
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr2 = krealloc(ptr1, size2, GFP_KERNEL));
 	KUNIT_ASSERT_NULL(test, ptr2);
-	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
+
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, *(volatile char *)ptr1);
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
 }
 
 static void kmalloc_oob_16(struct kunit *test)
@@ -501,7 +552,11 @@ static void kmalloc_uaf_16(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 	kfree(ptr2);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, *ptr1 = *ptr2);
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
+
 	kfree(ptr1);
 }
 
@@ -640,8 +695,14 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
 	memset((char *)ptr, 0, 64);
 	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(invalid_size);
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
+
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test,
+			memmove((char *)ptr, (char *)ptr + 4, invalid_size));
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test,
+			memmove((char *)ptr, (char *)ptr + 4, invalid_size));
+
 	kfree(ptr);
 }
 
@@ -654,7 +715,11 @@ static void kmalloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	kfree(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
+
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[8]);
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
 }
 
 static void kmalloc_uaf_memset(struct kunit *test)
@@ -701,7 +766,11 @@ static void kmalloc_uaf2(struct kunit *test)
 		goto again;
 	}
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]);
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr1)[40]);
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]);
+
 	KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
 
 	kfree(ptr2);
@@ -727,19 +796,33 @@ static void kmalloc_uaf3(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 	kfree(ptr2);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[8]);
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr1)[8]);
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[8]);
 }
 
 static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *safe)
 {
 	int *i_unsafe = unsafe;
 
-	KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, READ_ONCE(*i_unsafe));
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
+
 	KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
-	KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, smp_load_acquire(i_unsafe));
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
 
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, atomic_read(unsafe));
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
+
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
@@ -752,18 +835,38 @@ static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *safe)
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, 42));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42));
+
+	/*
+	 * The result of the test below may vary due to garbage values of unsafe in
+	 * store-only mode. Therefore, skip this test when KASAN is configured
+	 * in store-only mode.
+	 */
+	if (!kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42));
+
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub_and_test(42, unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_and_test(unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_and_test(unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_negative(42, unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
 
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
+	/*
+	 * The result of the test below may vary due to garbage values of unsafe in
+	 * store-only mode. Therefore, skip this test when KASAN is configured
+	 * in store-only mode.
+	 */
+	if (!kasan_store_only_enabled()) {
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
+	}
+
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, atomic_long_read(unsafe));
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
+
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
@@ -776,16 +879,32 @@ static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *safe)
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xchg(unsafe, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_cmpxchg(unsafe, 21, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(unsafe, safe, 42));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsafe, 42));
+
+	/*
+	 * The result of the test below may vary due to garbage values in
+	 * store-only mode. Therefore, skip this test when KASAN is configured
+	 * in store-only mode.
+	 */
+	if (!kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsafe, 42));
+
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub_and_test(42, unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_and_test(unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_and_test(unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_negative(42, unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, 42));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe));
+
+	/*
+	 * The result of the test below may vary due to garbage values in
+	 * store-only mode. Therefore, skip this test when KASAN is configured
+	 * in store-only mode.
+	 */
+	if (!kasan_store_only_enabled()) {
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, 42));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe));
+	}
 }
 
 static void kasan_atomics(struct kunit *test)
@@ -842,8 +961,14 @@ static void ksize_unpoisons_memory(struct kunit *test)
 	/* These must trigger a KASAN report. */
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
 		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size + 5]);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);
+
+	if (kasan_store_only_enabled()) {
+		KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[size + 5]);
+		KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[real_size - 1]);
+	} else {
+		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size + 5]);
+		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);
+	}
 
 	kfree(ptr);
 }
@@ -863,8 +988,13 @@ static void ksize_uaf(struct kunit *test)
 
 	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
+	if (kasan_store_only_enabled()) {
+		KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[0]);
+		KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[size]);
+	} else {
+		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
+	}
 }
 
 /*
@@ -886,6 +1016,7 @@ static void rcu_uaf_reclaim(struct rcu_head *rp)
 		container_of(rp, struct kasan_rcu_info, rcu);
 
 	kfree(fp);
+
 	((volatile struct kasan_rcu_info *)fp)->i;
 }
 
@@ -899,9 +1030,14 @@ static void rcu_uaf(struct kunit *test)
 	global_rcu_ptr = rcu_dereference_protected(
 				(struct kasan_rcu_info __rcu *)ptr, NULL);
 
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
-		rcu_barrier());
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test,
+			call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
+			rcu_barrier());
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test,
+			call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
+			rcu_barrier());
 }
 
 static void workqueue_uaf_work(struct work_struct *work)
@@ -924,8 +1060,12 @@ static void workqueue_uaf(struct kunit *test)
 	queue_work(workqueue, work);
 	destroy_workqueue(workqueue);
 
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		((volatile struct work_struct *)work)->data);
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test,
+			((volatile struct work_struct *)work)->data);
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test,
+			((volatile struct work_struct *)work)->data);
 }
 
 static void kfree_via_page(struct kunit *test)
@@ -972,7 +1112,10 @@ static void kmem_cache_oob(struct kunit *test)
 		return;
 	}
 
-	KUNIT_EXPECT_KASAN_FAIL(test, *p = p[size + OOB_TAG_OFF]);
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, *p = p[size + OOB_TAG_OFF]);
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, *p = p[size + OOB_TAG_OFF]);
 
 	kmem_cache_free(cache, p);
 	kmem_cache_destroy(cache);
@@ -1068,7 +1211,10 @@ static void kmem_cache_rcu_uaf(struct kunit *test)
 	 */
 	rcu_barrier();
 
-	KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, READ_ONCE(*p));
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
 
 	kmem_cache_destroy(cache);
 }
@@ -1206,6 +1352,9 @@ static void mempool_oob_right_helper(struct kunit *test, mempool_t *pool, size_t
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
 		KUNIT_EXPECT_KASAN_FAIL(test,
 			((volatile char *)&elem[size])[0]);
+	else if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test,
+			((volatile char *)&elem[round_up(size, KASAN_GRANULE_SIZE)])[0]);
 	else
 		KUNIT_EXPECT_KASAN_FAIL(test,
 			((volatile char *)&elem[round_up(size, KASAN_GRANULE_SIZE)])[0]);
@@ -1273,7 +1422,11 @@ static void mempool_uaf_helper(struct kunit *test, mempool_t *pool, bool page)
 	mempool_free(elem, pool);
 
 	ptr = page ? page_address((struct page *)elem) : elem;
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[0]);
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 }
 
 static void mempool_kmalloc_uaf(struct kunit *test)
@@ -1532,8 +1685,13 @@ static void kasan_memchr(struct kunit *test)
 
 	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		kasan_ptr_result = memchr(ptr, '1', size + 1));
+
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test,
+			kasan_ptr_result = memchr(ptr, '1', size + 1));
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test,
+			kasan_ptr_result = memchr(ptr, '1', size + 1));
 
 	kfree(ptr);
 }
@@ -1559,8 +1717,14 @@ static void kasan_memcmp(struct kunit *test)
 
 	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		kasan_int_result = memcmp(ptr, arr, size+1));
+
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test,
+			kasan_int_result = memcmp(ptr, arr, size+1));
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test,
+			kasan_int_result = memcmp(ptr, arr, size+1));
+
 	kfree(ptr);
 }
 
@@ -1593,9 +1757,13 @@ static void kasan_strings(struct kunit *test)
 	KUNIT_EXPECT_EQ(test, KASAN_GRANULE_SIZE - 2,
 			strscpy(ptr, src + 1, KASAN_GRANULE_SIZE));
 
-	/* strscpy should fail if the first byte is unreadable. */
-	KUNIT_EXPECT_KASAN_FAIL(test, strscpy(ptr, src + KASAN_GRANULE_SIZE,
-					      KASAN_GRANULE_SIZE));
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, strscpy(ptr, src + KASAN_GRANULE_SIZE,
+						      KASAN_GRANULE_SIZE));
+	else
+		/* strscpy should fail if the first byte is unreadable. */
+		KUNIT_EXPECT_KASAN_FAIL(test, strscpy(ptr, src + KASAN_GRANULE_SIZE,
+						      KASAN_GRANULE_SIZE));
 
 	kfree(src);
 	kfree(ptr);
@@ -1607,17 +1775,22 @@ static void kasan_strings(struct kunit *test)
 	 * will likely point to zeroed byte.
 	 */
 	ptr += 16;
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result = strchr(ptr, '1'));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result = strrchr(ptr, '1'));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strcmp(ptr, "2"));
 
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strncmp(ptr, "2", 1));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strlen(ptr));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strnlen(ptr, 1));
+	if (kasan_store_only_enabled()) {
+		KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_ptr_result = strchr(ptr, '1'));
+		KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_ptr_result = strrchr(ptr, '1'));
+		KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_int_result = strcmp(ptr, "2"));
+		KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_int_result = strncmp(ptr, "2", 1));
+		KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_int_result = strlen(ptr));
+		KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_int_result = strnlen(ptr, 1));
+	} else {
+		KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result = strchr(ptr, '1'));
+		KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result = strrchr(ptr, '1'));
+		KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strcmp(ptr, "2"));
+		KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strncmp(ptr, "2", 1));
+		KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strlen(ptr));
+		KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strnlen(ptr, 1));
+	}
 }
 
 static void kasan_bitops_modify(struct kunit *test, int nr, void *addr)
@@ -1636,12 +1809,25 @@ static void kasan_bitops_test_and_modify(struct kunit *test, int nr, void *addr)
 {
 	KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit(nr, addr));
 	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_set_bit(nr, addr));
-	KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
+
+	/*
+	 * When KASAN is running in store-only mode,
+	 * a fault won't occur even if the bit is set.
+	 * Therefore, skip the test_and_set_bit_lock test in store-only mode.
+	 */
+	if (!kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
+
 	KUNIT_EXPECT_KASAN_FAIL(test, test_and_clear_bit(nr, addr));
 	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_clear_bit(nr, addr));
 	KUNIT_EXPECT_KASAN_FAIL(test, test_and_change_bit(nr, addr));
 	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_change_bit(nr, addr));
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = test_bit(nr, addr));
+
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_int_result = test_bit(nr, addr));
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = test_bit(nr, addr));
+
 	if (nr < 7)
 		KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =
 				xor_unlock_is_negative_byte(1 << nr, addr));
@@ -1765,7 +1951,10 @@ static void vmalloc_oob(struct kunit *test)
 		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size]);
 
 	/* An aligned access into the first out-of-bounds granule. */
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size + 5]);
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)v_ptr)[size + 5]);
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size + 5]);
 
 	/* Check that in-bounds accesses to the physical page are valid. */
 	page = vmalloc_to_page(v_ptr);
@@ -2042,16 +2231,33 @@ static void copy_user_test_oob(struct kunit *test)
 
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		unused = copy_from_user(kmem, usermem, size + 1));
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		unused = copy_to_user(usermem, kmem, size + 1));
+
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test,
+			unused = copy_to_user(usermem, kmem, size + 1));
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test,
+			unused = copy_to_user(usermem, kmem, size + 1));
+
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		unused = __copy_from_user(kmem, usermem, size + 1));
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		unused = __copy_to_user(usermem, kmem, size + 1));
+
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test,
+			unused = __copy_to_user(usermem, kmem, size + 1));
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test,
+			unused = __copy_to_user(usermem, kmem, size + 1));
+
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		unused = __copy_from_user_inatomic(kmem, usermem, size + 1));
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		unused = __copy_to_user_inatomic(usermem, kmem, size + 1));
+
+	if (kasan_store_only_enabled())
+		KUNIT_EXPECT_KASAN_SUCCESS(test,
+			unused = __copy_to_user_inatomic(usermem, kmem, size + 1));
+	else
+		KUNIT_EXPECT_KASAN_FAIL(test,
+			unused = __copy_to_user_inatomic(usermem, kmem, size + 1));
 
 	/*
 	* Prepare a long string in usermem to avoid the strncpy_from_user test
-- 
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250813175335.3980268-3-yeoreum.yun%40arm.com.
