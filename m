Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBDXT2XCQMGQEOV2K23A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 33299B3E091
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 12:46:40 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-70f9ef271a4sf47919616d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 03:46:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756723599; cv=pass;
        d=google.com; s=arc-20240605;
        b=jiC/fStThpfrr6gPm6gERRfS6KDJMHp/SglxibLcrHuD05iQ4Fc6OcgwKER/m5nXIK
         yaDQ+1A0anq1Y70xJFwiUfW44uNe/NBuUCyGMrXRMfU/VyQCw0sHsHfiBYsstIDrVSS6
         9cGeghKlHut/w0iME82GdEqdwtK5uhSXqJTVlgfbYK6m7FerohHT459Cr+JE8pWnY84C
         tlOk15XBPvgsp/HlznCVPy3Gbg80PIVqKltdIWz+fFCXQEy9vL+4Hjh6r3ckPJQzydcJ
         bDr+Rz/w5HIAPDYxjTLdAXzrCkW3ZgpjvqBGShsOqKCGl6uzpMzcgc5jWiGX0cdoV7zr
         /NZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nJpwc8Ae7Nktk1KiKN/5sMNj2leM2Gf6KeHERWL1nJ0=;
        fh=ZOz4rjvr429Y1j16naaahj2IvMrV5Qok/aqeYM06uko=;
        b=W+a5tOLb+0KNx6fBLafS9HZ1xctL7h36rBglOZgRCE3YG6YLWpqsWqYhGewRHvYR/R
         zPLwpH/25oTfC7JGCQ/i93UidNM107rSf9rdQ4wQ/qCPOlsP5e6vHlSbdo8oduNOIk5h
         HxT/CzwXWxYyadkk/PfHW0fmb2fXvAD1wpW8WXLf7JmUmG1oRUxHnBvfRf0KILE+a7Jg
         muEglLeF4skkmx5SlqV5ye3mhnxW7pD/oQFEAoIGJOvXG/KCRtkDYpXZxGMdHtv0YCmX
         zbMbmqMxWpyBwZ6ycnOSby6gD1zy3u14U5M8xiVTMzC65s26+6raR+K0N5r5ISvpg1Kg
         mRNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756723599; x=1757328399; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nJpwc8Ae7Nktk1KiKN/5sMNj2leM2Gf6KeHERWL1nJ0=;
        b=i+5znIAH48SO6no0i50jbhELgUVr92A/7kFggDwO1MXpzbk8cJgv29pH3lIRRQpHjY
         IEYDK6AuYq/SF9VSPWesH3JGEBHURko0e+GBGPrq859oS/E7hi/62Q6JmVvI+ibVotbe
         hJdO8tjubBc3usrLI/iVC88I6LumVyeLE7hrzMbC9kIQIsD+UpbcOhKGYNFyqFGj2sQl
         q3lSwSil/1aJi32XTMrWAu+MgAL+hyL52CM6qwsc8bpajkBkZXKvkjmFutazTge6NLiv
         zmlo/2yl4B+qbx8ICERSbwHbf1+hQGZlFNHkL4rwbDKSR3nCPxl2D/fJ0CshqikloDiZ
         Jd/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756723599; x=1757328399;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nJpwc8Ae7Nktk1KiKN/5sMNj2leM2Gf6KeHERWL1nJ0=;
        b=Ha4faZ2mfccC2PH1gn5FU79nYgruWPpdVhm9/KwgFyGvqIY/VFze/LsLlmn4doFiUV
         bYUthBVmCYjfAwJZFu+JNEcP+YCSe/XLo4BX76PoJeRhSFGT1ct5adEAd5CwSLjAqOvV
         C42VsI9uPusqtG7H1nMBcd7t0iCLlbBoWjPdOPd/CSD4rZu127KyCKNXoOWfF4YX3Mgu
         0yrKcOOconVFxpKJdFSbxVd6YUAozF5FBRgT2vJArpW4xyKzbGgT7TQn5EAk3GEuUhQ2
         Z5B/0mMW+e1soU5v5XVMxFe55yb3YfuuO39xJvzWOfd9OTxg0weYL84xdd5j3RR4jIs2
         wBvA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV2twUC+cxatEwy+Hbk7Xt+JHVlIYsGgTnBv/kGVDdF1GKi5tJjuWSCYTNZFnpMwbF3ayAkHQ==@lfdr.de
X-Gm-Message-State: AOJu0YyUzzShQaRt92cEV6gGuSi3M8KaiMUzUk/Fuy9MebGSeHFLDRlY
	EPDt1VT/SnYOPbEu6R9+kwqaVxuGTaej3Uq97RFBeHaYEo43cw0M8K6E
X-Google-Smtp-Source: AGHT+IEfPGC2sCeey/d9lKa6ELjS0Zs4iqgrbIfUr+Mk30hkJs6dtYYv5sqF/Y9b2sV8X16tPxe9uA==
X-Received: by 2002:a05:6214:40d:b0:70d:cc9d:7ed4 with SMTP id 6a1803df08f44-70fac78ee0emr88781496d6.11.1756723598822;
        Mon, 01 Sep 2025 03:46:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZckq5ba+MdeBLZ0bz+Z00XsmUR8LbdbOexQArN4jFljdg==
Received: by 2002:a05:6214:2f10:b0:707:18b0:de30 with SMTP id
 6a1803df08f44-70defdedb71ls29954916d6.1.-pod-prod-00-us-canary; Mon, 01 Sep
 2025 03:46:38 -0700 (PDT)
X-Received: by 2002:a05:6122:a0b:b0:539:4bf9:233a with SMTP id 71dfb90a1353d-544a02df1f5mr2131102e0c.5.1756723598078;
        Mon, 01 Sep 2025 03:46:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756723598; cv=none;
        d=google.com; s=arc-20240605;
        b=SyxDum8EDDTFl/4YoYNy5sntG3sP3OPGzQlrpiGFpW/E67EyRQmbihciXIuUzAQ4Ri
         ATiMeQxcCjont5NxhaP0QG4Lg4jrfzmWn6bTOQXayYJHq5rc1QF2iX8YI8CSZ9ez87fv
         CYPyCfkNrnqkCAMr6KBA6uwTrcW/L8MuYK/SZOXOadBrKmKj37TxdzE1r5EAP7jQHkJf
         8jTw3UXGzMEYHkyDtTxrS6jXh3bPNaAMh3+i9vA7NzQzHBJgULB3rj12bL6qVHgczrTC
         9aSdjJlpcqSTEUtWXW0jBrUuE5OF3dhHE4U7X3s6GS4zR4Q4ydd3V79ogI73QNJlG0dj
         Rupg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=HEz/4t0m9hqvMtGXtgLG1PSZqiUIjkhX4CdvpdyqYCE=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=atLC2pTBJBB0Lqlal64Q34SIImt8hy0vzuh55lL0k516lNY+TaVYhLgHvIu21E7eKt
         tkpEw6YSkv75/1LRAohBYgWMg22QVyZOxfc2UA7i4+9Rm10EBXPBzQ4MftM2RuLsWS7Q
         BMI/YsW512Unru0MOSkwrHcAPp+7K5RfzUwa5sfwq2eiLJvkBl4MrPdPNwb0+6Sltodh
         UVj5riPJFACNzp1yrHkZPSlB/Xek7z/7uh5uh2cAcVvaiXYlAh7LTQ0/yQf1JKjlec45
         gmU/fhk9p1h0jibcENeuZV/nRhbQKvbPeYCaaUKoF4qzLBUut1OFxtQKB8m+vAhLjFjO
         Ah7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 71dfb90a1353d-544914fe552si334614e0c.5.2025.09.01.03.46.37
        for <kasan-dev@googlegroups.com>;
        Mon, 01 Sep 2025 03:46:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0559116A3;
	Mon,  1 Sep 2025 03:46:29 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 50B573F6A8;
	Mon,  1 Sep 2025 03:46:33 -0700 (PDT)
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
Subject: [PATCH v6 2/2] kasan: apply write-only mode in kasan kunit testcases
Date: Mon,  1 Sep 2025 11:46:23 +0100
Message-Id: <20250901104623.402172-3-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250901104623.402172-1-yeoreum.yun@arm.com>
References: <20250901104623.402172-1-yeoreum.yun@arm.com>
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

When KASAN is configured in write-only mode,
fetch/load operations do not trigger tag check faults.

As a result, the outcome of some test cases may differ
compared to when KASAN is configured without write-only mode.

Therefore, by modifying pre-exist testcases
check the write only makes tag check fault (TCF) where
writing is perform in "allocated memory" but tag is invalid
(i.e) redzone write in atomic_set() testcases.
Otherwise check the invalid fetch/read doesn't generate TCF.

Also, skip some testcases affected by initial value
(i.e) atomic_cmpxchg() testcase maybe successd if
it passes valid atomic_t address and invalid oldaval address.
In this case, if invalid atomic_t doesn't have the same oldval,
it won't trigger write operation so the test will pass.

Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
---
 mm/kasan/kasan_test_c.c | 204 ++++++++++++++++++++++++++--------------
 1 file changed, 135 insertions(+), 69 deletions(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index e0968acc03aa..8b3bb33603e1 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -94,11 +94,13 @@ static void kasan_test_exit(struct kunit *test)
 }
 
 /**
- * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produces a
- * KASAN report; causes a KUnit test failure otherwise.
+ * KUNIT_EXPECT_KASAN_RESULT - check that the executed expression
+ * causes a KUnit test failure when the result is different from @fail.
  *
  * @test: Currently executing KUnit test.
- * @expression: Expression that must produce a KASAN report.
+ * @expr: Expression to be tested.
+ * @expr_str: Expression to be tested encoded as a string.
+ * @fail: Whether expression should produce a KASAN report.
  *
  * For hardware tag-based KASAN, when a synchronous tag fault happens, tag
  * checking is auto-disabled. When this happens, this test handler reenables
@@ -110,25 +112,29 @@ static void kasan_test_exit(struct kunit *test)
  * Use READ/WRITE_ONCE() for the accesses and compiler barriers around the
  * expression to prevent that.
  *
- * In between KUNIT_EXPECT_KASAN_FAIL checks, test_status.report_found is kept
+ * In between KUNIT_EXPECT_KASAN_RESULT checks, test_status.report_found is kept
  * as false. This allows detecting KASAN reports that happen outside of the
  * checks by asserting !test_status.report_found at the start of
- * KUNIT_EXPECT_KASAN_FAIL and in kasan_test_exit.
+ * KUNIT_EXPECT_KASAN_RESULT and in kasan_test_exit.
  */
-#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {			\
+#define KUNIT_EXPECT_KASAN_RESULT(test, expr, expr_str, fail)		\
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
+	if (READ_ONCE(test_status.report_found) != fail) {		\
+		KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN failure"	\
+				"%sexpected in \"" expr_str		\
+				 "\", but %soccurred",			\
+				(fail ? " " : " not "),		\
+				(test_status.report_found ?		\
+				 "" : "none "));			\
 	}								\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&				\
 	    kasan_sync_fault_possible()) {				\
@@ -141,6 +147,34 @@ static void kasan_test_exit(struct kunit *test)
 	WRITE_ONCE(test_status.async_fault, false);			\
 } while (0)
 
+/*
+ * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produces a
+ * KASAN report; causes a KUnit test failure otherwise.
+ *
+ * @test: Currently executing KUnit test.
+ * @expr: Expression that must produce a KASAN report.
+ */
+#define KUNIT_EXPECT_KASAN_FAIL(test, expr)			\
+	KUNIT_EXPECT_KASAN_RESULT(test, expr, #expr, true)
+
+/*
+ * KUNIT_EXPECT_KASAN_FAIL_READ - check that the executed expression
+ * produces a KASAN report when the write-only mode is not enabled;
+ * causes a KUnit test failure otherwise.
+ *
+ * Note: At the moment, this macro does not check whether the produced
+ * KASAN report is a report about a bad read access. It is only intended
+ * for checking the write-only KASAN mode functionality without failing
+ * KASAN tests.
+ *
+ * @test: Currently executing KUnit test.
+ * @expr: Expression that must only produce a KASAN report
+ *        when the write-only mode is not enabled.
+ */
+#define KUNIT_EXPECT_KASAN_FAIL_READ(test, expr)			\
+	KUNIT_EXPECT_KASAN_RESULT(test, expr, #expr,			\
+			!kasan_write_only_enabled())			\
+
 #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {			\
 	if (!IS_ENABLED(config))					\
 		kunit_skip((test), "Test requires " #config "=y");	\
@@ -183,8 +217,8 @@ static void kmalloc_oob_right(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + 5] = 'y');
 
 	/* Out-of-bounds access past the aligned kmalloc object. */
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =
-					ptr[size + KASAN_GRANULE_SIZE + 5]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ptr[0] =
+			ptr[size + KASAN_GRANULE_SIZE + 5]);
 
 	kfree(ptr);
 }
@@ -198,7 +232,7 @@ static void kmalloc_oob_left(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	OPTIMIZER_HIDE_VAR(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, *ptr = *(ptr - 1));
 	kfree(ptr);
 }
 
@@ -211,7 +245,7 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	OPTIMIZER_HIDE_VAR(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ptr[0] = ptr[size]);
 	kfree(ptr);
 }
 
@@ -291,7 +325,7 @@ static void kmalloc_large_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	kfree(ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
 }
 
 static void kmalloc_large_invalid_free(struct kunit *test)
@@ -323,7 +357,7 @@ static void page_alloc_oob_right(struct kunit *test)
 	ptr = page_address(pages);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ptr[0] = ptr[size]);
 	free_pages((unsigned long)ptr, order);
 }
 
@@ -338,7 +372,7 @@ static void page_alloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	free_pages((unsigned long)ptr, order);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
 }
 
 static void krealloc_more_oob_helper(struct kunit *test,
@@ -458,7 +492,7 @@ static void krealloc_uaf(struct kunit *test)
 
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr2 = krealloc(ptr1, size2, GFP_KERNEL));
 	KUNIT_ASSERT_NULL(test, ptr2);
-	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, *(volatile char *)ptr1);
 }
 
 static void kmalloc_oob_16(struct kunit *test)
@@ -501,7 +535,7 @@ static void kmalloc_uaf_16(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 	kfree(ptr2);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, *ptr1 = *ptr2);
 	kfree(ptr1);
 }
 
@@ -640,8 +674,8 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
 	memset((char *)ptr, 0, 64);
 	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(invalid_size);
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test,
+			memmove((char *)ptr, (char *)ptr + 4, invalid_size));
 	kfree(ptr);
 }
 
@@ -654,7 +688,7 @@ static void kmalloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	kfree(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[8]);
 }
 
 static void kmalloc_uaf_memset(struct kunit *test)
@@ -701,7 +735,7 @@ static void kmalloc_uaf2(struct kunit *test)
 		goto again;
 	}
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr1)[40]);
 	KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
 
 	kfree(ptr2);
@@ -727,19 +761,19 @@ static void kmalloc_uaf3(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 	kfree(ptr2);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[8]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr1)[8]);
 }
 
 static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *safe)
 {
 	int *i_unsafe = unsafe;
 
-	KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, READ_ONCE(*i_unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
-	KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, smp_load_acquire(i_unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
 
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, atomic_read(unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
@@ -752,18 +786,31 @@ static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *safe)
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, 42));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42));
+	/*
+	 * The result of the test below may vary due to garbage values of
+	 * unsafe in write-only mode.
+	 * Therefore, skip this test when KASAN is configured in write-only mode.
+	 */
+	if (!kasan_write_only_enabled())
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub_and_test(42, unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_and_test(unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_and_test(unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_negative(42, unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
+	/*
+	 * The result of the test below may vary due to garbage values of
+	 * unsafe in write-only mode.
+	 * Therefore, skip this test when KASAN is configured in write-only mode.
+	 */
+	if (!kasan_write_only_enabled()) {
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
+	}
 
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, atomic_long_read(unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
@@ -776,16 +823,29 @@ static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *safe)
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xchg(unsafe, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_cmpxchg(unsafe, 21, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(unsafe, safe, 42));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsafe, 42));
+	/*
+	 * The result of the test below may vary due to garbage values of
+	 * unsafe in write-only mode.
+	 * Therefore, skip this test when KASAN is configured in write-only mode.
+	 */
+	if (!kasan_write_only_enabled())
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsafe, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub_and_test(42, unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_and_test(unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_and_test(unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_negative(42, unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, 42));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(unsafe));
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe));
+	/*
+	 * The result of the test below may vary due to garbage values of
+	 * unsafe in write-only mode.
+	 * Therefore, skip this test when KASAN is configured in write-only mode.
+	 */
+	if (!kasan_write_only_enabled()) {
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, 42));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe));
+	}
 }
 
 static void kasan_atomics(struct kunit *test)
@@ -842,8 +902,8 @@ static void ksize_unpoisons_memory(struct kunit *test)
 	/* These must trigger a KASAN report. */
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
 		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size + 5]);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[size + 5]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[real_size - 1]);
 
 	kfree(ptr);
 }
@@ -863,8 +923,8 @@ static void ksize_uaf(struct kunit *test)
 
 	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[size]);
 }
 
 /*
@@ -899,9 +959,9 @@ static void rcu_uaf(struct kunit *test)
 	global_rcu_ptr = rcu_dereference_protected(
 				(struct kasan_rcu_info __rcu *)ptr, NULL);
 
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
-		rcu_barrier());
+	KUNIT_EXPECT_KASAN_FAIL_READ(test,
+			call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
+			rcu_barrier());
 }
 
 static void workqueue_uaf_work(struct work_struct *work)
@@ -924,8 +984,8 @@ static void workqueue_uaf(struct kunit *test)
 	queue_work(workqueue, work);
 	destroy_workqueue(workqueue);
 
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		((volatile struct work_struct *)work)->data);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test,
+			((volatile struct work_struct *)work)->data);
 }
 
 static void kfree_via_page(struct kunit *test)
@@ -972,7 +1032,7 @@ static void kmem_cache_oob(struct kunit *test)
 		return;
 	}
 
-	KUNIT_EXPECT_KASAN_FAIL(test, *p = p[size + OOB_TAG_OFF]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, *p = p[size + OOB_TAG_OFF]);
 
 	kmem_cache_free(cache, p);
 	kmem_cache_destroy(cache);
@@ -1068,7 +1128,7 @@ static void kmem_cache_rcu_uaf(struct kunit *test)
 	 */
 	rcu_barrier();
 
-	KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, READ_ONCE(*p));
 
 	kmem_cache_destroy(cache);
 }
@@ -1207,7 +1267,7 @@ static void mempool_oob_right_helper(struct kunit *test, mempool_t *pool, size_t
 		KUNIT_EXPECT_KASAN_FAIL(test,
 			((volatile char *)&elem[size])[0]);
 	else
-		KUNIT_EXPECT_KASAN_FAIL(test,
+		KUNIT_EXPECT_KASAN_FAIL_READ(test,
 			((volatile char *)&elem[round_up(size, KASAN_GRANULE_SIZE)])[0]);
 
 	mempool_free(elem, pool);
@@ -1273,7 +1333,7 @@ static void mempool_uaf_helper(struct kunit *test, mempool_t *pool, bool page)
 	mempool_free(elem, pool);
 
 	ptr = page ? page_address((struct page *)elem) : elem;
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
 }
 
 static void mempool_kmalloc_uaf(struct kunit *test)
@@ -1532,7 +1592,7 @@ static void kasan_memchr(struct kunit *test)
 
 	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
-	KUNIT_EXPECT_KASAN_FAIL(test,
+	KUNIT_EXPECT_KASAN_FAIL_READ(test,
 		kasan_ptr_result = memchr(ptr, '1', size + 1));
 
 	kfree(ptr);
@@ -1559,7 +1619,7 @@ static void kasan_memcmp(struct kunit *test)
 
 	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
-	KUNIT_EXPECT_KASAN_FAIL(test,
+	KUNIT_EXPECT_KASAN_FAIL_READ(test,
 		kasan_int_result = memcmp(ptr, arr, size+1));
 	kfree(ptr);
 }
@@ -1594,7 +1654,7 @@ static void kasan_strings(struct kunit *test)
 			strscpy(ptr, src + 1, KASAN_GRANULE_SIZE));
 
 	/* strscpy should fail if the first byte is unreadable. */
-	KUNIT_EXPECT_KASAN_FAIL(test, strscpy(ptr, src + KASAN_GRANULE_SIZE,
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, strscpy(ptr, src + KASAN_GRANULE_SIZE,
 					      KASAN_GRANULE_SIZE));
 
 	kfree(src);
@@ -1607,17 +1667,17 @@ static void kasan_strings(struct kunit *test)
 	 * will likely point to zeroed byte.
 	 */
 	ptr += 16;
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result = strchr(ptr, '1'));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_ptr_result = strchr(ptr, '1'));
 
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result = strrchr(ptr, '1'));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_ptr_result = strrchr(ptr, '1'));
 
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strcmp(ptr, "2"));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result = strcmp(ptr, "2"));
 
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strncmp(ptr, "2", 1));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result = strncmp(ptr, "2", 1));
 
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strlen(ptr));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result = strlen(ptr));
 
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strnlen(ptr, 1));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result = strnlen(ptr, 1));
 }
 
 static void kasan_bitops_modify(struct kunit *test, int nr, void *addr)
@@ -1636,12 +1696,18 @@ static void kasan_bitops_test_and_modify(struct kunit *test, int nr, void *addr)
 {
 	KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit(nr, addr));
 	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_set_bit(nr, addr));
-	KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
+	/*
+	 * When KASAN is running in write-only mode,
+	 * a fault won't occur when the bit is set.
+	 * Therefore, skip the test_and_set_bit_lock test in write-only mode.
+	 */
+	if (!kasan_write_only_enabled())
+		KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
 	KUNIT_EXPECT_KASAN_FAIL(test, test_and_clear_bit(nr, addr));
 	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_clear_bit(nr, addr));
 	KUNIT_EXPECT_KASAN_FAIL(test, test_and_change_bit(nr, addr));
 	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_change_bit(nr, addr));
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = test_bit(nr, addr));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result = test_bit(nr, addr));
 	if (nr < 7)
 		KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =
 				xor_unlock_is_negative_byte(1 << nr, addr));
@@ -1765,7 +1831,7 @@ static void vmalloc_oob(struct kunit *test)
 		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size]);
 
 	/* An aligned access into the first out-of-bounds granule. */
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size + 5]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)v_ptr)[size + 5]);
 
 	/* Check that in-bounds accesses to the physical page are valid. */
 	page = vmalloc_to_page(v_ptr);
@@ -2042,15 +2108,15 @@ static void copy_user_test_oob(struct kunit *test)
 
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		unused = copy_from_user(kmem, usermem, size + 1));
-	KUNIT_EXPECT_KASAN_FAIL(test,
+	KUNIT_EXPECT_KASAN_FAIL_READ(test,
 		unused = copy_to_user(usermem, kmem, size + 1));
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		unused = __copy_from_user(kmem, usermem, size + 1));
-	KUNIT_EXPECT_KASAN_FAIL(test,
+	KUNIT_EXPECT_KASAN_FAIL_READ(test,
 		unused = __copy_to_user(usermem, kmem, size + 1));
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		unused = __copy_from_user_inatomic(kmem, usermem, size + 1));
-	KUNIT_EXPECT_KASAN_FAIL(test,
+	KUNIT_EXPECT_KASAN_FAIL_READ(test,
 		unused = __copy_to_user_inatomic(usermem, kmem, size + 1));
 
 	/*
-- 
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901104623.402172-3-yeoreum.yun%40arm.com.
