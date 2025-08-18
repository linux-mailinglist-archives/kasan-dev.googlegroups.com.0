Return-Path: <kasan-dev+bncBCD6ROMWZ4CBB3FWRPCQMGQE3QALRSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 65B8DB29B40
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 09:51:10 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-70a9f55836dsf95703036d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 00:51:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755503469; cv=pass;
        d=google.com; s=arc-20240605;
        b=iNV8tK0P9Xy2ELMySXNhU8UEBUAxdkAQimID4Z4ePRJpIL38/P9N8/J1FnloN2Gh7z
         c5CEbiYveSMVRdxd99sx2N6uNmJGGcU2rQVmTFcDgvPiodjB6DgBc/qwMqn1y8rB83bu
         lPjEWY477LLD9RPwn8SjCSgvLy9wiOFf3Zj7SIScP2hNTYWsLK5GM+a+TMN5togxkViW
         QEmcEBgeBerdOMGAWoyRqzlERJbUcksVdj92PyWbfyiyyZfvc7orWX0SN3dbbYiZ+s45
         /vgIylBOHSzGBZPoVCt4K9TGVhDvBhzv0gadXdw0ktXzfexDFRIsxtOne31lrzwpn6rF
         w22g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GLNBr5qJRtBOQILbJ3kL9wpUpo44K5aDCdwryUfw9Rc=;
        fh=QJ/Y1SF+Av9XreSlLk4nUndHa6msntl7TBbOkHCVSs0=;
        b=LhqFqqb+0BVp7ALd3bJ5YhtTw7Qh9XHrSwlyXVdFqIFvLfVfUzDFGWo4TmUs4FOpQ+
         6SwKdcfczDWH7cqlneQasdpPFTsXRqXozG+53Ef/JcJP280QhKqehT7vlYD0Fe9B+e4m
         /5zSIO2N/pPkq61LnBT7xdTplK8Jce6EuTr5jM0sA/SZsNoRt60Ul5sW2znRQdS98cAQ
         Pl708GUr5No2YTBRYr0pMWmeVmrWp1NmQQtS8CCI5YxmgzwrRfsgo1TnYvb545FtLOop
         z0izjL+YmE0s1zReJkxO4Fsf9SrJa4lNgodIHQDXArT/YVWXl6gGHcmyvMQTLIcuRCaJ
         deFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755503469; x=1756108269; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GLNBr5qJRtBOQILbJ3kL9wpUpo44K5aDCdwryUfw9Rc=;
        b=d76nxymIIt0Hk0U06PF3zSTqZKRO9bUlh2nhxmvxjHQN/LiEjF85ZzE9s5aNouQQig
         MIqA9k+8jd1ozhSRDRXqEhP8FdCs+5a2kG0eToQC6k8lSow9ttwVOze6Rhv+9QKtve5D
         9OQLpkEceNnvxvQbUxwObczWo7Ta9u/yWICV6FsqErEmTpWh55qX1Uq4gsM4qhplXf5r
         S1DFkPn0WEXIIjIQ3D0DlxW8Np48Gf7KCYOZAVBU/RW1psO578IEm/eRJisWsY7Olbau
         KmEuz1LSxd6QuGZLvDd+bmxlz11gFTNHo5Kr2h9hTruE3HrJx4gxF8mK7+mmNXvnpcr2
         d74A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755503469; x=1756108269;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GLNBr5qJRtBOQILbJ3kL9wpUpo44K5aDCdwryUfw9Rc=;
        b=nWkwbSeMkKHCgnEZqcTuG3YstCQ1qgwU7Tv/M1YYLjUn7GAUWS0h4pEm5W4iKUdLeL
         TITmoA9CD6f+EXyEHlkMfienWuSHPa1RrhfY+e+4ZOD/Iv1u8TOLUHh+GIHx3Z68s+xP
         pHVnBWc4lUDVY4zos2MomPatlYWXyZuvp4F13V48tingDHAYecTPRhOYb3BI3/4pUiNf
         7S7Dbdmkea/VfpL0iu+Ro0fK+F2ti6Yrn3DAW8N0CuLqRYllO0t8yMXiTWum1tt/Z7Ab
         z/OfGzbIVVHsIVrrNWt3epDcoPDI5UeTZMWu2PhvNoilyjCBJOaPRoC0HjJjgO3byZL+
         kBiA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWEEQ1Q/MeWzcMj5eN9/hNeBSRXwzbwEJPNYhEdAJe3G76wFqSXN7qkZvDoeQPP7yPdPKk5ow==@lfdr.de
X-Gm-Message-State: AOJu0YxRUNl4dVdhhxGbM8K3lo7baIRuYSWi3z3VjtQM9rBUZjJJBLpp
	aA8nmaerIkOo/+3JX8VIJfqo79f3pYbMsBFyWYhctjt+PaSvthQ5KvFC
X-Google-Smtp-Source: AGHT+IEZ83HE30nqYrODIgSjU2SO5WJY2dxzBRzd60vqhViEhKIB7QnU39zO6yb+vRzx4Qx/Xy3aVg==
X-Received: by 2002:a05:6214:5004:b0:709:b911:5f9a with SMTP id 6a1803df08f44-70ba7ae80a0mr131711606d6.15.1755503468878;
        Mon, 18 Aug 2025 00:51:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdtegBxNEhcSpFcsh3gon8wnLGVyZbVMxDDpq1kG+JpKQ==
Received: by 2002:a05:6214:cc7:b0:6fa:fb65:95dc with SMTP id
 6a1803df08f44-70aafed50dbls55500916d6.1.-pod-prod-01-us; Mon, 18 Aug 2025
 00:51:08 -0700 (PDT)
X-Received: by 2002:a05:6214:246c:b0:709:9e64:93f5 with SMTP id 6a1803df08f44-70ba7c4f30emr130321306d6.41.1755503468085;
        Mon, 18 Aug 2025 00:51:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755503468; cv=none;
        d=google.com; s=arc-20240605;
        b=gmKP4hpve1vMYPwijwj48WCpqwwoVR1sxkaFEGJKYPpDbTHjE9ydOm987GWCyyhQW3
         NI2jFiKLHmwLycXjXQT52syO0iWgxXPR+54OFieo11RU+w5yqvNMt7Py1xj2E4G/vMSc
         VIsJm9m7A0NZ4eNr2m/BvcLicleJ5SSSdXhq6ZE27aiXdOv238fyBJA2W295x65chxgN
         UTZoQjibLMN/dA/68pff8/kg685+wypjnngTmCPDxvJ2f7x7xZCLG5vpX4gq3kt6lq8l
         TElAS7/895C1mdS3okni+zNSKNGd8Zg11Dh6++CedIkjv2KAJyAAuxjbnXsHyO6X8vjV
         Op0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=j9shQaZ35zLMryE0mP38Mqas2Io/Kf9CKdT3bcY1eCo=;
        fh=sO9hEm1jMmDS9TNxUqxXxXlVQts1wG4o/F/u/UhyUv4=;
        b=MYkFIljmTvveYREKTZ1YYkwwYOK56FkxyjUbuTJWHBS11vLw3VtgfIwepwENTBVvNV
         Doe9sbdE3ltBJmHwe1s22FK7Rnba7A7dMKVShH7Ie8HesKleig01XF4HMe43Dobqu/Ms
         8eNyEMNTCtzPakQoxZROzsZJGEfPum+tgFi5L7hMnyoPfQHQbUJxPogrOrlcRzPpFKYk
         CVQ5b9ueEsfbMoD6NFM8OaFNbro21x7H+QRyznkPcG9ndEfOVDQiJ73OsCEjUqE6nudj
         kN6Rj2hlZclEQLjANNGZZMTfcMPQjha9Tt4AmKLHflTZbA8snPRFbvd0Oiai/9JOYHDY
         /n7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=yeoreum.yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 6a1803df08f44-70ba8a8ce87si2903126d6.0.2025.08.18.00.51.08
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Aug 2025 00:51:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 267391762;
	Mon, 18 Aug 2025 00:50:59 -0700 (PDT)
Received: from e129823.cambridge.arm.com (e129823.arm.com [10.1.197.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 504E03F58B;
	Mon, 18 Aug 2025 00:51:03 -0700 (PDT)
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
Subject: [PATCH v4 2/2] kasan: apply write-only mode in kasan kunit testcases
Date: Mon, 18 Aug 2025 08:50:51 +0100
Message-Id: <20250818075051.996764-3-yeoreum.yun@arm.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250818075051.996764-1-yeoreum.yun@arm.com>
References: <20250818075051.996764-1-yeoreum.yun@arm.com>
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
 mm/kasan/kasan_test_c.c | 237 +++++++++++++++++++++++++++-------------
 1 file changed, 162 insertions(+), 75 deletions(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index e0968acc03aa..cc0730aa18d1 100644
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
@@ -141,6 +147,29 @@ static void kasan_test_exit(struct kunit *test)
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
+ * KUNIT_EXPECT_KASAN_FAIL_READ - check that the executed expression produces
+ * a KASAN report for read access.
+ * It causes a KUnit test failure. if KASAN report isn't produced for read access.
+ * For write access, it cause a KUnit test failure if a KASAN report is produced
+ *
+ * @test: Currently executing KUnit test.
+ * @expr: Expression doesn't produce a KASAN report.
+ */
+#define KUNIT_EXPECT_KASAN_FAIL_READ(test, expr)			\
+	_KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, #expr,			\
+			!kasan_write_only_enabled())			\
+
 #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {			\
 	if (!IS_ENABLED(config))					\
 		kunit_skip((test), "Test requires " #config "=y");	\
@@ -183,8 +212,8 @@ static void kmalloc_oob_right(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + 5] = 'y');
 
 	/* Out-of-bounds access past the aligned kmalloc object. */
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =
-					ptr[size + KASAN_GRANULE_SIZE + 5]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ptr[0] =
+			ptr[size + KASAN_GRANULE_SIZE + 5]);
 
 	kfree(ptr);
 }
@@ -198,7 +227,8 @@ static void kmalloc_oob_left(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	OPTIMIZER_HIDE_VAR(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, *ptr = *(ptr - 1));
+
 	kfree(ptr);
 }
 
@@ -211,7 +241,8 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	OPTIMIZER_HIDE_VAR(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ptr[0] = ptr[size]);
+
 	kfree(ptr);
 }
 
@@ -291,7 +322,7 @@ static void kmalloc_large_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	kfree(ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
 }
 
 static void kmalloc_large_invalid_free(struct kunit *test)
@@ -323,7 +354,8 @@ static void page_alloc_oob_right(struct kunit *test)
 	ptr = page_address(pages);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ptr[0] = ptr[size]);
+
 	free_pages((unsigned long)ptr, order);
 }
 
@@ -338,7 +370,7 @@ static void page_alloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	free_pages((unsigned long)ptr, order);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
 }
 
 static void krealloc_more_oob_helper(struct kunit *test,
@@ -455,10 +487,10 @@ static void krealloc_uaf(struct kunit *test)
 	ptr1 = kmalloc(size1, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
 	kfree(ptr1);
-
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr2 = krealloc(ptr1, size2, GFP_KERNEL));
 	KUNIT_ASSERT_NULL(test, ptr2);
-	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
+
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, *(volatile char *)ptr1);
 }
 
 static void kmalloc_oob_16(struct kunit *test)
@@ -501,7 +533,8 @@ static void kmalloc_uaf_16(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 	kfree(ptr2);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, *ptr1 = *ptr2);
+
 	kfree(ptr1);
 }
 
@@ -640,8 +673,10 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
 	memset((char *)ptr, 0, 64);
 	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(invalid_size);
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
+
+	KUNIT_EXPECT_KASAN_FAIL_READ(test,
+			memmove((char *)ptr, (char *)ptr + 4, invalid_size));
+
 	kfree(ptr);
 }
 
@@ -654,7 +689,8 @@ static void kmalloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	kfree(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
+
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[8]);
 }
 
 static void kmalloc_uaf_memset(struct kunit *test)
@@ -701,7 +737,8 @@ static void kmalloc_uaf2(struct kunit *test)
 		goto again;
 	}
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr1)[40]);
+
 	KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
 
 	kfree(ptr2);
@@ -727,19 +764,19 @@ static void kmalloc_uaf3(struct kunit *test)
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
+
 	KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
-	KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, smp_load_acquire(i_unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, atomic_read(unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
@@ -752,18 +789,35 @@ static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *safe)
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
+	if (!kasan_write_only_enabled())
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
+	if (!kasan_write_only_enabled()) {
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
+	}
+
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, atomic_long_read(unsafe));
+
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
 	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
@@ -776,16 +830,32 @@ static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *safe)
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
+	if (!kasan_write_only_enabled())
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
+	if (!kasan_write_only_enabled()) {
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, 42));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(unsafe));
+		KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe));
+	}
 }
 
 static void kasan_atomics(struct kunit *test)
@@ -842,8 +912,9 @@ static void ksize_unpoisons_memory(struct kunit *test)
 	/* These must trigger a KASAN report. */
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
 		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size + 5]);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);
+
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[size + 5]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[real_size - 1]);
 
 	kfree(ptr);
 }
@@ -863,8 +934,8 @@ static void ksize_uaf(struct kunit *test)
 
 	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[size]);
 }
 
 /*
@@ -886,6 +957,7 @@ static void rcu_uaf_reclaim(struct rcu_head *rp)
 		container_of(rp, struct kasan_rcu_info, rcu);
 
 	kfree(fp);
+
 	((volatile struct kasan_rcu_info *)fp)->i;
 }
 
@@ -899,9 +971,9 @@ static void rcu_uaf(struct kunit *test)
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
@@ -924,8 +996,8 @@ static void workqueue_uaf(struct kunit *test)
 	queue_work(workqueue, work);
 	destroy_workqueue(workqueue);
 
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		((volatile struct work_struct *)work)->data);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test,
+			((volatile struct work_struct *)work)->data);
 }
 
 static void kfree_via_page(struct kunit *test)
@@ -972,7 +1044,7 @@ static void kmem_cache_oob(struct kunit *test)
 		return;
 	}
 
-	KUNIT_EXPECT_KASAN_FAIL(test, *p = p[size + OOB_TAG_OFF]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, *p = p[size + OOB_TAG_OFF]);
 
 	kmem_cache_free(cache, p);
 	kmem_cache_destroy(cache);
@@ -1068,7 +1140,7 @@ static void kmem_cache_rcu_uaf(struct kunit *test)
 	 */
 	rcu_barrier();
 
-	KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, READ_ONCE(*p));
 
 	kmem_cache_destroy(cache);
 }
@@ -1207,7 +1279,7 @@ static void mempool_oob_right_helper(struct kunit *test, mempool_t *pool, size_t
 		KUNIT_EXPECT_KASAN_FAIL(test,
 			((volatile char *)&elem[size])[0]);
 	else
-		KUNIT_EXPECT_KASAN_FAIL(test,
+		KUNIT_EXPECT_KASAN_FAIL_READ(test,
 			((volatile char *)&elem[round_up(size, KASAN_GRANULE_SIZE)])[0]);
 
 	mempool_free(elem, pool);
@@ -1273,7 +1345,8 @@ static void mempool_uaf_helper(struct kunit *test, mempool_t *pool, bool page)
 	mempool_free(elem, pool);
 
 	ptr = page ? page_address((struct page *)elem) : elem;
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
 }
 
 static void mempool_kmalloc_uaf(struct kunit *test)
@@ -1532,7 +1605,8 @@ static void kasan_memchr(struct kunit *test)
 
 	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
-	KUNIT_EXPECT_KASAN_FAIL(test,
+
+	KUNIT_EXPECT_KASAN_FAIL_READ(test,
 		kasan_ptr_result = memchr(ptr, '1', size + 1));
 
 	kfree(ptr);
@@ -1559,8 +1633,10 @@ static void kasan_memcmp(struct kunit *test)
 
 	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
-	KUNIT_EXPECT_KASAN_FAIL(test,
+
+	KUNIT_EXPECT_KASAN_FAIL_READ(test,
 		kasan_int_result = memcmp(ptr, arr, size+1));
+
 	kfree(ptr);
 }
 
@@ -1594,7 +1670,7 @@ static void kasan_strings(struct kunit *test)
 			strscpy(ptr, src + 1, KASAN_GRANULE_SIZE));
 
 	/* strscpy should fail if the first byte is unreadable. */
-	KUNIT_EXPECT_KASAN_FAIL(test, strscpy(ptr, src + KASAN_GRANULE_SIZE,
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, strscpy(ptr, src + KASAN_GRANULE_SIZE,
 					      KASAN_GRANULE_SIZE));
 
 	kfree(src);
@@ -1607,17 +1683,13 @@ static void kasan_strings(struct kunit *test)
 	 * will likely point to zeroed byte.
 	 */
 	ptr += 16;
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result = strchr(ptr, '1'));
 
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result = strrchr(ptr, '1'));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strcmp(ptr, "2"));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strncmp(ptr, "2", 1));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strlen(ptr));
-
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strnlen(ptr, 1));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_ptr_result = strchr(ptr, '1'));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_ptr_result = strrchr(ptr, '1'));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result = strcmp(ptr, "2"));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result = strncmp(ptr, "2", 1));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result = strlen(ptr));
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result = strnlen(ptr, 1));
 }
 
 static void kasan_bitops_modify(struct kunit *test, int nr, void *addr)
@@ -1636,12 +1708,22 @@ static void kasan_bitops_test_and_modify(struct kunit *test, int nr, void *addr)
 {
 	KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit(nr, addr));
 	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_set_bit(nr, addr));
-	KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
+
+	/*
+	 * When KASAN is running in store-only mode,
+	 * a fault won't occur when the bit is set.
+	 * Therefore, skip the test_and_set_bit_lock test in store-only mode.
+	 */
+	if (!kasan_write_only_enabled())
+		KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
+
 	KUNIT_EXPECT_KASAN_FAIL(test, test_and_clear_bit(nr, addr));
 	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_clear_bit(nr, addr));
 	KUNIT_EXPECT_KASAN_FAIL(test, test_and_change_bit(nr, addr));
 	KUNIT_EXPECT_KASAN_FAIL(test, __test_and_change_bit(nr, addr));
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = test_bit(nr, addr));
+
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, kasan_int_result = test_bit(nr, addr));
+
 	if (nr < 7)
 		KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =
 				xor_unlock_is_negative_byte(1 << nr, addr));
@@ -1765,7 +1847,7 @@ static void vmalloc_oob(struct kunit *test)
 		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size]);
 
 	/* An aligned access into the first out-of-bounds granule. */
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size + 5]);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)v_ptr)[size + 5]);
 
 	/* Check that in-bounds accesses to the physical page are valid. */
 	page = vmalloc_to_page(v_ptr);
@@ -2042,15 +2124,20 @@ static void copy_user_test_oob(struct kunit *test)
 
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		unused = copy_from_user(kmem, usermem, size + 1));
-	KUNIT_EXPECT_KASAN_FAIL(test,
+
+	KUNIT_EXPECT_KASAN_FAIL_READ(test,
 		unused = copy_to_user(usermem, kmem, size + 1));
+
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		unused = __copy_from_user(kmem, usermem, size + 1));
-	KUNIT_EXPECT_KASAN_FAIL(test,
+
+	KUNIT_EXPECT_KASAN_FAIL_READ(test,
 		unused = __copy_to_user(usermem, kmem, size + 1));
+
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		unused = __copy_from_user_inatomic(kmem, usermem, size + 1));
-	KUNIT_EXPECT_KASAN_FAIL(test,
+
+	KUNIT_EXPECT_KASAN_FAIL_READ(test,
 		unused = __copy_to_user_inatomic(usermem, kmem, size + 1));
 
 	/*
-- 
LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250818075051.996764-3-yeoreum.yun%40arm.com.
