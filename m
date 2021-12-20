Return-Path: <kasan-dev+bncBAABBO73QOHAMGQEREBJYZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id C25F447B5B9
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:03:39 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id r7-20020adfbb07000000b001a254645f13sf3893824wrg.7
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:03:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037819; cv=pass;
        d=google.com; s=arc-20160816;
        b=K3OMjn/MW8Pi0/WkqRY5O30/DH6lUXADRW62XZIHlF11MimlwP7+jr6bD1AfZxLx3f
         vT9YDkP2WIVppy0t2LUatUonvKC4fL0odLXyMSdOgu70sFTroVhujNwHfkwXCM5LueEf
         VPHTpR6xUJQpgBdCTcCQaSgQtGLxrZaqh0aFvDuLBSv0BP8XcJLWDgFjXFl/rSODy7pv
         piDbhG52gDgG0s3PbGkQUL+5XBcAD982CxHXuwdwX6meQmIh2d1PwpFjuhIz3MFwYmIz
         3qfgD4Rza5hwi//T0RkOKvBV1saCa8mTPnN0h1hx6u+o8dbAsfBkOSRLpeSd6CqR+RwR
         7xPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Mqf71u2dFobABw3lFhMAH25tpfBCIyHVszHAksKhSyk=;
        b=yzEolG1wtXrtDsIYXg7HwmfLTWQ+xFyDGSTL/7OPKg+Mr2E1yLx3dLoYACCGR0TdYg
         EiBvJvMRy1Rr2hKNOaMoa0xb5znPwdqpKY5c7Xo0ZCia96r/SmDKwpzTuAHdMLjL0Y2t
         OuxQXFn1fvZytNq/g2funs3ll4ZDC+m34vC6x/eNl1RKO9racTTVz1+JYPkR1L87yEVd
         cjlEpahH8xWS5v0P33QASJEZrFid3vxazN0GxFybTMUdqOzLAmwKkqrwDryjLr88QXZN
         z3aqAih6upIYa7q5oDf8idxsrqEltOy5oW5n0f4NLjr92oFQPY14zErqZrvH7CdQYzDm
         fBmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CYE0KUzV;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Mqf71u2dFobABw3lFhMAH25tpfBCIyHVszHAksKhSyk=;
        b=Mfm0fuzzRj1wU+tmtkJ3GqnaZY2Gh9C0up9ZxWIrePrlNvnJBFX045i+OeTNdfrNkw
         gcqABYtUgnXFn2Ig4r08cthqLGc03jQd/Kib/QOeJsYh3j6GvGYqYCWz3vXcETpPrPfk
         VRpvDYpgzx6+2o5PpSvWmn8vbGkW3stJC2j/FQyrrabiiGqWGQjcsDqi/NZJPANOhzoF
         HoJw/sFa82VT2iweE941dqIU3daZKuaowFySEsWe1mHOWFeF6cVx5AjTveA+g6VTqp5o
         PFKCQD3D1KsxpdjGcFCHvyuIlZ3ksJma/um9ZjXBdiK/hW35tY8PO3H9MymYijHVNZec
         560A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Mqf71u2dFobABw3lFhMAH25tpfBCIyHVszHAksKhSyk=;
        b=BIXxRb6oBQXjcjTHfi8779fflHa8BWV6sOtCnwMIv3YbZw12D216X1LLoRfsCK6ete
         eTsd/Wv5jHeQUaWQiizVJ2dXnLdTEuMTPcAHWtbqdTP0tR4wHUkwyhse917rYUnDzkDs
         SEgAjKVjuCurs2xAPKteS+ppgoyr4xQECq6tzcz+qeh0dylEAk3i5zHLLyslFJQK4FnS
         8AcI1139A4SgwUUs+V/RSDYHT3llLpF2qLnJwgLdeARdFQjgjvhElghygnXp9M9xz95m
         kLMTHrxiFEFmNOIiBObfPUY7rioX1MhkYjVdTp6m1dg5T6YlR9qmSm1k9D66UjUYfA/H
         0DgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532s8J3OVnmRE7Jln/E3HvBm6opcGOHVp6e+wQgJX/qIeDsN8cZ4
	naoDVdu20lGfRUzNTkP9dBY=
X-Google-Smtp-Source: ABdhPJyreGg+Yw6mhB2aIKOVQLdDQkFn7ys3nLZZuBQJve9wRYwclyCVGOd2qYWK6tnxRMUg8kSt5Q==
X-Received: by 2002:a05:6000:1c7:: with SMTP id t7mr115379wrx.656.1640037819514;
        Mon, 20 Dec 2021 14:03:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d21b:: with SMTP id j27ls6393239wrh.3.gmail; Mon, 20 Dec
 2021 14:03:38 -0800 (PST)
X-Received: by 2002:a5d:6488:: with SMTP id o8mr115375wri.630.1640037818928;
        Mon, 20 Dec 2021 14:03:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037818; cv=none;
        d=google.com; s=arc-20160816;
        b=OFrsAEvRU0Oxh45euM8a2iEKdR6pRQ33PKsKVJ9iWCWSO0prTqirHGG/KGg8UhLI3C
         Ie06v3jpWb6oBC/1h11njz4KEDUEDh8+OnZt3Bk7WZv7uTlDAZ9eNHc1r1kZPSyqaw59
         1xsXiQeNAJHey8yXIbKGDM5sBc4+3wlpivTvoRm06zwmyLOvz0+XaFA7vHtdY0WAioIs
         I476vzKzQXFNxtDrhz9Cqhqs8vlOHp9NMEfw/dVmgDK4l9Bmz2QGedDN4O8zrw8O34UG
         ygcImySyudYfJ/77cIB3708k0IPZ3aSGiIoYDUijIDkLD49IxhVe6y2TxGHJB4R8Pxh5
         cMvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=boV4BKjs1buZcE6U9f3+9ZNSDpvsszrp49sK5MVcXV4=;
        b=I1O5SiK3oj0zLVP0cqD0wLnEIciQcSqj5N+BW5VYKMR24uu76EmjfRMtf+VrcscpVO
         xEbc8Ejaign5aLFCfdyYhzXx1q66OHtxQmyCJfUG21Y1pCxeMfDOl/caahSBoOU8gjNG
         U3lyo2rjVbU3E49NRR7/5/okqJjlHLy4UegL3lPXOvfGLGxyVBwqN6AKbNQaZvpzf/ZU
         wAKscsGrsVWNMoq+jNSMDPJeB0UnkK+sba7sTv+qnsQ/bCftcJJ4WQiWeTjk+nv/U0lF
         bAUe0TR5LLWp316MewVLUG85WkVz+zlC14/p/NK12/N9gwFP4dac3cbCgNvetvhirfgF
         s3aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=CYE0KUzV;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id p22si49455wms.1.2021.12.20.14.03.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:03:38 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v4 39/39] kasan: improve vmalloc tests
Date: Mon, 20 Dec 2021 23:03:33 +0100
Message-Id: <b1652fc2a60d2f7d80b8e585575bc4f5a755b83c.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=CYE0KUzV;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Update the existing vmalloc_oob() test to account for the specifics
of the tag-based modes. Also add a few new checks and comments.

Add new vmalloc-related tests:

- vmalloc_helpers_tags() to check that exported vmalloc helpers can
  handle tagged pointers.
- vmap_tags() to check that SW_TAGS mode properly tags vmap() mappings.
- vm_map_ram_tags() to check that SW_TAGS mode properly tags
  vm_map_ram() mappings.
- vmalloc_percpu() to check that SW_TAGS mode tags regions allocated
  for __alloc_percpu(). The tagging of per-cpu mappings is best-effort;
  proper tagging is tracked in [1].

[1] https://bugzilla.kernel.org/show_bug.cgi?id=215019

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 189 +++++++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 183 insertions(+), 6 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 847cdbefab46..ae7b2e703f1b 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -19,6 +19,7 @@
 #include <linux/uaccess.h>
 #include <linux/io.h>
 #include <linux/vmalloc.h>
+#include <linux/set_memory.h>
 
 #include <asm/page.h>
 
@@ -1049,21 +1050,181 @@ static void kmalloc_double_kzfree(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, kfree_sensitive(ptr));
 }
 
+static void vmalloc_helpers_tags(struct kunit *test)
+{
+	void *ptr;
+	int rv;
+
+	/* This test is intended for tag-based modes. */
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
+
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
+
+	ptr = vmalloc(PAGE_SIZE);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	/* Check that the returned pointer is tagged. */
+	KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
+	KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
+
+	/* Make sure exported vmalloc helpers handle tagged pointers. */
+	KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
+
+	/* Make sure vmalloc'ed memory permissions can be changed. */
+	rv = set_memory_ro((unsigned long)ptr, 1);
+	KUNIT_ASSERT_GE(test, rv, 0);
+	rv = set_memory_rw((unsigned long)ptr, 1);
+	KUNIT_ASSERT_GE(test, rv, 0);
+
+	vfree(ptr);
+}
+
 static void vmalloc_oob(struct kunit *test)
 {
-	void *area;
+	char *v_ptr, *p_ptr;
+	struct page *page;
+	size_t size = PAGE_SIZE / 2 - KASAN_GRANULE_SIZE - 5;
 
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
 
+	v_ptr = vmalloc(size);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
+
 	/*
-	 * We have to be careful not to hit the guard page.
+	 * We have to be careful not to hit the guard page in vmalloc tests.
 	 * The MMU will catch that and crash us.
 	 */
-	area = vmalloc(3000);
-	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, area);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)area)[3100]);
-	vfree(area);
+	/* Make sure in-bounds accesses are valid. */
+	v_ptr[0] = 0;
+	v_ptr[size - 1] = 0;
+
+	/*
+	 * An unaligned access past the requested vmalloc size.
+	 * Only generic KASAN can precisely detect these.
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size]);
+
+	/* An aligned access into the first out-of-bounds granule. */
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size + 5]);
+
+	/* Check that in-bounds accesses to the physical page are valid. */
+	page = vmalloc_to_page(v_ptr);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, page);
+	p_ptr = page_address(page);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, p_ptr);
+	p_ptr[0] = 0;
+
+	vfree(v_ptr);
+
+	/*
+	 * We can't check for use-after-unmap bugs in this nor in the following
+	 * vmalloc tests, as the page might be fully unmapped and accessing it
+	 * will crash the kernel.
+	 */
+}
+
+static void vmap_tags(struct kunit *test)
+{
+	char *p_ptr, *v_ptr;
+	struct page *p_page, *v_page;
+	size_t order = 1;
+
+	/*
+	 * This test is specifically crafted for the software tag-based mode,
+	 * the only tag-based mode that poisons vmap mappings.
+	 */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_SW_TAGS);
+
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
+
+	p_page = alloc_pages(GFP_KERNEL, order);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, p_page);
+	p_ptr = page_address(p_page);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, p_ptr);
+
+	v_ptr = vmap(&p_page, 1 << order, VM_MAP, PAGE_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
+
+	/*
+	 * We can't check for out-of-bounds bugs in this nor in the following
+	 * vmalloc tests, as allocations have page granularity and accessing
+	 * the guard page will crash the kernel.
+	 */
+
+	KUNIT_EXPECT_GE(test, (u8)get_tag(v_ptr), (u8)KASAN_TAG_MIN);
+	KUNIT_EXPECT_LT(test, (u8)get_tag(v_ptr), (u8)KASAN_TAG_KERNEL);
+
+	/* Make sure that in-bounds accesses through both pointers work. */
+	*p_ptr = 0;
+	*v_ptr = 0;
+
+	/* Make sure vmalloc_to_page() correctly recovers the page pointer. */
+	v_page = vmalloc_to_page(v_ptr);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_page);
+	KUNIT_EXPECT_PTR_EQ(test, p_page, v_page);
+
+	vunmap(v_ptr);
+	free_pages((unsigned long)p_ptr, order);
+}
+
+static void vm_map_ram_tags(struct kunit *test)
+{
+	char *p_ptr, *v_ptr;
+	struct page *page;
+	size_t order = 1;
+
+	/*
+	 * This test is specifically crafted for the software tag-based mode,
+	 * the only tag-based mode that poisons vm_map_ram mappings.
+	 */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_SW_TAGS);
+
+	page = alloc_pages(GFP_KERNEL, order);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, page);
+	p_ptr = page_address(page);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, p_ptr);
+
+	v_ptr = vm_map_ram(&page, 1 << order, -1);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
+
+	KUNIT_EXPECT_GE(test, (u8)get_tag(v_ptr), (u8)KASAN_TAG_MIN);
+	KUNIT_EXPECT_LT(test, (u8)get_tag(v_ptr), (u8)KASAN_TAG_KERNEL);
+
+	/* Make sure that in-bounds accesses through both pointers work. */
+	*p_ptr = 0;
+	*v_ptr = 0;
+
+	vm_unmap_ram(v_ptr, 1 << order);
+	free_pages((unsigned long)p_ptr, order);
+}
+
+static void vmalloc_percpu(struct kunit *test)
+{
+	char __percpu *ptr;
+	int cpu;
+
+	/*
+	 * This test is specifically crafted for the software tag-based mode,
+	 * the only tag-based mode that poisons percpu mappings.
+	 */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_SW_TAGS);
+
+	ptr = __alloc_percpu(PAGE_SIZE, PAGE_SIZE);
+
+	for_each_possible_cpu(cpu) {
+		char *c_ptr = per_cpu_ptr(ptr, cpu);
+
+		KUNIT_EXPECT_GE(test, (u8)get_tag(c_ptr), (u8)KASAN_TAG_MIN);
+		KUNIT_EXPECT_LT(test, (u8)get_tag(c_ptr), (u8)KASAN_TAG_KERNEL);
+
+		/* Make sure that in-bounds accesses don't crash the kernel. */
+		*c_ptr = 0;
+	}
+
+	free_percpu(ptr);
 }
 
 /*
@@ -1097,6 +1258,18 @@ static void match_all_not_assigned(struct kunit *test)
 		KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
 		free_pages((unsigned long)ptr, order);
 	}
+
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		return;
+
+	for (i = 0; i < 256; i++) {
+		size = (get_random_int() % 1024) + 1;
+		ptr = vmalloc(size);
+		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+		KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
+		KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
+		vfree(ptr);
+	}
 }
 
 /* Check that 0xff works as a match-all pointer tag for tag-based modes. */
@@ -1202,7 +1375,11 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kasan_bitops_generic),
 	KUNIT_CASE(kasan_bitops_tags),
 	KUNIT_CASE(kmalloc_double_kzfree),
+	KUNIT_CASE(vmalloc_helpers_tags),
 	KUNIT_CASE(vmalloc_oob),
+	KUNIT_CASE(vmap_tags),
+	KUNIT_CASE(vm_map_ram_tags),
+	KUNIT_CASE(vmalloc_percpu),
 	KUNIT_CASE(match_all_not_assigned),
 	KUNIT_CASE(match_all_ptr_tag),
 	KUNIT_CASE(match_all_mem_tag),
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b1652fc2a60d2f7d80b8e585575bc4f5a755b83c.1640036051.git.andreyknvl%40google.com.
