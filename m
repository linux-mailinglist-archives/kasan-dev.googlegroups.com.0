Return-Path: <kasan-dev+bncBAABB2UJXKGQMGQE32D5REI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id A8BA546AAE3
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:47:22 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 69-20020a1c0148000000b0033214e5b021sf6725089wmb.3
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:47:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827242; cv=pass;
        d=google.com; s=arc-20160816;
        b=utXiAo9Y9coTgVRuw954ePzWyhfIei2vCxznCjp2kZq6MFw6JcG+unniS8bYKltXf1
         jrLvJHaGruyj+UoPSLMMRC0odjLHacZKAwZRd/5CB48/aeJeZj+NrIoqkE4wjaacH/WY
         eRa6MHsi5414Kh5wudIjou8Dg/61jFtVeUwTmBZmU80zDZP2QOAoUM16fqFFo23Ey4fD
         sayz5CbO+LGQyDyYz9vAE5t9fGRUYMGCu/QUTjSZmyc4UVobxpcAhv9MbZQljZWWPXk6
         0QHq2/f8G6bBIQIqN8g3oBkyXzYsvInL69ZCAMgeQhM4hqU8b5hJzuvMbC3WfbmJLdUg
         ecvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kX6Ai3omqBp+X1wVIxMWWute7y5cItgxKyDWQJTpv64=;
        b=SCelCLW1sJYGTFUL+SgZpCClVwNbuL2JidKUuq8oJpYNOMK8x7fibn6J/X9q4bt0Ep
         a1gLuzgLoxTlCZmhY3kNs9CTy7JCWtAUYv4hMGgk/WDH1jSof0isS/tVz1bsKm9qADhy
         ixlBTW/JbYPNVgxxNAPXdTGx7EaB2EBOXmA+h16KGWUhXy9O+MryPa0z3YM3gc9kavko
         r4TEsh55rp2aJzagwk7vDUAnWRHUrdznqSZAkWMPwWnQ6a7uSN3ltZrJB6XTT5S2LGTY
         6Fl9zyydEXWB1Y1wUgBBeK0BJD13Vorg/dUtUuHjhCVs7zRZUaqWiJYaWFEl5f2IfEKe
         eCrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=I2Ewj6wA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kX6Ai3omqBp+X1wVIxMWWute7y5cItgxKyDWQJTpv64=;
        b=C+JLt7CiWn7quoFSechoyjiO/QNmpqbdsr2EIVgBp5ATC3ja5L06EDtn4DOmf9C/Ju
         PHAUcdS3dEnKPHdwqjhjJekTHMtgZl5BT1StNKG8Ft90cz8LxZhz+b+/LgR7Civ8v35q
         Ltc+boWWxGZy71i7oG0CJcnEP8Cbh86M8iPJDUEg89oDr3urx1696gBhDq8bS4w+6Sbo
         jCnACd5s1QzghxArGd0HGnb7EZ8cCJIhGw2vRMPdB4srko0hfnangpArPhyQc+MHVuW5
         Pt3brOElBaF329JneaE86jkC/YY/KjT448cVCcka2CMGHL3EAvR04kYOtj0s8yfuj6oC
         Sxkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kX6Ai3omqBp+X1wVIxMWWute7y5cItgxKyDWQJTpv64=;
        b=ebT3JWPwOYrkzKnMN9LkpFMVy0p8Q/hrYIyvILbyWXGi2shEuUuMWF8VlRrCPJpKRH
         /todN61ocnNCOeZ3bnq6OfwDYWIkshQePHXa5n3HJ26ZGK7Dlu9apXUGGec6k6KI6fOZ
         nvBCSkTuLanog03VgeXmbLiTXwZSKHYyE5SORPOc9l5Czq5Eyjtv/aEx4FLJUqU9CSb2
         /K+P2bHmh8OsDgkhP1HgpPsxi838pqDpkef0yzf7lUz8DfPAGpnti77PvHAWq0IoF8mq
         cYEIuKx9xzb5Smp3TdblXHb2iBk+0K7NGDWNvhSXrmrVCY+4gEg69+E2vApezKVYsKyG
         xAIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ni5dlXbV+06BtIUGfIJrgiOIy39reB1FoMkuH8vGfICyDd+br
	n1Da3uEiUwtj5CZwRsS4GqA=
X-Google-Smtp-Source: ABdhPJynhJQWFyOE4O7IpNioTnP+c1GsV3g4YzWGfYLXL/Bpr46YL5RFmo7x7hGWvKNUMxWMlBw3cQ==
X-Received: by 2002:a05:6000:18a8:: with SMTP id b8mr24958483wri.166.1638827242494;
        Mon, 06 Dec 2021 13:47:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f885:: with SMTP id u5ls1153419wrp.3.gmail; Mon, 06 Dec
 2021 13:47:21 -0800 (PST)
X-Received: by 2002:a05:6000:1010:: with SMTP id a16mr46801494wrx.155.1638827241908;
        Mon, 06 Dec 2021 13:47:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827241; cv=none;
        d=google.com; s=arc-20160816;
        b=AAvglXTL7oLBM2ghd4QYv9iT0aCGrjlx9LgWYDaeClBFSWBNlrdvhs8zbDFOuuWTa+
         tU7BktDnE7ZbNvYEZDTzsdyDfBSKMYgf7K6gSIeLUp06SMETSgiGrGR1F5Qccc6Pkqfl
         kPbrHUmdJOh5NxDXAIrVbXfPirhrjjVMvPoQRC3xYNJY9soqY8AFL8DHF7wToRPwVUA4
         mYdVxeMNFQ/8EKK/eVAD2ynOLwLNHLRUOOf5IbRReJzygtLadLabqfLgBzaZScGV/QsU
         MB7bvhKpd6IvBa3NrhLmM+kEPDKGspj3GxPP8wlZ6tb3XeEnAaxPhbnzk5T2qJenXxSC
         gdJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3pytIz/mVv/PIB06AmhSlrnOdE2zgWaSkR0qkks0t+o=;
        b=wcUK077zgNAUCIy0hWFVSmxIPsRWQGsPy3h2YPHx0imeK46JHkfVT4zZRDhpLSDvGw
         Y8w1RQKAdlKl6qf+AbjHo8HpbVwe8YVov4dpVNuMA+PyZ/5xuQi7gGHFJIKZ+0DuT4/z
         7jLVRfJqiHwfkln+Avzol/Sp3LqmQMPxTon2eZ0UJo6eB2SkzCx8sTK/djJBdYba4YI4
         hFUHunm1F8jEZGi2bMfesbh7lFPLDjnCrARNrQyA7LUAwNEVJmVrA+peVI0fIxZniyy0
         MuND7wPfT5XaUDsHmi7LI5Jc1RLD4ThxRkvxNTCQFgxoDKO5Rq0OIGS7spYRYSrU25HX
         EVkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=I2Ewj6wA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id z64si70075wmc.0.2021.12.06.13.47.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:47:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 34/34] kasan: improve vmalloc tests
Date: Mon,  6 Dec 2021 22:44:11 +0100
Message-Id: <1780c3aae4f143d4bd2137cb0d2e3a137a680664.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=I2Ewj6wA;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
 lib/test_kasan.c | 181 +++++++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 175 insertions(+), 6 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 0643573f8686..44875356278a 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -1025,21 +1025,174 @@ static void kmalloc_double_kzfree(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, kfree_sensitive(ptr));
 }
 
+static void vmalloc_helpers_tags(struct kunit *test)
+{
+	void *ptr;
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
@@ -1073,6 +1226,18 @@ static void match_all_not_assigned(struct kunit *test)
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
@@ -1176,7 +1341,11 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1780c3aae4f143d4bd2137cb0d2e3a137a680664.1638825394.git.andreyknvl%40google.com.
