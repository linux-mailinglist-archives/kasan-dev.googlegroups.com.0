Return-Path: <kasan-dev+bncBAABB2GBTKGQMGQEPHBGHTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id D270146410A
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:08:40 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id a64-20020a1c7f43000000b003335e5dc26bsf11138394wmd.8
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:08:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310120; cv=pass;
        d=google.com; s=arc-20160816;
        b=DFSqzMV2KYz82+RDPv4pbSzEiUePgm9N6+to02szbYo69P/OY078uUVKVoUY9xnh4X
         SQqiKzm3/sbDE2f5C/gOPIkXeggferMYS/gOadfLaqBoiSrTIS+RoBdimsA6LLipOvzv
         8S1uxBNQzAq58WqtdWBZwVf/STXQiE6AKa+b3aBCCk9Qz8SEMwYsy0c9CGadrfVI6VLn
         qby1c5cRxKzG7heMyr4MCx/tNXhWsWHYt2ekZORNS33YaorN5iNllcEu8/ijooCfkToI
         dGAOT+ALD52tLajYkxEmITwLu9/a/rk2VVQ55EvG71kvgwG5xAcZnO1IHPsMSjVVTJyN
         UHYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/sdW+hr8wKlbYdz+8xiTiF55Elg23u1VqxtihkUq778=;
        b=F+gidvKlXZpPSdAt3jCe0IEVb/I8ojOr3FSCzzrukzbZ7ihD3N9R9GjnbbOFEsDg1w
         0yliO8ORiLP6MrnpTmkzTg8tebadS3bpZKFn05BhxWncR1sptqGgerH3Rgv1D3DA2HOh
         iqFhSBLOOtnBxlXm01tylMo/kaGd+eGidBwDzFObr8oh529hWVuNJipr2yCfUzQIoSQD
         tDsUZ4xKMt1ing1NpnNq5wSNZsqYzTF92wM41onebR/9spHMRYWM6xUgVKxRZ2Jb1lVh
         u0dMjzM3cxy13PSl1wDah8k9fDsfPJkGomqr8l2wa5xXeUdn1hnYdBLuUt3WC7usPQuS
         GF6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=O9XjRA5F;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/sdW+hr8wKlbYdz+8xiTiF55Elg23u1VqxtihkUq778=;
        b=oY1C0w31Qy0FydETCMSgVRU4rh410x3bhZ6SqnbLPFIrq6644vkq/aO9zyXLW4R0FO
         VNw1c8UvmCYdBd8Pl+G/Xi3NhcYUkZntezizdjbX3re2YO5o8mpOHXg7qWi4unnxg21o
         AcL4SeHitLlPYNnY/YSp89F6M7f2KZiu4ZNRtgzkpG5GYM9W4pIx1Q2JQ2nFKtYu243Y
         fPKL+3mPwu0gEfJR3rBDB4BxiBI25I2FtXI8WbTIqHjy/LjGIp0UKH3lmFKy293Rgcws
         UhTk1zQB8yMJUV13/uYBfK524VpkAQSRYchD2F2J7XilhDpX0qsip4ktoTDOsYyeqSR+
         4sDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/sdW+hr8wKlbYdz+8xiTiF55Elg23u1VqxtihkUq778=;
        b=jQUv4ay6FJ4LBbIRBnLxids0w8+LPD2bz8H1gc7+z4SFx39WOrRXrrzDZ1PZoCKjZw
         UD/5AnRO+uhRmIjstaoX31+SpfTzNgce+fO4QoAGOKFtVommNbMlEem6gh1VjSxIfV2A
         SGICFapBipS3hx3B244qkcVDCTxI1pGO/8W2Ndj7Srs9zfTuJfxWB4rVYTKaaJ1icjwl
         Sf4vL6KvYrHkyXNoW5xGML1fn3NP+jGLloQzrwLiYY8p8ye+XpS4dFliWIoLn3yEkgrC
         TkrkDpw2GyX1SfCs3rIeyEnBF1l2vNvS+PJ9MBJpR06nU048MTkWUIcThwzB87+10XzW
         w3YQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5325dhYes6a46nWRf7UED7kEzDHa/T2mRKSlYuLwzneVUfrS6mNf
	dMHGMnSJ99ljDo9wTqkmXMM=
X-Google-Smtp-Source: ABdhPJw2auU2uNQQQ9L4bjD5UGrH0IT/aArCmYk831bJWE8ZfgYkLTGaWmCdvm3aZmgHt1mS7pc1pQ==
X-Received: by 2002:a05:6000:381:: with SMTP id u1mr1928165wrf.383.1638310120661;
        Tue, 30 Nov 2021 14:08:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f1c2:: with SMTP id z2ls190989wro.2.gmail; Tue, 30 Nov
 2021 14:08:40 -0800 (PST)
X-Received: by 2002:a5d:4704:: with SMTP id y4mr1858682wrq.85.1638310120043;
        Tue, 30 Nov 2021 14:08:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310120; cv=none;
        d=google.com; s=arc-20160816;
        b=mrMI3KNH27UU9dLKvPbarNVo3+W3awVqb9HIDERPCcSYuxiiTgb7CPXCncG68YTUuQ
         67Iju5B8pQ+O/tUz2d2yLX3g88VeSlcBqOAqjbqx3vRgImiK2bC1Uomvqx9wPId18aqa
         KMTfKBYgv9EGrKzuL3635YHaO3TgkmfeQIDRqqIjQHQimZOQ16z0ykSJQtyhCdQitb4f
         pnONEAQuZedspMZjf/eVRJFa1yfOA1zTOzdMv72ARZWl1lnQ6hEaIWlDnZIkGVkwonCS
         If1Nj/jGlzVTuQuJsZyGnsXsjPqhr07P7dfEDWIT76v3NS2URuBvLoNqIimDpBDAsyZ0
         ReSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3pytIz/mVv/PIB06AmhSlrnOdE2zgWaSkR0qkks0t+o=;
        b=Jd+k6lAM56Yq6dfnzO/Jq05djrYBqNCIof5IU1jeflTmYLFMj4O7FiOimsXM3p3b6x
         Aywdf6pSYDEcNf3a2xz+Ob0lbnOvxLSw07ethOnCfaOFJjvZgq9+Zu19vMCVFZIQS4uk
         6bnH1aK5WX07/eGLcfwcW8CoQPCZxuYHy5dKF/03w1B8P7zb2xZGxaqsW3Iz9hwoRcVq
         EmSwzF/7pO+C+ZXzLdcqPAPgYCFzgN5G9uF6Wh+rI2aFpsA6+NNYQmlbWfmVEbUX33Nh
         uWvictNDm9iqZPCv/xb5WWh5L2afDM2IjEJKHrWZMCT2C9lOPXANZtCSzE/A8OspTpOZ
         vN/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=O9XjRA5F;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id p5si1268325wru.1.2021.11.30.14.08.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:08:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 31/31] kasan: improve vmalloc tests
Date: Tue, 30 Nov 2021 23:08:38 +0100
Message-Id: <8ca1ca8ae126f653b5aaed2c6a98ad961bbb937f.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=O9XjRA5F;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8ca1ca8ae126f653b5aaed2c6a98ad961bbb937f.1638308023.git.andreyknvl%40google.com.
