Return-Path: <kasan-dev+bncBAABBIWWXOHQMGQEVQWUNGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E0644987E2
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:08:35 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id k11-20020a0565123d8b00b00432719f58dbsf9394441lfv.22
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:08:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047715; cv=pass;
        d=google.com; s=arc-20160816;
        b=PqGDIePviEDjygzRRhkoPFLoCIXJ/R7M0Rqnd4ZeWJZEH5c01Tsmu9+t/Vb8PpxT/c
         XiFDZUuoXBzDDJCodPyMuieSsLfrRZyYfcMfNQGeviGfiKURvE7zviXhrOPKJ3eLVuSd
         GjER83xnzrAefMpfUxVfAFXQl/GezmtR4NSroOSa8E4YTWrVIruzYLWcYinCo2qlAL+E
         HvR6W0vtLq9AO33yFBy20DSfQCemchCnsBxnEsjFqAupiBG0Gx/uLOK1fs1QfXyeCA36
         BJfG036NsnyOX6w59MUO5XDyPBWyWDuYp97HepKLowYLjidRQ4riwQnvVFCqseJ61FDj
         DWBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qzHb981cc0OhaLs0MZXsYbMTcl8b1cz36ofscXZr9SM=;
        b=Ipl6ttID5SH2MgDx23DqotD4ppyPaGx5HKpLI89LGiKp0DuBJ8vbnPYvsZGj9XFCix
         XvXn7ywP3nBNmvCIg9ypNLgCunzm2kntQ7dy9Ex5X7hp7pDtg2k+3CQM6DkHoblxZxp5
         T64xYZ3GFFXobUrXhwVgbi8/XCdEQrgMUeQC8wbPfT753j4Wa7gGDFblR7D4dy380QOL
         oxQ3qUOPczRutqOGDIjp7oEc27Q4v2a1xYNsbohAnJlMVBfDTNxcDUfs3m6Y6J7zTpKL
         6t9b9YxH33PY3ViOdDwxAFKOBhgL9MoJuwY3UFJvCGvs4XeUB6RQhPtxccZ15IO+c1oj
         kS6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=scOaYcfB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qzHb981cc0OhaLs0MZXsYbMTcl8b1cz36ofscXZr9SM=;
        b=NAbkrlUar6Q0rsJ1Fz6JImEOtVrMrHdoWcE32gJZl6FOBLcrEFhjhZkWBd0uXeHC+r
         WCx16o9wNJf1l94/Jmd4mEAcONo2d20rsC8tRxyGQYVRQN7TwucBgo6r5olklVoEqK0H
         HEQJUH6Pl/4IeOtyWERwCPTlBvWJ7NdldHfRnxGdWOG7VIxQnUzkcImkBx8o1vqvAltE
         dbmi6cEdhIF3P6LtlR0yP+TtJ/ur/DONcEYJ5/sxN7TFGJo2ymNEC4QXK/9AZygwI1gs
         JZ2Gdb0LXtKVSsRCpH3rlxpJC3F12kfg3eztA1mPYdF6HU/CobycVfP6bV8TJr32ve0R
         NcFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qzHb981cc0OhaLs0MZXsYbMTcl8b1cz36ofscXZr9SM=;
        b=7wVOHdrKllZV2tBidOzB1glgTl0wQoQEoRAfTpYQ9DFdfNbsPp0icRQ/DghFcSXpMZ
         R5UK2LjIund2a04n6Sa3NMZpcNtTPqfweenWBhaPnX1CopjVxdSn90g03JZdxZStozVC
         6ifyH5exEyzVizZk34P8+ecRl/UXNZ6K9wnYMd3S11/WMBwQzEmtJyUEGAMmYopE1gz8
         DHs+3qQKpEX1LtYiae3A38czbnGFTUW3dg4BerY4o6b/alC5OGEt5vGTW86zQJzIBXTX
         uLFZK0Ix8IJiVxoCWVLyXQxFcL78C4GDhB/d+0Y5s4CN0dT9bWgwRXPt5IBaL0Dez+Fb
         McPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532BNVv4nTTKi8aPFJSaNvGx/N4RHhoUwYqtLwbvOrvTe+qU+yjA
	oVctCQs5NlgFhH4C8w7JriI=
X-Google-Smtp-Source: ABdhPJzTO+PZkT/BicQxu+mONfNSHRXapBTCnb39HyP2m3/tV+BRg+4TPmKTft3SNKGlPCyy0UBpKA==
X-Received: by 2002:a19:7412:: with SMTP id v18mr10119591lfe.591.1643047715024;
        Mon, 24 Jan 2022 10:08:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b90:: with SMTP id g16ls577870lfv.3.gmail; Mon, 24
 Jan 2022 10:08:34 -0800 (PST)
X-Received: by 2002:a05:6512:239e:: with SMTP id c30mr13354207lfv.95.1643047714025;
        Mon, 24 Jan 2022 10:08:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047714; cv=none;
        d=google.com; s=arc-20160816;
        b=ETBvo61Hw3qmBmiUQUnLZq8/NBj2A70Ju5jvARd/e1jpXIj1mv14carYedDSdpm5EE
         DXAXjqA+DS/K5vFCpstXQvZODxbzjYQhAIcWiKfIAQXUqnGSYv2QQLlfWNv3fx7X2nNZ
         eqKKsTcSlO2wrZeSGJCDASe9VWIaxAbF26MSyBn8z+iK/loGn+z+bu2TK8NOoFzkBlR8
         mLxg+vphy+D24GXBGcZ4E4GiMd8DfkNwEKKoHP5Q2T/YL0+OMMMG3P+1NypABPmsC/hb
         UBl21WbGEUc8P6rdcgmw7lyYpmWg4o6FYz4sZ37+SzogFwZI9Bzd+dX3+j2vaISRjvxI
         wYDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=boV4BKjs1buZcE6U9f3+9ZNSDpvsszrp49sK5MVcXV4=;
        b=oAoevvMDZ4lR0AE7lo46EUAhNw2UyMzpmIsT4657tDxTtuWHAEuwxtzB0MO8ayIfMN
         kT9v50knXdB00Q7T/qD3UmpSSjaXbvY42aN8USA7yNiBr1x+8zWFPQ+m4wloqYL2UKII
         b7C/AgSzYq51sTCOsRq/R+33ZLV95ljl8dknr2xwAHsfN6ZKHc85h1XVmDMZuwxXCBze
         bHpUdoLh65b175lGPiI8Nz9ejNiRuIewFodItMO9N9jMkGQTf2XO7Nlcksw38ucTX6dw
         FN+kaAkzScJUfoRGcK8/ZkRA7KWcWOwEV+dmxpxKnAsWaSBB+Zp8tJNq+q1Divhb3Hdl
         ohcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=scOaYcfB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id q5si499113lfg.3.2022.01.24.10.08.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:08:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH v6 39/39] kasan: improve vmalloc tests
Date: Mon, 24 Jan 2022 19:05:13 +0100
Message-Id: <bbdc1c0501c5275e7f26fdb8e2a7b14a40a9f36b.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=scOaYcfB;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bbdc1c0501c5275e7f26fdb8e2a7b14a40a9f36b.1643047180.git.andreyknvl%40google.com.
