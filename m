Return-Path: <kasan-dev+bncBAABB3EC36GQMGQEHOYNAQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FEB6473711
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:55:56 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id g81-20020a1c9d54000000b003330e488323sf6730558wme.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:55:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432556; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ohp2QzeCFjlo9T9b7rtNfpA7FgQEfC+zG2FoZxbXeTzm8BemmG1mu8iJVJ3hpOfrJu
         A2ESoqIznIdi/upGpYzWqOTA3x9JoFG9abqrS9YwFNzhZbuzig/3B55KXqP9ZHKefJIu
         w+iS+0NljvCJHf3uPDPyN6l7Z0ctxdzZMfpYnzLgr31Rw2hQgfRbBr9VvYtB/Odmvy9H
         6cdwLANlZhaMuAfm5ANoPhSMHiQfOT6IxfsmX1xZ20fFZB7wgtR+u9buNjGSZtU3NXzV
         Tp0ucLP6tPxEKLzHrCVqi+nmAGVdwe0S1HrIa+Rmv5MBsQl8SBr3MJWDnPS3/SFr6nTS
         HO8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ezdWVDsxwDbv09ly6nGpnvg/nZOjCf3ZLs2uuk5pWQE=;
        b=avVMf+uOJW0qrPt/xc6NUgmFkp01TYodRrr7ja1euLQz0tPH8xWNujJ4KshvHfm1xZ
         Y4GG8G+/veNXBmUy4tEi0apv+IaOIzARlvF1TqI22Nfv7YyOIqww9baDTcG9YURBZ+3r
         pu8b2+hg3nnjgu9/YOLDZ17fETzR5Q/df56ZFpe815SEZ1hN5NNyMHqKRqJxNorkRooX
         vJPivXzB29QZylo6QODwGDsbXfM5vSQKpjvjJrL2JgxpzM6ssoyYCsk4Rnn3eOxLCOgI
         srWdbGbhJyafKMR0/fPZg+4TBF4qt1OUkuX3skM7fuZO6PJ2rxe0P5LMeJnktPTRM+rQ
         JHPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bihdkVfT;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ezdWVDsxwDbv09ly6nGpnvg/nZOjCf3ZLs2uuk5pWQE=;
        b=GVCYGosIWDlsIh9BBtSdOaYgcJkUKpoti1wEurlx6Ei9NWNJMdAarOPWXMYnuFwhwu
         dBjKD1x2KuWG6rjN3FjmEg1aoIqadkZYk19Zs2BRjHnjrrhknRtBUJuGDkgGTDObK7Ii
         vZJ2Mw0AsyuaW7kNm4zcPop2VaaAPAbN1xqDC/V/uU/pf1SRktTcfDWkPu/PGn2xKUS7
         RCJve1M3sQZBOFkn/n0oHXX22KSGpKK2bAjkmoMIFG2f98rJOrTAyKA3DDBqRHvIO9dK
         39egOeYTks5h8jhznHpat0mxc+IneFGrF5oCkDdYgk2zxGEfKJBus6hhmlhOUbxdX092
         CL9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ezdWVDsxwDbv09ly6nGpnvg/nZOjCf3ZLs2uuk5pWQE=;
        b=nfd9cRwFb7F6kfJQD1vt0RFX0I8hjsbKvJ1gh1fkOjHsUIAiBukFqM0rjRao9WDp8I
         z0mhoT/ZwkzrSgk8qFNdx1wpcehnzUW2rvDNRnWZgRmTlIgU+nG0L7KBngY7/NCfe+W0
         /Q/k1R69bSr31jKZMY8IBHfprL5R1t1ek74lzR//V3EhJlbrXcu4pA0orOr331GVeUM6
         VVk+c7hjBnNF03fQ2aJbimQ/XhkcK9ZhKs7LymS4xezZc4mtJ7GM0+oydfNsO7rjzPvS
         UUUR6TBFwAlPWU5bSLLIpFWIOxFmlMeosRCyMLracAXfNyUZ3MFCcl30rLEURCajbeEy
         8kmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533TrkGvIU2JryDZOiKiFekkLBnHZ2g+tjHo0696B8yIQ8l8lT9A
	QiHnMpnbbA3esLx87myffco=
X-Google-Smtp-Source: ABdhPJzXG6akP57Tzlrr1XItWiTbfjLueUw21+GZF4hfYDlnVkDwumlYy64/6cXspbXSVclbh9clpA==
X-Received: by 2002:adf:ef84:: with SMTP id d4mr1284581wro.175.1639432556382;
        Mon, 13 Dec 2021 13:55:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f885:: with SMTP id u5ls504740wrp.3.gmail; Mon, 13 Dec
 2021 13:55:55 -0800 (PST)
X-Received: by 2002:a5d:634c:: with SMTP id b12mr1297441wrw.460.1639432555716;
        Mon, 13 Dec 2021 13:55:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432555; cv=none;
        d=google.com; s=arc-20160816;
        b=UJf96VUmiEGxRbuBTkm3JnddOpwhVC/GZyA7ChGI3nyus0JDlDRodPelC7lqGIzOKC
         OfGHM0qh10iQZIgfP1h6Lhhg2iynkboGsOWytt9rzNgiIbnFlpelLRhgO3tQB35lBpYR
         fo4/vtrTBdFXndF+gaaMha+wayVdpU9im7Bh+CJd2oxOrkAts5RPRjNCAkU0zvQ0/jsg
         aerricfiNV2DlFD6qaRebiGkg0tOH/b96Pqy823ZPVK0RyKale2KrgF+yKNqUDpoVKaX
         EWz6bcAAd4K/S/Xsc45bl536ewH33Qe+Up3lmdnARFhAd4ggkKonhjFeoaivDovqNflr
         tvBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=atsw/HgrrU9UEfCA9neCOdaHXk4j162F8pSBON7qM7s=;
        b=LfFGuVkaU+2t4SldsfR3PBQerYYFAm5vh4ipQc8X5Pk2+Pf/1hzMqUx4GH5Hj9wUM+
         HC+Z7xnTfQTL2IDuCJAPMeQ/IfcqSjbvtLrc6i1DARriQEabFY/wMtG5JvwFDKRPtkes
         +bi+DZ83jOgG07TkbwJrbMyr22rlbzp2+ZoC93wSqltViV3yvIng7RlN92aC9zVU+GqI
         o0H73sYCd8HguzwB/oXpZ+G9ytvqrtjUem0n+3WHyKO0VvygYDebMNqdtaSi4KM7cQsV
         savyWgF/q3LZJfVSs5huvq92Ye7OqEZR2EtrPiOPED15UiEi3DTMYGaMZ4kS7q2KAkuP
         CX4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bihdkVfT;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id o10si7338wmq.2.2021.12.13.13.55.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:55:55 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH mm v3 38/38] kasan: improve vmalloc tests
Date: Mon, 13 Dec 2021 22:55:40 +0100
Message-Id: <3da23b9b90a4092dfc0e8355a974702985f6d426.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=bihdkVfT;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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
index 847cdbefab46..a554aaec45cc 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -1049,21 +1049,174 @@ static void kmalloc_double_kzfree(struct kunit *test)
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
@@ -1097,6 +1250,18 @@ static void match_all_not_assigned(struct kunit *test)
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
@@ -1202,7 +1367,11 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3da23b9b90a4092dfc0e8355a974702985f6d426.1639432170.git.andreyknvl%40google.com.
