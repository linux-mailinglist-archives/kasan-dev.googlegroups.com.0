Return-Path: <kasan-dev+bncBAABBP4LXCHAMGQE6TC5U4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id D7E8F481FC6
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:17:19 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id r7-20020adfbb07000000b001a254645f13sf6570535wrg.7
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:17:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891839; cv=pass;
        d=google.com; s=arc-20160816;
        b=mPGhTntI3fAQs7orLInxsyiDfAtiKAPIDDzsl/s6mO4bydLyhAwALwOnQecYTpW0RN
         L7EM8mCpAjgTAGeOIYahijCzwwGO/NAeYbQHylXaW+LDNU0N4jJXy7WZC1R4ACK50rHi
         ZnSMbC6YHgctNUkHTkziq24729aXtwXjMjUWZEZqLIG2XERINxIs5PJMy/4B+JCNpIFF
         oyh28ISd2Qx+Fra2UnNAWbY7GzE5C4j2X7p/6+FuR5IiAFHTlZ2fp8NBEzzDTGhB9Qoe
         q7l+S7XVSfh66zEubfuuSV4C9pdQKJasZvT0Dp/zqdmdcH3NP29us0qeG+QiihQxJNc7
         EDpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JWc12F/1Qt4sDgLiYzGuMv3kwqMvtvvBVSdZwqHPuSo=;
        b=L9fdHVyNh1xJlO/bJ/jJe2YZwmR8rmUJ9SiGBjyvZN14rZz1/GNdZ/25ziDhDJVF88
         UDfw/0fVEI2M7WUaKZZD+YJm5swGtcp9DpjphhAAJ7CAh6Jk2JoOt0EhgXCHoGQI4Ot0
         qbOXmiqXM1HSqr8fmRB7RJRJmtdO9UcAi1JiPy/tT9W66e6qHpMfGglXZhdOol/Nun2b
         ML+3bdSfv+9plNtEWUkNbGJaa0HQs8t6VedTGaOJ6e7N0PWhdv2eSeR3pk1P0NhTEoaH
         EoLKcPrtVpXFl6jN+/yiHRyt4sHKtkjVZ3IV6IT7E/f5yCnRKKnZc6kIUMfLZ0MNF5L2
         MMKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kxIYlakH;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JWc12F/1Qt4sDgLiYzGuMv3kwqMvtvvBVSdZwqHPuSo=;
        b=SkrjjjL4PDSL7BdLIQwSvuXOk1d4TDdY7XPrr124YJv3iy9HrIdfiMbLGPvjipEjh+
         vZQCVURyzIGIdAsYUfUzqOToJHWwNAggOtOHYggCAw2NsAMtBohiwqEkf+ygmkntPVmn
         yQvWYoxRAOo5Hhhf/L/p1xCOhBvZxqx73Sy3IZPjrkeCEJjIliWZrckMwalLqavgLQCh
         1066TqMVBMUblCMeJjS5K/jB19evm0QPujaKlsPkMr9wEROswgsSIsTViO/pyGOlzvYg
         jGqSiUAcSHgcDrKhvselMX0hkn1f685iD3inoLwMo6nQt/jdwC8NaXiz6gIE3VLw2+Mv
         9nqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JWc12F/1Qt4sDgLiYzGuMv3kwqMvtvvBVSdZwqHPuSo=;
        b=G078MkgWRh8wQh2BrrJUppg94mVkqQmWeleH4q9jSv5WWF4AJr1ZjkhMsbECbIbsWb
         oSJWbUIM0OdGxQ6xz3itf6JXllzTU7i/iBOwQy4NnqQ04Hdrfgyxr3gE5v8+Dr6KuBMM
         uFnJHxDsXE8q5T/+5OWRq+OoOWnPRUoSX7Bj9Htt2xV6tLUL+5QO3HbXqUAQeW12JB95
         ig72eWThcSmDT847pYM8P0q2FVGmC+Oa0MEe3uxF3vDS/LCsAQHys7zIh0U6cBw43WOa
         7NXhgDXg/gSTSFqq0MYi/irvCMng1UVgzfkT3KUOp1Cui0esluvqmrsYr/cvnx3dBLXh
         aTJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HocH3w5nJJtd6NmF+EolMbq3HuPGMVv+xnDmQwfyi/GiPSwau
	noUx68nliw4WrGayJga6Uts=
X-Google-Smtp-Source: ABdhPJwArKYmkolTzD/2aJzwI6++F8OnSWxuzjKjBoDE7TYJzncijjwyN0N8kYOaQ98ZYw8FENzIrA==
X-Received: by 2002:adf:fdc3:: with SMTP id i3mr25704458wrs.125.1640891839645;
        Thu, 30 Dec 2021 11:17:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ca47:: with SMTP id m7ls325044wml.3.gmail; Thu, 30 Dec
 2021 11:17:19 -0800 (PST)
X-Received: by 2002:a1c:740c:: with SMTP id p12mr27015740wmc.140.1640891838949;
        Thu, 30 Dec 2021 11:17:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891838; cv=none;
        d=google.com; s=arc-20160816;
        b=PzV40Leamel4wH5A2qutwOZ2D2jqs4yyQmRKjfKYXSs31M1/ZqEInjL7NaRWRzfDSK
         ejdUV0GfSYTH+/V1Yv19xwbwqbK9AHOKxJYqfgwH7w748bKnoNTWNO+uUfdy6ZU6XLGS
         NY+vrWFlzPgokSODeaH8KOaD27bAasuGl6W0Z8ZISc42qA5UK8XUmebOOo91LC4nx+Rj
         iTobn1lvTU1Pz22ZnCAW9itqxHAaah+Ge3PLViNlr4UPIoeGgX4VqBOLlXdZtfzxcB4I
         YgSKH8XjYYc1r+zDvK4lpm9Wy8zREqCCyGThuMn/rOxiKBalLBep+qaqUdSGAJi3OvjB
         LEOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=boV4BKjs1buZcE6U9f3+9ZNSDpvsszrp49sK5MVcXV4=;
        b=mAHyhjlQrHpEcoM7183+LfLAWYBTLTQJ+oqDZvXOQd1E/GCJSrKytoTMFeUp1Cjft/
         s9M9SoxUCINS+mIbQyHntdg+ILoiT1yhZSvizIsXYoDfyQNg3iNyTW4IcoNwtd73qV8U
         gZfsv3VdOfZcjbgSXQOL0yUso0AjKbzpCKBmQmkMDBv6b+rtY+C5lZuCmQq2YdhV3rmZ
         GQGiYoD3TCbRzPGcYn48TdAFaJoU0iOo2lCMSUv712A/JYwDZppy4GcpPzI1tIiqdix6
         qyJQzCEPbiKXG41xpNLUtz/07WZfA+CplVySLZLZZS8sh9Eg5EmBcdn5vKcMdRACYqBo
         Ae7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kxIYlakH;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id m12si946823wrp.3.2021.12.30.11.17.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:17:18 -0800 (PST)
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
Subject: [PATCH mm v5 39/39] kasan: improve vmalloc tests
Date: Thu, 30 Dec 2021 20:17:14 +0100
Message-Id: <2355bbf7c4a3165c6114edd518bc5fe233ede537.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=kxIYlakH;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2355bbf7c4a3165c6114edd518bc5fe233ede537.1640891329.git.andreyknvl%40google.com.
