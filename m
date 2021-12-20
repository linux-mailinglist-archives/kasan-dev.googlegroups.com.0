Return-Path: <kasan-dev+bncBAABB4P2QOHAMGQEHHGOFZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id C8A1047B5A6
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:02:25 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id d2-20020a0565123d0200b0040370d0d2fbsf5185025lfv.23
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:02:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037745; cv=pass;
        d=google.com; s=arc-20160816;
        b=nsVyozavbluYuXN/YNqEeY2hNxYyeaP1kutvwrSh3/fq1PpxZ3JVPT+VP5YkSeAHIZ
         P8txFID7LHk8Q7GIWg+Xj3+BiVMSinQTNXaWSGwKwCRHsO2jtvwc0Z7qXKstOdzLRfzT
         a3z+hYBqYNomzgbj6tm4QEaCnRERtlU4QJtdbTCoOb474JBFjwuqGwARWZjrkcVOh4PM
         8QnXTN6rgazs9fhUaTOyPL1u9E6hm0e4BHXzkFkCiox2m6XK5P6hI1D+C4cN8UnYohOV
         2QlFpe4GtE+uf7hOD9X93DPRrv6CU51zqiZuRZ580yZxp56YqF19JdKDTRKbTg/v2elC
         vg4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qg3eZT6l0X8xlXd4QdoT5w5qq7NmaqJpoKIev4aFAc8=;
        b=bZ4jUiJ+EZDbLCmYI7uKt1eoyRW18ifl0oqTUHhvnU4af5tvEUoj65/6R3IXoq50BJ
         Qe9nvr1OmpIBiiAp41A6cukH0f34Tu78TLHVNuo6e3PwbD/wF0QYQQl+++YIyqbPQNut
         KHVgPycR9c1V5sw1f8JFeh0RcXx3MaiWOCrIN4i9M3RjU92d68Noe0MVFc9PRDDKygoL
         ZiZFwXHfDKVdEYDtVnBISjaO7DHpFj1WyHqY7ox+pwHneIDW1EEFXS3wUI46fq2qzhO/
         n7KNCShWmxkauip02xDUF1KCV+IQP3EnyZswhaZOjZCzhliJMW9RnVwO1oDH+yaQIEl/
         nm6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Hun8KCBY;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qg3eZT6l0X8xlXd4QdoT5w5qq7NmaqJpoKIev4aFAc8=;
        b=eVCqJfAR13pMi/rqflBSQDvCkLZ5KWvx5CwhZ5A8tt11kc7gKXS+ZHUAFsilzm4tua
         FppWN4h9tt++sWxfURwgrbf/s0RM8kxpYDCR0lQjbFREepoHzbzWBdBq5KDSN4uk2I/r
         rRcn0uny/V1HmlSLfYPgo1LMifzAh0MUNGo9FSX55WvVSGQaTMLBWm5S+AksVx0MhLeU
         kYaHS6aozhlxW2e4l46M7eTsfhfdnjImuvDzu7WF92gTkJukDqm0S9zKwiCfidxbhK+z
         ClxCdMObfMTcpPG5jhEslaVu2snjs6KaYRDYN3saGH8vS5Tv15K/PrW26y8TNF1RHtcg
         Fa9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qg3eZT6l0X8xlXd4QdoT5w5qq7NmaqJpoKIev4aFAc8=;
        b=fD1dS1t7A7stEUNz4MK2/Hpq/SI0aDZrvSFcnUQBF1JCmfZVbcHYZAPgB9l3wSraMV
         Nn4Nahx2SKl+5RcOG6tEbKnmL4+eAlXBWIoqL23+3Gv8D7XlUb7eWwtnl5Ockfw2ZIEq
         7ZkXAtH9d9Fdin1JKGfxHbrMZlyw6942FmP5iRXO7b2m90XaN/73FIeroWCamHby9soh
         3dN1pPYRkO5wmLwLfX9mLSnwSN1WZZx33hE1qdCBctHTpXfT4C4qfvx7febwPjtxMHEL
         PvvV0/ACjYMLkhkLdTUEg7x42VqNnRD84UWTbRkvT8667dLB2DwY0krbaxJp6ud/HGde
         LuNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530KsbDde7zK6SCDfOfCmzZk6y0fg6tE3QlhPuSHNI4sX+VWJdcN
	QmOyatF5wQivDPp+2KJ3gHw=
X-Google-Smtp-Source: ABdhPJzNKbzQhM62WMVW8BleKQTEF6pBS3tDUtpk4gLIXEpsrr4wqX4kgU+BRLvwSrC8S8zRGtRj7Q==
X-Received: by 2002:a05:651c:4c6:: with SMTP id e6mr49879lji.505.1640037745391;
        Mon, 20 Dec 2021 14:02:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:201a:: with SMTP id s26ls2688478ljo.5.gmail; Mon,
 20 Dec 2021 14:02:24 -0800 (PST)
X-Received: by 2002:a2e:80cf:: with SMTP id r15mr100118ljg.34.1640037744583;
        Mon, 20 Dec 2021 14:02:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037744; cv=none;
        d=google.com; s=arc-20160816;
        b=NJunx/YK6NC/Nd9P4boXI/1OqjY2ze92biAMDaUsw0TB6gIHm12wnjEfrSXz62zEAN
         U9xZycB5jLj8E5IrpRqVEKHYPVrLSDSQ18aBjMq5F6hvPDxqsgceKPw8ImMPHIkNTzYQ
         uYHnZ2yTFGyzRHezEXvFQZj+XfZ4jslBkjYr0ay9IHOIyOhxhcyswUJaiHp7DoJZAfxp
         ZN+jebkYTYkAJlmSYT35YGVAc5xWldgn5c4hJ+zblDkmlImf+AOLWVXOHp2opLACwyLP
         ORilCAzjxkJZgM8H8X5p5c4Aehj1kdLP6k0oifB9qYlVREMfAQZ8WoRU6BXKOW3Hb7fD
         kBbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kur2ASckBTfMXx5vBveod/WRZYhkEYj/b8Zk+mLRv7w=;
        b=l2cSGM4Iwg8wOzElmgt+pkhyWuHrfFNJT9xh6pCs247NTD6MPoNWGWkwVZsioDvNJF
         psh11yatYmTGf1KXsQOUedw4LzAveZBIfmT75+QvKuJoHxnCwBKZKXs51H/U+511vlie
         7+zyKkhJbm8hh6P9L+1i261Suy6A/uRatSTZNkwF9HvXlE00q/+EVttCyjxr+Og7wVp9
         VAKNACLmqZ7JINtTFV5ErvPN2sS1KCGQW6OlLsQx56a5Ry3X4nOnVonm8jD5XEAWagi6
         J6NGsodeBlIB5EyjOnvgHeBJjWU+679zvllVrj/FrADWpMKQTdH2CIGkJEvgkvQGxAp3
         pyxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Hun8KCBY;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id z24si689090lfu.0.2021.12.20.14.02.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:02:24 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH mm v4 31/39] kasan, vmalloc: only tag normal vmalloc allocations
Date: Mon, 20 Dec 2021 23:02:03 +0100
Message-Id: <09fc776d03e8aaa9efa78c743392972060f5256d.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Hun8KCBY;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

The kernel can use to allocate executable memory. The only supported way
to do that is via __vmalloc_node_range() with the executable bit set in
the prot argument. (vmap() resets the bit via pgprot_nx()).

Once tag-based KASAN modes start tagging vmalloc allocations, executing
code from such allocations will lead to the PC register getting a tag,
which is not tolerated by the kernel.

Only tag the allocations for normal kernel pages.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v3->v4:
- Rename KASAN_VMALLOC_NOEXEC to KASAN_VMALLOC_PROT_NORMAL.
- Compare with PAGE_KERNEL instead of using pgprot_nx().
- Update patch description.

Changes v2->v3:
- Add this patch.
---
 include/linux/kasan.h |  7 ++++---
 mm/kasan/hw_tags.c    |  7 +++++++
 mm/kasan/shadow.c     |  7 +++++++
 mm/vmalloc.c          | 49 +++++++++++++++++++++++++------------------
 4 files changed, 47 insertions(+), 23 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 499f1573dba4..3593c95d1fa5 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -27,9 +27,10 @@ struct kunit_kasan_expectation {
 
 typedef unsigned int __bitwise kasan_vmalloc_flags_t;
 
-#define KASAN_VMALLOC_NONE	0x00u
-#define KASAN_VMALLOC_INIT	0x01u
-#define KASAN_VMALLOC_VM_ALLOC	0x02u
+#define KASAN_VMALLOC_NONE		0x00u
+#define KASAN_VMALLOC_INIT		0x01u
+#define KASAN_VMALLOC_VM_ALLOC		0x02u
+#define KASAN_VMALLOC_PROT_NORMAL	0x04u
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 21104fd51872..2e9378a4f07f 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -247,6 +247,13 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	if (!(flags & KASAN_VMALLOC_VM_ALLOC))
 		return (void *)start;
 
+	/*
+	 * Don't tag executable memory.
+	 * The kernel doesn't tolerate having the PC register tagged.
+	 */
+	if (!(flags & KASAN_VMALLOC_PROT_NORMAL))
+		return (void *)start;
+
 	tag = kasan_random_tag();
 	start = set_tag(start, tag);
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index b958babc8fed..7272e248db87 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -488,6 +488,13 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
 
+	/*
+	 * Don't tag executable memory.
+	 * The kernel doesn't tolerate having the PC register tagged.
+	 */
+	if (!(flags & KASAN_VMALLOC_PROT_NORMAL))
+		return (void *)start;
+
 	start = set_tag(start, kasan_random_tag());
 	kasan_unpoison(start, size, false);
 	return (void *)start;
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 47f3de7a3396..01ec2ef447af 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2220,7 +2220,7 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
 	 * With hardware tag-based KASAN, marking is skipped for
 	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
 	 */
-	mem = kasan_unpoison_vmalloc(mem, size, KASAN_VMALLOC_NONE);
+	mem = kasan_unpoison_vmalloc(mem, size, KASAN_VMALLOC_PROT_NORMAL);
 
 	return mem;
 }
@@ -2459,7 +2459,7 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 	 */
 	if (!(flags & VM_ALLOC))
 		area->addr = kasan_unpoison_vmalloc(area->addr, requested_size,
-							KASAN_VMALLOC_NONE);
+						    KASAN_VMALLOC_PROT_NORMAL);
 
 	return area;
 }
@@ -3065,7 +3065,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 {
 	struct vm_struct *area;
 	void *ret;
-	kasan_vmalloc_flags_t kasan_flags;
+	kasan_vmalloc_flags_t kasan_flags = KASAN_VMALLOC_NONE;
 	unsigned long real_size = size;
 	unsigned long real_align = align;
 	unsigned int shift = PAGE_SHIFT;
@@ -3118,21 +3118,28 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 		goto fail;
 	}
 
-	/* Prepare arguments for __vmalloc_area_node(). */
-	if (kasan_hw_tags_enabled() &&
-	    pgprot_val(prot) == pgprot_val(PAGE_KERNEL)) {
-		/*
-		 * Modify protection bits to allow tagging.
-		 * This must be done before mapping in __vmalloc_area_node().
-		 */
-		prot = arch_vmap_pgprot_tagged(prot);
+	/*
+	 * Prepare arguments for __vmalloc_area_node() and
+	 * kasan_unpoison_vmalloc().
+	 */
+	if (pgprot_val(prot) == pgprot_val(PAGE_KERNEL)) {
+		if (kasan_hw_tags_enabled()) {
+			/*
+			 * Modify protection bits to allow tagging.
+			 * This must be done before mapping.
+			 */
+			prot = arch_vmap_pgprot_tagged(prot);
 
-		/*
-		 * Skip page_alloc poisoning and zeroing for physical pages
-		 * backing VM_ALLOC mapping. Memory is instead poisoned and
-		 * zeroed by kasan_unpoison_vmalloc().
-		 */
-		gfp_mask |= __GFP_SKIP_KASAN_UNPOISON | __GFP_SKIP_ZERO;
+			/*
+			 * Skip page_alloc poisoning and zeroing for physical
+			 * pages backing VM_ALLOC mapping. Memory is instead
+			 * poisoned and zeroed by kasan_unpoison_vmalloc().
+			 */
+			gfp_mask |= __GFP_SKIP_KASAN_UNPOISON | __GFP_SKIP_ZERO;
+		}
+
+		/* Take note that the mapping is PAGE_KERNEL. */
+		kasan_flags |= KASAN_VMALLOC_PROT_NORMAL;
 	}
 
 	/* Allocate physical pages and map them into vmalloc space. */
@@ -3146,10 +3153,13 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	 * (except for the should_skip_init() check) to make sure that memory
 	 * is initialized under the same conditions regardless of the enabled
 	 * KASAN mode.
+	 * Tag-based KASAN modes only assign tags to normal non-executable
+	 * allocations, see __kasan_unpoison_vmalloc().
 	 */
-	kasan_flags = KASAN_VMALLOC_VM_ALLOC;
+	kasan_flags |= KASAN_VMALLOC_VM_ALLOC;
 	if (!want_init_on_free() && want_init_on_alloc(gfp_mask))
 		kasan_flags |= KASAN_VMALLOC_INIT;
+	/* KASAN_VMALLOC_PROT_NORMAL already set if required. */
 	area->addr = kasan_unpoison_vmalloc(area->addr, real_size, kasan_flags);
 
 	/*
@@ -3863,8 +3873,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	 */
 	for (area = 0; area < nr_vms; area++)
 		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
-							 vms[area]->size,
-							 KASAN_VMALLOC_NONE);
+				vms[area]->size, KASAN_VMALLOC_PROT_NORMAL);
 
 	kfree(vas);
 	return vms;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/09fc776d03e8aaa9efa78c743392972060f5256d.1640036051.git.andreyknvl%40google.com.
