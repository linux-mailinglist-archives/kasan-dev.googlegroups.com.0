Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7UG7SKQMGQE6QVTYAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E98656351A
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:23:59 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id az40-20020a05600c602800b003a048edf007sf1085861wmb.5
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:23:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685439; cv=pass;
        d=google.com; s=arc-20160816;
        b=KjAemOldB4Iquy3RHzopAhudJdAVtLDHrKOb3PaAyvhgyg6dhSjxbVIYw9Ic786N4u
         d3D6VFsHINfmc6X9lMny+4ko0HcKsyRcLOYGc4iocnORcAphj8mBGBG6p+KrkbNumNUn
         RAJrqqeEAZK9F8SBrqCF5/aTpF1Q0EbfQxz9FRXlakX3MB9H94HMVPrR3FEeQ+ntXRiz
         5250t4X0YHFV2bL/32pvWQ1OvWRAblcacF4MZOlqE5qW3SA9Q51rYHUSf7aW3LWOuCUy
         YDhEvjSwbtdU6puHcNU3X0L9WfTGxwrwmHISwdaC08OuEol3i228vokg1OtuInduQ7Ky
         z2rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=d1H7ti7EIhn54Gxt5RlyY9Za0fSEQ845nt9tEKXEfkE=;
        b=q56asELQOhJHA7yBj2Y9L14jzbYEPnyz0SimBgq6fgxEP5+nN9n7t1/0xbyy7buQ+U
         sR0BsEn6ZZp/HhZ1BEs/xS1Wh8gnrqhz8O8iC0aUpCJQY2T6JUNJXaS4dfxC2PxCR2H8
         jIEKx+Q6iNMkTbCiHBh8g63UO1myybqwczF7kecrmOi4oTQtnkyueou978xeCZi9L8m1
         BY4fh8uJbjlRqFlFwOzk77oG2KnQjC7NK9fhrWZQq0yWF5dJCv6ipkNyZWFjGegx3YPN
         mpCVwGUIZ4nqiltOx0feMKLd3tm3Y4rcZIkQdquD53LkO1SHVQSi1bZ8lns0zfmcrVMj
         YSag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ilZQasgN;
       spf=pass (google.com: domain of 3fqo_ygykczwche9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3fQO_YgYKCZwCHE9ANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d1H7ti7EIhn54Gxt5RlyY9Za0fSEQ845nt9tEKXEfkE=;
        b=qaFWZC+aaYVjsbAT/CXOd9+BJgj1R1ZipbE7EHGmrZpfWjq62zpDNYhi4K7WDz8f7q
         raxATS7rIZpGsFZtB5EaIBcJyC1+bEG/rrOdhhW9sYSMUQF4YQLpdJOhERuu/pQeYV/b
         UFIv8wmvoVgNeCKolhcCZ43TJpfz0rh0oJfHmHs6YdKCjaemZEq/ubk8B9zqwM6khbXV
         4z1+wvapKq/n71Liqw/dIkhrQJaHw9fPT6yU2iKVKNxVum2zAYGmqeAsH4XPED5F0EBy
         2g+bheJUXxYhbyadHO8qHycWVfRQK+ENOxDH3nRGCgRR8HF00cHt6YBbriZmr+owK1ii
         sggg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d1H7ti7EIhn54Gxt5RlyY9Za0fSEQ845nt9tEKXEfkE=;
        b=sh9QIn1DxGWKnZoxPqEwgsCMgpFtXm/16j8Q3fsJuzr3DLbNzpaxrLVaTIhnWKVlFo
         PN8Gps0mSPt/vibUuAf2Ar5akoIAZ7fWvCwe3mSWJiuy+Tp4TvwX7iOtVVjqgTAVoitt
         YA9HD2Q20GFSBsYp4qSfXaLeaGnKXlRfO07p6upUBp7YrdYFaa0Lan/cnreaSi+H1qMT
         ZJ2CMdM1Iu2s3YQNrP8sLEFMfk50arCsH4RaFN35JWpR6k+UELXen6k5jWQ9mkYQNPU7
         PSjnfbOEEqM0BEFAhPd2nYJBWSar/LRZXzh2bWdTBCUAnBiWtR7NjzMeymrDOPtI56TE
         T9ug==
X-Gm-Message-State: AJIora94/QYFMFuwqVGstwjllXHDAzn54O8gHDSYJgd96qZRq6LKmCU5
	eFTMXuNxuAfluWwp3nbzBeU=
X-Google-Smtp-Source: AGRyM1umKgvOixlytij/Yp7BGTi28jZa4mI7APkMxmfiVz8lxyiAV2cmBl4sFp7zTwp6Nu70Txk3/A==
X-Received: by 2002:a5d:688d:0:b0:21d:3f71:f33c with SMTP id h13-20020a5d688d000000b0021d3f71f33cmr8288561wru.82.1656685438882;
        Fri, 01 Jul 2022 07:23:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:156e:b0:21d:2eb7:c707 with SMTP id
 14-20020a056000156e00b0021d2eb7c707ls11372426wrz.3.gmail; Fri, 01 Jul 2022
 07:23:57 -0700 (PDT)
X-Received: by 2002:a05:6000:15ca:b0:21b:baca:5902 with SMTP id y10-20020a05600015ca00b0021bbaca5902mr14242232wry.294.1656685437860;
        Fri, 01 Jul 2022 07:23:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685437; cv=none;
        d=google.com; s=arc-20160816;
        b=bwXUGnapq4QA8qKenyKHScPRfJu28QIqJ+Ff5ColUnqfnM/ksxeU25WzMaDr3tsFfo
         adEazc2fKsoE0ljdMy0vlfaoq2xsHoAsmrgrvzQAeShHqNKjvi6wpbTcyg1rQd4V3aOs
         hNheSpUIahCjYNUL478hi0cc4LQA7Z4UEJ8oCOHbtGWF+U0Vrz400XimgsCGaxbHkJgU
         uM+QKnRLoC9uMr/ys1QTcI2EHGRPoXrJL7LIGmr2/xLvboHBzmoFHpGZm6mPeYsWejpz
         CamqKZSKOL/aa8WSWoyxkkEbJBCGENUntr6ltb9mNsFkrSiffI7KZOSRZLsXCnQLRDd6
         osdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=yQ768gKjsg7o2qhom6fXRmA7hEqZpzUb/NLIF5UbCVk=;
        b=vCtWKqs7c/QLe1CU16KHTRPpoBnlI1QEdWzf7LMSj6HdPdKlabgx5V9qSm/L2Co2v0
         NLaykP8XNLZP2XHBLOLW5mintTmDicR2AczXNeSBjG8fo7NgyiYWRFrM8pDv8DbNqK28
         dMFq2VE5iExr9VatAZLFOd3pzXmxLOoIJKOh/UPSxnwH1jeG/4cBXI1ieB8F2xnwXkU+
         72axDE+4eCiCaw5lY7kWbWdCRMCDPFg3SHxYOut1vWgWYz6NsMzwxWI7j2DZdRoRebjE
         6ALP0cjYOXaS2rO8KTdDTRwMRHjPuJCdXyuFYLy/gRXASuKpFnOgd5cy7z7b2HzBhBKP
         YBXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ilZQasgN;
       spf=pass (google.com: domain of 3fqo_ygykczwche9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3fQO_YgYKCZwCHE9ANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id m7-20020adffa07000000b0021a07a20517si789883wrr.7.2022.07.01.07.23.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:23:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fqo_ygykczwche9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id oz40-20020a1709077da800b00722ef1e93bdso835211ejc.17
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:23:57 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:4410:b0:434:f35f:132e with SMTP id
 y16-20020a056402441000b00434f35f132emr19195845eda.215.1656685437446; Fri, 01
 Jul 2022 07:23:57 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:40 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-16-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 15/45] mm: kmsan: call KMSAN hooks from SLUB code
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ilZQasgN;       spf=pass
 (google.com: domain of 3fqo_ygykczwche9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3fQO_YgYKCZwCHE9ANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

In order to report uninitialized memory coming from heap allocations
KMSAN has to poison them unless they're created with __GFP_ZERO.

It's handy that we need KMSAN hooks in the places where
init_on_alloc/init_on_free initialization is performed.

In addition, we apply __no_kmsan_checks to get_freepointer_safe() to
suppress reports when accessing freelist pointers that reside in freed
objects.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 -- move the implementation of SLUB hooks here

v4:
 -- change sizeof(type) to sizeof(*ptr)
 -- swap mm: and kmsan: in the subject
 -- get rid of kmsan_init(), replace it with __no_kmsan_checks

Link: https://linux-review.googlesource.com/id/I6954b386c5c5d7f99f48bb6cbcc74b75136ce86e
---
 include/linux/kmsan.h | 57 ++++++++++++++++++++++++++++++
 mm/kmsan/hooks.c      | 80 +++++++++++++++++++++++++++++++++++++++++++
 mm/slab.h             |  1 +
 mm/slub.c             | 18 ++++++++++
 4 files changed, 156 insertions(+)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 699fe4f5b3bee..fd76cea338878 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -15,6 +15,7 @@
 #include <linux/types.h>
 
 struct page;
+struct kmem_cache;
 
 #ifdef CONFIG_KMSAN
 
@@ -72,6 +73,44 @@ void kmsan_free_page(struct page *page, unsigned int order);
  */
 void kmsan_copy_page_meta(struct page *dst, struct page *src);
 
+/**
+ * kmsan_slab_alloc() - Notify KMSAN about a slab allocation.
+ * @s:      slab cache the object belongs to.
+ * @object: object pointer.
+ * @flags:  GFP flags passed to the allocator.
+ *
+ * Depending on cache flags and GFP flags, KMSAN sets up the metadata of the
+ * newly created object, marking it as initialized or uninitialized.
+ */
+void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags);
+
+/**
+ * kmsan_slab_free() - Notify KMSAN about a slab deallocation.
+ * @s:      slab cache the object belongs to.
+ * @object: object pointer.
+ *
+ * KMSAN marks the freed object as uninitialized.
+ */
+void kmsan_slab_free(struct kmem_cache *s, void *object);
+
+/**
+ * kmsan_kmalloc_large() - Notify KMSAN about a large slab allocation.
+ * @ptr:   object pointer.
+ * @size:  object size.
+ * @flags: GFP flags passed to the allocator.
+ *
+ * Similar to kmsan_slab_alloc(), but for large allocations.
+ */
+void kmsan_kmalloc_large(const void *ptr, size_t size, gfp_t flags);
+
+/**
+ * kmsan_kfree_large() - Notify KMSAN about a large slab deallocation.
+ * @ptr: object pointer.
+ *
+ * Similar to kmsan_slab_free(), but for large allocations.
+ */
+void kmsan_kfree_large(const void *ptr);
+
 /**
  * kmsan_map_kernel_range_noflush() - Notify KMSAN about a vmap.
  * @start:	start of vmapped range.
@@ -138,6 +177,24 @@ static inline void kmsan_copy_page_meta(struct page *dst, struct page *src)
 {
 }
 
+static inline void kmsan_slab_alloc(struct kmem_cache *s, void *object,
+				    gfp_t flags)
+{
+}
+
+static inline void kmsan_slab_free(struct kmem_cache *s, void *object)
+{
+}
+
+static inline void kmsan_kmalloc_large(const void *ptr, size_t size,
+				       gfp_t flags)
+{
+}
+
+static inline void kmsan_kfree_large(const void *ptr)
+{
+}
+
 static inline void kmsan_vmap_pages_range_noflush(unsigned long start,
 						  unsigned long end,
 						  pgprot_t prot,
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 070756be70e3a..052e17b7a717d 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -26,6 +26,86 @@
  * skipping effects of functions like memset() inside instrumented code.
  */
 
+void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags)
+{
+	if (unlikely(object == NULL))
+		return;
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+	/*
+	 * There's a ctor or this is an RCU cache - do nothing. The memory
+	 * status hasn't changed since last use.
+	 */
+	if (s->ctor || (s->flags & SLAB_TYPESAFE_BY_RCU))
+		return;
+
+	kmsan_enter_runtime();
+	if (flags & __GFP_ZERO)
+		kmsan_internal_unpoison_memory(object, s->object_size,
+					       KMSAN_POISON_CHECK);
+	else
+		kmsan_internal_poison_memory(object, s->object_size, flags,
+					     KMSAN_POISON_CHECK);
+	kmsan_leave_runtime();
+}
+EXPORT_SYMBOL(kmsan_slab_alloc);
+
+void kmsan_slab_free(struct kmem_cache *s, void *object)
+{
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+
+	/* RCU slabs could be legally used after free within the RCU period */
+	if (unlikely(s->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)))
+		return;
+	/*
+	 * If there's a constructor, freed memory must remain in the same state
+	 * until the next allocation. We cannot save its state to detect
+	 * use-after-free bugs, instead we just keep it unpoisoned.
+	 */
+	if (s->ctor)
+		return;
+	kmsan_enter_runtime();
+	kmsan_internal_poison_memory(object, s->object_size, GFP_KERNEL,
+				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
+	kmsan_leave_runtime();
+}
+EXPORT_SYMBOL(kmsan_slab_free);
+
+void kmsan_kmalloc_large(const void *ptr, size_t size, gfp_t flags)
+{
+	if (unlikely(ptr == NULL))
+		return;
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+	kmsan_enter_runtime();
+	if (flags & __GFP_ZERO)
+		kmsan_internal_unpoison_memory((void *)ptr, size,
+					       /*checked*/ true);
+	else
+		kmsan_internal_poison_memory((void *)ptr, size, flags,
+					     KMSAN_POISON_CHECK);
+	kmsan_leave_runtime();
+}
+EXPORT_SYMBOL(kmsan_kmalloc_large);
+
+void kmsan_kfree_large(const void *ptr)
+{
+	struct page *page;
+
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+	kmsan_enter_runtime();
+	page = virt_to_head_page((void *)ptr);
+	KMSAN_WARN_ON(ptr != page_address(page));
+	kmsan_internal_poison_memory((void *)ptr,
+				     PAGE_SIZE << compound_order(page),
+				     GFP_KERNEL,
+				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
+	kmsan_leave_runtime();
+}
+EXPORT_SYMBOL(kmsan_kfree_large);
+
 static unsigned long vmalloc_shadow(unsigned long addr)
 {
 	return (unsigned long)kmsan_get_metadata((void *)addr,
diff --git a/mm/slab.h b/mm/slab.h
index db9fb5c8dae73..d0de8195873d8 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -752,6 +752,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
 			memset(p[i], 0, s->object_size);
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, flags);
+		kmsan_slab_alloc(s, p[i], flags);
 	}
 
 	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
diff --git a/mm/slub.c b/mm/slub.c
index b1281b8654bd3..b8b601f165087 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -22,6 +22,7 @@
 #include <linux/proc_fs.h>
 #include <linux/seq_file.h>
 #include <linux/kasan.h>
+#include <linux/kmsan.h>
 #include <linux/cpu.h>
 #include <linux/cpuset.h>
 #include <linux/mempolicy.h>
@@ -359,6 +360,17 @@ static void prefetch_freepointer(const struct kmem_cache *s, void *object)
 	prefetchw(object + s->offset);
 }
 
+/*
+ * When running under KMSAN, get_freepointer_safe() may return an uninitialized
+ * pointer value in the case the current thread loses the race for the next
+ * memory chunk in the freelist. In that case this_cpu_cmpxchg_double() in
+ * slab_alloc_node() will fail, so the uninitialized value won't be used, but
+ * KMSAN will still check all arguments of cmpxchg because of imperfect
+ * handling of inline assembly.
+ * To work around this problem, we apply __no_kmsan_checks to ensure that
+ * get_freepointer_safe() returns initialized memory.
+ */
+__no_kmsan_checks
 static inline void *get_freepointer_safe(struct kmem_cache *s, void *object)
 {
 	unsigned long freepointer_addr;
@@ -1709,6 +1721,7 @@ static inline void *kmalloc_large_node_hook(void *ptr, size_t size, gfp_t flags)
 	ptr = kasan_kmalloc_large(ptr, size, flags);
 	/* As ptr might get tagged, call kmemleak hook after KASAN. */
 	kmemleak_alloc(ptr, size, 1, flags);
+	kmsan_kmalloc_large(ptr, size, flags);
 	return ptr;
 }
 
@@ -1716,12 +1729,14 @@ static __always_inline void kfree_hook(void *x)
 {
 	kmemleak_free(x);
 	kasan_kfree_large(x);
+	kmsan_kfree_large(x);
 }
 
 static __always_inline bool slab_free_hook(struct kmem_cache *s,
 						void *x, bool init)
 {
 	kmemleak_free_recursive(x, s->flags);
+	kmsan_slab_free(s, x);
 
 	debug_check_no_locks_freed(x, s->object_size);
 
@@ -3756,6 +3771,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	 */
 	slab_post_alloc_hook(s, objcg, flags, size, p,
 				slab_want_init_on_alloc(flags, s));
+
 	return i;
 error:
 	slub_put_cpu_ptr(s->cpu_slab);
@@ -5939,6 +5955,7 @@ static char *create_unique_id(struct kmem_cache *s)
 	p += sprintf(p, "%07u", s->size);
 
 	BUG_ON(p > name + ID_STR_LENGTH - 1);
+	kmsan_unpoison_memory(name, p - name);
 	return name;
 }
 
@@ -6040,6 +6057,7 @@ static int sysfs_slab_alias(struct kmem_cache *s, const char *name)
 	al->name = name;
 	al->next = alias_list;
 	alias_list = al;
+	kmsan_unpoison_memory(al, sizeof(*al));
 	return 0;
 }
 
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-16-glider%40google.com.
