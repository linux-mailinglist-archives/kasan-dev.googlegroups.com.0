Return-Path: <kasan-dev+bncBCCMH5WKTMGRBD6DUCJQMGQEZNI2DMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F1615103F1
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:04 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id z35-20020a0565120c2300b004721f8a4e37sf736905lfu.20
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991504; cv=pass;
        d=google.com; s=arc-20160816;
        b=ovsgU7M0NsQCFf0n9n2+nfTJJ7MzXjgZsaUQlsf7y6w2oQ4ktIKbE1iUXT0psPt4kQ
         oI26VuqfkxyXskD8nZTTP+e/nmHIDNwaB8QgU64G68mJ8BVG8/1t5S1+fiG/qE1HPH94
         11X7RkYQvHkEB/bCIw81Z8HBN/7+TbD8F6zpSekNHFNK7z7i39f9UTa4xG8TkIedzX32
         oqAnl3OcIiAXYlc26ns3GsEha5tijeYlVYVePh6axI7WSmiCJcr/creFUQhXKC7xEkuO
         P+3LJCHrZ0TDZCGxZ9N7qfoVwkDfkLdkvL0SpOPci48XsSq6YFE/kPvNZX+oWyFBKKvv
         tBnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ZelSwsiLPOmLupuG6YbDLib/zGNYbapC1/zDcZmYEj8=;
        b=Z4R5pLD7qNrPMBirSekTxUFxLRB0JBrfOq2KBkzm+wUDcA24rieWK//TReJuZ4MmH3
         jM1Mh8TmzmfppDEkPs4csGkyNXOEYMlclfSWf52JNRkjqM9dVQzIov1YZEvKAX1tzzcB
         NjTYOD6XN8dlsuk9QyfKASaVQsMEpOg8w/m0ZrSgDHtVSZrye/FHCtoJjSIGQQ2JqASH
         fBfOOdiO1m6csGdNlxbBqlo3zTaMaL+SMmn85dM45ztPEv/keJCFkiTCpWb+Nnc8Klrk
         of0SvBwu55esyWqP8wBmdtVcpjHRGc+KSKyMdZp8+QEtzjeX/3tgt1WBHzn9M6hYg9eK
         vx9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=M78kkNEB;
       spf=pass (google.com: domain of 3jifoygykcysv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3jiFoYgYKCYsv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZelSwsiLPOmLupuG6YbDLib/zGNYbapC1/zDcZmYEj8=;
        b=KXjmNnIvj4pQzaTAaN7bGG7eYjHMlhhqkOXKdI1sHr80fodEjljcqpa0c/IzxGpQjx
         zwt/OI4TasQG5cBtBgMNPq6KvPQsdeDrm2gUa7pvQ9PeIvgWvm7J1Q/omcM8wKAv52qH
         ppzXaikgEqfCCgjugM0xqvyRjrIabW/czr+7OpYcPvGyM1FhmiAZJP+zpcIdsz9frIlD
         uENwhv7TU+/BaIYntrm77Ci1B5kzG3HVTFNWuSj3/B1IpmYNSfa+iT7LsQ+soaIVyvBE
         PLboosbBniUzhal84HUcA5797fRjgZFcG6kE3wtytnXtDsLdvqzR+gCZogLshewBnmf3
         jEag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZelSwsiLPOmLupuG6YbDLib/zGNYbapC1/zDcZmYEj8=;
        b=RaTEkVme+lkmG67eSGFX7tKjk5q3FLzeGLbPPlr/jaceD6TCB1sYBG9IJ71buXq5un
         wFdz6dfRBNhyf0rdXQamYCfCnqBb3voUIkx0makSzrEGvS53FVOZ2V9nYTirjmvvidlt
         FLOCsul5E+OSnwT/b1on86wsyjziT9CZfUz5bP+9tT7eZPKQyhf6k26Drv/ChKl0SS4h
         1jaK5W78idi2aNp4ZHSX+4cqaj8frGfm4rjsBOse05Dv0F3tITW2oHOVOZK/qso5taHZ
         fG068TG1SaEDMVNn1mtdTG9S0zC5/TLxJURl4Z0R9jifIeC2+Ud+NylQX4ihaQJtYgvj
         CrKg==
X-Gm-Message-State: AOAM533Jdv/W/fRD71b7Ch581U10BT6VE0C6P5EeaQD+VSN01jEEYFuF
	vQMzcq79KmljpN9vfAaIN14=
X-Google-Smtp-Source: ABdhPJyEJQFXKbqmkDCkbg1C2C7Wk2KOgbtMCqNRWPZhi8Z1BJmxKm95MHxil9w1yjdFQxai3/5ljg==
X-Received: by 2002:a05:6512:3ed:b0:472:3d9:7bdd with SMTP id n13-20020a05651203ed00b0047203d97bddmr8509963lfq.111.1650991504014;
        Tue, 26 Apr 2022 09:45:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:17a4:b0:24d:5627:cbb7 with SMTP id
 bn36-20020a05651c17a400b0024d5627cbb7ls2133480ljb.0.gmail; Tue, 26 Apr 2022
 09:45:02 -0700 (PDT)
X-Received: by 2002:a2e:a816:0:b0:24d:9cd2:2d0a with SMTP id l22-20020a2ea816000000b0024d9cd22d0amr14637478ljq.26.1650991502863;
        Tue, 26 Apr 2022 09:45:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991502; cv=none;
        d=google.com; s=arc-20160816;
        b=KlhfObkBhrXeY22rwjcKK8K3Ko/CcKbvnDsPc1Kh64rPqbUNxgaceloulNmw80Ymsa
         rj1kz8IoxESrm+pO2dpJ+Fm2IxtQLQuXdD3TlRzVDAGN8SYyZ4WLFgjBpmzAONbDaqZi
         STfC3vFQut7o55sVI76E/1kOWhx0Vjn4wSs1pyaP6ACwym6zwEdugNpLNaBvDM5CY+AN
         ZwRBHbksWkfMpff3ruGam3SW7L+vPJlHFwngwlNSPIlO8fgryhBwBWts+ZQM1zosc81H
         g5mnmTEzrSLrxGq+E3vs+pOj0/O2QadBvR2FidGQLuYgiBcrb1EcdJcmJ5ycersWN8qE
         oUYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=xJ2BmwZfS9U11w9738T9IIYSomxf8dgaSR2dg4ENYSM=;
        b=oZWdzqcANzFZxbUQa/BJNpTtatLPXwwNvEBNo4xMU1vwf86JS3CpUpBEEidjOQJLSZ
         9LiFfIkhWgPSTAJd6KNEMLPJouiY3s9+YZItt0GPdPJkm6qOEdtz4JNZCLL156mBdGnW
         jAN/Acx75k8jnmuMOtCZU6IZvnpbLkLZVgrZJHn0bv5PvTMfkKi4na1OOsGddIbGAidT
         P31W80i8Qn3KFchaSHr6bK+PRcM4hhFAwoUKCxds2pI/LvJ0kiz0hsA8apYJgK+/s3Qf
         fr2bQZ5N0qR2rgkU42gtUr5298ZdwhawdX+VcpBg637Ho2dwSkabA+3lotN6PyVza0m6
         AZQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=M78kkNEB;
       spf=pass (google.com: domain of 3jifoygykcysv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3jiFoYgYKCYsv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id o3-20020a056512230300b00471902f5be2si866919lfu.3.2022.04.26.09.45.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jifoygykcysv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id jg25-20020a170907971900b006f010192c19so8621597ejc.21
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:02 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a17:906:4787:b0:6f3:7e2a:ebfd with SMTP id
 cw7-20020a170906478700b006f37e2aebfdmr14388383ejc.243.1650991502331; Tue, 26
 Apr 2022 09:45:02 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:45 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-17-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 16/46] kmsan: mm: maintain KMSAN metadata for page operations
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=M78kkNEB;       spf=pass
 (google.com: domain of 3jifoygykcysv0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3jiFoYgYKCYsv0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
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

Insert KMSAN hooks that make the necessary bookkeeping changes:
 - poison page shadow and origins in alloc_pages()/free_page();
 - clear page shadow and origins in clear_page(), copy_user_highpage();
 - copy page metadata in copy_highpage(), wp_page_copy();
 - handle vmap()/vunmap()/iounmap();

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 -- move page metadata hooks implementation here
 -- remove call to kmsan_memblock_free_pages()

v3:
 -- use PAGE_SHIFT in kmsan_ioremap_page_range()

Link: https://linux-review.googlesource.com/id/I6d4f53a0e7eab46fa29f0348f3095d9f2e326850
---
 arch/x86/include/asm/page_64.h |  13 ++++
 arch/x86/mm/ioremap.c          |   3 +
 include/linux/highmem.h        |   3 +
 include/linux/kmsan.h          | 123 +++++++++++++++++++++++++++++++++
 mm/internal.h                  |   6 ++
 mm/kmsan/hooks.c               |  87 +++++++++++++++++++++++
 mm/kmsan/shadow.c              | 114 ++++++++++++++++++++++++++++++
 mm/memory.c                    |   2 +
 mm/page_alloc.c                |  11 +++
 mm/vmalloc.c                   |  20 +++++-
 10 files changed, 380 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/page_64.h b/arch/x86/include/asm/page_64.h
index e9c86299b8351..36e270a8ea9a4 100644
--- a/arch/x86/include/asm/page_64.h
+++ b/arch/x86/include/asm/page_64.h
@@ -45,14 +45,27 @@ void clear_page_orig(void *page);
 void clear_page_rep(void *page);
 void clear_page_erms(void *page);
 
+/* This is an assembly header, avoid including too much of kmsan.h */
+#ifdef CONFIG_KMSAN
+void kmsan_unpoison_memory(const void *addr, size_t size);
+#endif
+__no_sanitize_memory
 static inline void clear_page(void *page)
 {
+#ifdef CONFIG_KMSAN
+	/* alternative_call_2() changes @page. */
+	void *page_copy = page;
+#endif
 	alternative_call_2(clear_page_orig,
 			   clear_page_rep, X86_FEATURE_REP_GOOD,
 			   clear_page_erms, X86_FEATURE_ERMS,
 			   "=D" (page),
 			   "0" (page)
 			   : "cc", "memory", "rax", "rcx");
+#ifdef CONFIG_KMSAN
+	/* Clear KMSAN shadow for the pages that have it. */
+	kmsan_unpoison_memory(page_copy, PAGE_SIZE);
+#endif
 }
 
 void copy_page(void *to, void *from);
diff --git a/arch/x86/mm/ioremap.c b/arch/x86/mm/ioremap.c
index 17a492c273069..0da8608778221 100644
--- a/arch/x86/mm/ioremap.c
+++ b/arch/x86/mm/ioremap.c
@@ -17,6 +17,7 @@
 #include <linux/cc_platform.h>
 #include <linux/efi.h>
 #include <linux/pgtable.h>
+#include <linux/kmsan.h>
 
 #include <asm/set_memory.h>
 #include <asm/e820/api.h>
@@ -474,6 +475,8 @@ void iounmap(volatile void __iomem *addr)
 		return;
 	}
 
+	kmsan_iounmap_page_range((unsigned long)addr,
+		(unsigned long)addr + get_vm_area_size(p));
 	memtype_free(p->phys_addr, p->phys_addr + get_vm_area_size(p));
 
 	/* Finally remove it */
diff --git a/include/linux/highmem.h b/include/linux/highmem.h
index 39bb9b47fa9cd..3e1898a44d7e3 100644
--- a/include/linux/highmem.h
+++ b/include/linux/highmem.h
@@ -6,6 +6,7 @@
 #include <linux/kernel.h>
 #include <linux/bug.h>
 #include <linux/cacheflush.h>
+#include <linux/kmsan.h>
 #include <linux/mm.h>
 #include <linux/uaccess.h>
 #include <linux/hardirq.h>
@@ -277,6 +278,7 @@ static inline void copy_user_highpage(struct page *to, struct page *from,
 	vfrom = kmap_local_page(from);
 	vto = kmap_local_page(to);
 	copy_user_page(vto, vfrom, vaddr, to);
+	kmsan_unpoison_memory(page_address(to), PAGE_SIZE);
 	kunmap_local(vto);
 	kunmap_local(vfrom);
 }
@@ -292,6 +294,7 @@ static inline void copy_highpage(struct page *to, struct page *from)
 	vfrom = kmap_local_page(from);
 	vto = kmap_local_page(to);
 	copy_page(vto, vfrom);
+	kmsan_copy_page_meta(to, from);
 	kunmap_local(vto);
 	kunmap_local(vfrom);
 }
diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 4e35f43eceaa9..da41850b46cbd 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -42,6 +42,129 @@ struct kmsan_ctx {
 	bool allow_reporting;
 };
 
+/**
+ * kmsan_alloc_page() - Notify KMSAN about an alloc_pages() call.
+ * @page:  struct page pointer returned by alloc_pages().
+ * @order: order of allocated struct page.
+ * @flags: GFP flags used by alloc_pages()
+ *
+ * KMSAN marks 1<<@order pages starting at @page as uninitialized, unless
+ * @flags contain __GFP_ZERO.
+ */
+void kmsan_alloc_page(struct page *page, unsigned int order, gfp_t flags);
+
+/**
+ * kmsan_free_page() - Notify KMSAN about a free_pages() call.
+ * @page:  struct page pointer passed to free_pages().
+ * @order: order of deallocated struct page.
+ *
+ * KMSAN marks freed memory as uninitialized.
+ */
+void kmsan_free_page(struct page *page, unsigned int order);
+
+/**
+ * kmsan_copy_page_meta() - Copy KMSAN metadata between two pages.
+ * @dst: destination page.
+ * @src: source page.
+ *
+ * KMSAN copies the contents of metadata pages for @src into the metadata pages
+ * for @dst. If @dst has no associated metadata pages, nothing happens.
+ * If @src has no associated metadata pages, @dst metadata pages are unpoisoned.
+ */
+void kmsan_copy_page_meta(struct page *dst, struct page *src);
+
+/**
+ * kmsan_map_kernel_range_noflush() - Notify KMSAN about a vmap.
+ * @start:	start of vmapped range.
+ * @end:	end of vmapped range.
+ * @prot:	page protection flags used for vmap.
+ * @pages:	array of pages.
+ * @page_shift:	page_shift passed to vmap_range_noflush().
+ *
+ * KMSAN maps shadow and origin pages of @pages into contiguous ranges in
+ * vmalloc metadata address range.
+ */
+void kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
+				    pgprot_t prot, struct page **pages,
+				    unsigned int page_shift);
+
+/**
+ * kmsan_vunmap_kernel_range_noflush() - Notify KMSAN about a vunmap.
+ * @start: start of vunmapped range.
+ * @end:   end of vunmapped range.
+ *
+ * KMSAN unmaps the contiguous metadata ranges created by
+ * kmsan_map_kernel_range_noflush().
+ */
+void kmsan_vunmap_range_noflush(unsigned long start, unsigned long end);
+
+/**
+ * kmsan_ioremap_page_range() - Notify KMSAN about a ioremap_page_range() call.
+ * @addr:	range start.
+ * @end:	range end.
+ * @phys_addr:	physical range start.
+ * @prot:	page protection flags used for ioremap_page_range().
+ * @page_shift:	page_shift argument passed to vmap_range_noflush().
+ *
+ * KMSAN creates new metadata pages for the physical pages mapped into the
+ * virtual memory.
+ */
+void kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
+			      phys_addr_t phys_addr, pgprot_t prot,
+			      unsigned int page_shift);
+
+/**
+ * kmsan_iounmap_page_range() - Notify KMSAN about a iounmap_page_range() call.
+ * @start: range start.
+ * @end:   range end.
+ *
+ * KMSAN unmaps the metadata pages for the given range and, unlike for
+ * vunmap_page_range(), also deallocates them.
+ */
+void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
+
+#else
+
+static inline int kmsan_alloc_page(struct page *page, unsigned int order,
+				   gfp_t flags)
+{
+	return 0;
+}
+
+static inline void kmsan_free_page(struct page *page, unsigned int order)
+{
+}
+
+static inline void kmsan_copy_page_meta(struct page *dst, struct page *src)
+{
+}
+
+static inline void kmsan_vmap_pages_range_noflush(unsigned long start,
+						  unsigned long end,
+						  pgprot_t prot,
+						  struct page **pages,
+						  unsigned int page_shift)
+{
+}
+
+static inline void kmsan_vunmap_range_noflush(unsigned long start,
+					      unsigned long end)
+{
+}
+
+static inline void kmsan_ioremap_page_range(unsigned long start,
+					    unsigned long end,
+					    phys_addr_t phys_addr,
+					    pgprot_t prot,
+					    unsigned int page_shift)
+{
+}
+
+static inline void kmsan_iounmap_page_range(unsigned long start,
+					    unsigned long end)
+{
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
diff --git a/mm/internal.h b/mm/internal.h
index cf16280ce1321..3cf6fde8f02c4 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -744,8 +744,14 @@ int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
 }
 #endif
 
+int __vmap_pages_range_noflush(unsigned long addr, unsigned long end,
+			       pgprot_t prot, struct page **pages,
+			       unsigned int page_shift);
+
 void vunmap_range_noflush(unsigned long start, unsigned long end);
 
+void __vunmap_range_noflush(unsigned long start, unsigned long end);
+
 int numa_migrate_prep(struct page *page, struct vm_area_struct *vma,
 		      unsigned long addr, int page_nid, int *flags);
 
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 4ac62fa67a02a..070756be70e3a 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -26,6 +26,93 @@
  * skipping effects of functions like memset() inside instrumented code.
  */
 
+static unsigned long vmalloc_shadow(unsigned long addr)
+{
+	return (unsigned long)kmsan_get_metadata((void *)addr,
+						 KMSAN_META_SHADOW);
+}
+
+static unsigned long vmalloc_origin(unsigned long addr)
+{
+	return (unsigned long)kmsan_get_metadata((void *)addr,
+						 KMSAN_META_ORIGIN);
+}
+
+void kmsan_vunmap_range_noflush(unsigned long start, unsigned long end)
+{
+	__vunmap_range_noflush(vmalloc_shadow(start), vmalloc_shadow(end));
+	__vunmap_range_noflush(vmalloc_origin(start), vmalloc_origin(end));
+	flush_cache_vmap(vmalloc_shadow(start), vmalloc_shadow(end));
+	flush_cache_vmap(vmalloc_origin(start), vmalloc_origin(end));
+}
+EXPORT_SYMBOL(kmsan_vunmap_range_noflush);
+
+/*
+ * This function creates new shadow/origin pages for the physical pages mapped
+ * into the virtual memory. If those physical pages already had shadow/origin,
+ * those are ignored.
+ */
+void kmsan_ioremap_page_range(unsigned long start, unsigned long end,
+			      phys_addr_t phys_addr, pgprot_t prot,
+			      unsigned int page_shift)
+{
+	gfp_t gfp_mask = GFP_KERNEL | __GFP_ZERO;
+	struct page *shadow, *origin;
+	unsigned long off = 0;
+	int i, nr;
+
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+
+	nr = (end - start) / PAGE_SIZE;
+	kmsan_enter_runtime();
+	for (i = 0; i < nr; i++, off += PAGE_SIZE) {
+		shadow = alloc_pages(gfp_mask, 1);
+		origin = alloc_pages(gfp_mask, 1);
+		__vmap_pages_range_noflush(
+			vmalloc_shadow(start + off),
+			vmalloc_shadow(start + off + PAGE_SIZE), prot, &shadow,
+			PAGE_SHIFT);
+		__vmap_pages_range_noflush(
+			vmalloc_origin(start + off),
+			vmalloc_origin(start + off + PAGE_SIZE), prot, &origin,
+			PAGE_SHIFT);
+	}
+	flush_cache_vmap(vmalloc_shadow(start), vmalloc_shadow(end));
+	flush_cache_vmap(vmalloc_origin(start), vmalloc_origin(end));
+	kmsan_leave_runtime();
+}
+EXPORT_SYMBOL(kmsan_ioremap_page_range);
+
+void kmsan_iounmap_page_range(unsigned long start, unsigned long end)
+{
+	unsigned long v_shadow, v_origin;
+	struct page *shadow, *origin;
+	int i, nr;
+
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+
+	nr = (end - start) / PAGE_SIZE;
+	kmsan_enter_runtime();
+	v_shadow = (unsigned long)vmalloc_shadow(start);
+	v_origin = (unsigned long)vmalloc_origin(start);
+	for (i = 0; i < nr; i++, v_shadow += PAGE_SIZE, v_origin += PAGE_SIZE) {
+		shadow = kmsan_vmalloc_to_page_or_null((void *)v_shadow);
+		origin = kmsan_vmalloc_to_page_or_null((void *)v_origin);
+		__vunmap_range_noflush(v_shadow, vmalloc_shadow(end));
+		__vunmap_range_noflush(v_origin, vmalloc_origin(end));
+		if (shadow)
+			__free_pages(shadow, 1);
+		if (origin)
+			__free_pages(origin, 1);
+	}
+	flush_cache_vmap(vmalloc_shadow(start), vmalloc_shadow(end));
+	flush_cache_vmap(vmalloc_origin(start), vmalloc_origin(end));
+	kmsan_leave_runtime();
+}
+EXPORT_SYMBOL(kmsan_iounmap_page_range);
+
 /* Functions from kmsan-checks.h follow. */
 void kmsan_poison_memory(const void *address, size_t size, gfp_t flags)
 {
diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index de58cfbc55b9d..8fe6a5ed05e67 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -184,3 +184,117 @@ void *kmsan_get_metadata(void *address, bool is_origin)
 	ret = (is_origin ? origin_ptr_for(page) : shadow_ptr_for(page)) + off;
 	return ret;
 }
+
+void kmsan_copy_page_meta(struct page *dst, struct page *src)
+{
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+	if (!dst || !page_has_metadata(dst))
+		return;
+	if (!src || !page_has_metadata(src)) {
+		kmsan_internal_unpoison_memory(page_address(dst), PAGE_SIZE,
+					       /*checked*/ false);
+		return;
+	}
+
+	kmsan_enter_runtime();
+	__memcpy(shadow_ptr_for(dst), shadow_ptr_for(src), PAGE_SIZE);
+	__memcpy(origin_ptr_for(dst), origin_ptr_for(src), PAGE_SIZE);
+	kmsan_leave_runtime();
+}
+
+void kmsan_alloc_page(struct page *page, unsigned int order, gfp_t flags)
+{
+	bool initialized = (flags & __GFP_ZERO) || !kmsan_enabled;
+	struct page *shadow, *origin;
+	depot_stack_handle_t handle;
+	int pages = 1 << order;
+	int i;
+
+	if (!page)
+		return;
+
+	shadow = shadow_page_for(page);
+	origin = origin_page_for(page);
+
+	if (initialized) {
+		__memset(page_address(shadow), 0, PAGE_SIZE * pages);
+		__memset(page_address(origin), 0, PAGE_SIZE * pages);
+		return;
+	}
+
+	/* Zero pages allocated by the runtime should also be initialized. */
+	if (kmsan_in_runtime())
+		return;
+
+	__memset(page_address(shadow), -1, PAGE_SIZE * pages);
+	kmsan_enter_runtime();
+	handle = kmsan_save_stack_with_flags(flags, /*extra_bits*/ 0);
+	kmsan_leave_runtime();
+	/*
+	 * Addresses are page-aligned, pages are contiguous, so it's ok
+	 * to just fill the origin pages with |handle|.
+	 */
+	for (i = 0; i < PAGE_SIZE * pages / sizeof(handle); i++)
+		((depot_stack_handle_t *)page_address(origin))[i] = handle;
+}
+
+void kmsan_free_page(struct page *page, unsigned int order)
+{
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+	kmsan_enter_runtime();
+	kmsan_internal_poison_memory(page_address(page),
+				     PAGE_SIZE << compound_order(page),
+				     GFP_KERNEL,
+				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
+	kmsan_leave_runtime();
+}
+
+void kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
+				    pgprot_t prot, struct page **pages,
+				    unsigned int page_shift)
+{
+	unsigned long shadow_start, origin_start, shadow_end, origin_end;
+	struct page **s_pages, **o_pages;
+	int nr, i, mapped;
+
+	if (!kmsan_enabled)
+		return;
+
+	shadow_start = vmalloc_meta((void *)start, KMSAN_META_SHADOW);
+	shadow_end = vmalloc_meta((void *)end, KMSAN_META_SHADOW);
+	if (!shadow_start)
+		return;
+
+	nr = (end - start) / PAGE_SIZE;
+	s_pages = kcalloc(nr, sizeof(struct page *), GFP_KERNEL);
+	o_pages = kcalloc(nr, sizeof(struct page *), GFP_KERNEL);
+	if (!s_pages || !o_pages)
+		goto ret;
+	for (i = 0; i < nr; i++) {
+		s_pages[i] = shadow_page_for(pages[i]);
+		o_pages[i] = origin_page_for(pages[i]);
+	}
+	prot = __pgprot(pgprot_val(prot) | _PAGE_NX);
+	prot = PAGE_KERNEL;
+
+	origin_start = vmalloc_meta((void *)start, KMSAN_META_ORIGIN);
+	origin_end = vmalloc_meta((void *)end, KMSAN_META_ORIGIN);
+	kmsan_enter_runtime();
+	mapped = __vmap_pages_range_noflush(shadow_start, shadow_end, prot,
+					    s_pages, page_shift);
+	KMSAN_WARN_ON(mapped);
+	mapped = __vmap_pages_range_noflush(origin_start, origin_end, prot,
+					    o_pages, page_shift);
+	KMSAN_WARN_ON(mapped);
+	kmsan_leave_runtime();
+	flush_tlb_kernel_range(shadow_start, shadow_end);
+	flush_tlb_kernel_range(origin_start, origin_end);
+	flush_cache_vmap(shadow_start, shadow_end);
+	flush_cache_vmap(origin_start, origin_end);
+
+ret:
+	kfree(s_pages);
+	kfree(o_pages);
+}
diff --git a/mm/memory.c b/mm/memory.c
index 76e3af9639d93..04aa68acffeb3 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -52,6 +52,7 @@
 #include <linux/highmem.h>
 #include <linux/pagemap.h>
 #include <linux/memremap.h>
+#include <linux/kmsan.h>
 #include <linux/ksm.h>
 #include <linux/rmap.h>
 #include <linux/export.h>
@@ -3032,6 +3033,7 @@ static vm_fault_t wp_page_copy(struct vm_fault *vmf)
 				put_page(old_page);
 			return 0;
 		}
+		kmsan_copy_page_meta(new_page, old_page);
 	}
 
 	if (mem_cgroup_charge(page_folio(new_page), mm, GFP_KERNEL))
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 0e42038382c12..98393e01e4259 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -27,6 +27,7 @@
 #include <linux/compiler.h>
 #include <linux/kernel.h>
 #include <linux/kasan.h>
+#include <linux/kmsan.h>
 #include <linux/module.h>
 #include <linux/suspend.h>
 #include <linux/pagevec.h>
@@ -1305,6 +1306,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	VM_BUG_ON_PAGE(PageTail(page), page);
 
 	trace_mm_page_free(page, order);
+	kmsan_free_page(page, order);
 
 	if (unlikely(PageHWPoison(page)) && !order) {
 		/*
@@ -3696,6 +3698,14 @@ static struct page *rmqueue_pcplist(struct zone *preferred_zone,
 /*
  * Allocate a page from the given zone. Use pcplists for order-0 allocations.
  */
+
+/*
+ * Do not instrument rmqueue() with KMSAN. This function may call
+ * __msan_poison_alloca() through a call to set_pfnblock_flags_mask().
+ * If __msan_poison_alloca() attempts to allocate pages for the stack depot, it
+ * may call rmqueue() again, which will result in a deadlock.
+ */
+__no_sanitize_memory
 static inline
 struct page *rmqueue(struct zone *preferred_zone,
 			struct zone *zone, unsigned int order,
@@ -5428,6 +5438,7 @@ struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
 	}
 
 	trace_mm_page_alloc(page, order, alloc_gfp, ac.migratetype);
+	kmsan_alloc_page(page, order, alloc_gfp);
 
 	return page;
 }
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index cadfbb5155ea5..76a54007e5142 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -320,6 +320,9 @@ int ioremap_page_range(unsigned long addr, unsigned long end,
 	err = vmap_range_noflush(addr, end, phys_addr, pgprot_nx(prot),
 				 ioremap_max_page_shift);
 	flush_cache_vmap(addr, end);
+	if (!err)
+		kmsan_ioremap_page_range(addr, end, phys_addr, prot,
+					 ioremap_max_page_shift);
 	return err;
 }
 
@@ -419,7 +422,7 @@ static void vunmap_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end,
  *
  * This is an internal function only. Do not use outside mm/.
  */
-void vunmap_range_noflush(unsigned long start, unsigned long end)
+void __vunmap_range_noflush(unsigned long start, unsigned long end)
 {
 	unsigned long next;
 	pgd_t *pgd;
@@ -441,6 +444,12 @@ void vunmap_range_noflush(unsigned long start, unsigned long end)
 		arch_sync_kernel_mappings(start, end);
 }
 
+void vunmap_range_noflush(unsigned long start, unsigned long end)
+{
+	kmsan_vunmap_range_noflush(start, end);
+	__vunmap_range_noflush(start, end);
+}
+
 /**
  * vunmap_range - unmap kernel virtual addresses
  * @addr: start of the VM area to unmap
@@ -575,7 +584,7 @@ static int vmap_small_pages_range_noflush(unsigned long addr, unsigned long end,
  *
  * This is an internal function only. Do not use outside mm/.
  */
-int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
+int __vmap_pages_range_noflush(unsigned long addr, unsigned long end,
 		pgprot_t prot, struct page **pages, unsigned int page_shift)
 {
 	unsigned int i, nr = (end - addr) >> PAGE_SHIFT;
@@ -601,6 +610,13 @@ int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
 	return 0;
 }
 
+int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
+		pgprot_t prot, struct page **pages, unsigned int page_shift)
+{
+	kmsan_vmap_pages_range_noflush(addr, end, prot, pages, page_shift);
+	return __vmap_pages_range_noflush(addr, end, prot, pages, page_shift);
+}
+
 /**
  * vmap_pages_range - map pages to a kernel virtual address
  * @addr: start of the VM area to map
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-17-glider%40google.com.
