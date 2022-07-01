Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7EG7SKQMGQE7FFPGJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F881563515
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:23:57 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id k3-20020a2ea283000000b0025bcd580d43sf501856lja.2
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:23:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685437; cv=pass;
        d=google.com; s=arc-20160816;
        b=z4uflmZ4dh0yxm+CgNTK+iQgHnjUcfTmvo3zrR0BqYKGfIMG661p4AoELvtEyrpzF9
         O4ShxuwIFUuqCrXqh3aHgsipr3vGX5k5pqMMv40X3R7DxwMmPzuOSiGm4b80dmm0Vd4i
         Rw+AAnlztfvTf6EiQbM1M6Cb8W0t4RoJSY6DTdl/aXa2Qz64olGf7Ibi/rtLobbA8aQc
         hNiLOXkes92OK5m1HpFamOoifd4hRMQn0A4fFJq+ErUilrGdgLNyO5mDsgwgkWlMjuo1
         4E5WqvtwTC606Rr8dcaQ9IzHv4ELMtlKQnJz6FhGVVxKlE6xw0A/lEvSd6H9ogpR611r
         2DkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=+j/6iIrvLGRpre6sO+9EobAKTzrW+PLUZPoWQp9oYUA=;
        b=oDFUmA83st6uTmXyE1YFZji03yv1nlKvjxhHOUf/TVFsLcanblvZQ7BtrsuD5xNqaH
         AMW1eWDXrzEhYPM0hRX/Cl4aEBvQwy3jHtFZ5rau0MEI3iiQvof/0KNq1NkoIPc29IBz
         H9FLsYbaZraquobPqQQuvroEpQu/WvJWz2P79MVvexAdJVt0QTnOolHpaMsBZt0pyuZT
         hUpGHMmQccoI9ZLaNL2M1NU+WGvhYsZMCZ6sbBYeMO6VJxXjaurM6pecE674MSJvQUoc
         HoNEojBeS5cGRyVUCal4Q+hzVzD2p1RNazuUajAnqTuJwd4zYBXI8x2ki1NR6EJZwvm3
         rrIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pnk7oQtF;
       spf=pass (google.com: domain of 3ego_ygykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3egO_YgYKCZk9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+j/6iIrvLGRpre6sO+9EobAKTzrW+PLUZPoWQp9oYUA=;
        b=l31kxhYA8NGoHpEj4+iJGaid0Ur5kw9+ZEMXS01/s4Y+kyano7AjH2nKsxHylD70UY
         MIynW4HPN4z3U4Ls4OzKCtC0xlgCDL0JBOBI0f4NzTAYQtbP3FCr1qYdJvTPB73/pkN/
         VkUEKYQATZf3MIRc4R9aIJiKGciVQh7UQCQiB0DldUAhmdzGWHj5d50/pEHUUhRbD38Q
         eENAQ8IBFUVKqq0BUuctTdRylhtV3qbSrXgy+iM9HyuFtji8h5DCkZlqDmo7rCN7Xq1Z
         24EDys444Ib8eBRRm7P13BcDjlxSjcBu8l4J2Mal7yjLipf5EwgG1UmrJrBDD8fSm2K7
         UEZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+j/6iIrvLGRpre6sO+9EobAKTzrW+PLUZPoWQp9oYUA=;
        b=mTHlE6gbf7u8q6IUeFFFSii5rQY/je5jUCtJWq2MAnATrxA1iGpiC8OTiFGyvg3DTg
         mvW5vkQ81t9de9HuepexzEb5Hobv3aqM9DmqlITle0ESKgqoQRnhya3zofKvUbV/lRfU
         ojIHZ21k25Aqduw6lf/6uGfOVjMdoLojqLaFvpz6mS9W7icGyNWgEMx0oAkfc74F1ByZ
         Lkc0+dvmWy3IqwLywKBjJz3oKa/c9/xpzXvDIte7lg6basw8S/3m7JHrp5F92VMpGrKX
         cla+4ZNTzYLYtlWqLxLu4lpctcTYXwdcbxDldeyD4qMua08N/ncrW3jxMK4b/9FhK1W6
         cJcw==
X-Gm-Message-State: AJIora+CfGhl7JSVkSDQXWWLNuuXoZKVJeERv10QiAiTd0bWvWvm5vch
	mhb4t2TSLc/lhCLoOB9MG5I=
X-Google-Smtp-Source: AGRyM1tFkZjSGzlF1fsvbqLCJRSio11Ejpuz3LCJsbrQp4EvZDIya8vV+/+BzBnd4gBQmof2WjhWkA==
X-Received: by 2002:a05:6512:696:b0:47f:74f4:8f83 with SMTP id t22-20020a056512069600b0047f74f48f83mr10089197lfe.633.1656685437034;
        Fri, 01 Jul 2022 07:23:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls86864lfv.3.gmail; Fri, 01 Jul 2022
 07:23:55 -0700 (PDT)
X-Received: by 2002:a05:6512:3f14:b0:47d:e011:f19b with SMTP id y20-20020a0565123f1400b0047de011f19bmr8945149lfa.427.1656685435343;
        Fri, 01 Jul 2022 07:23:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685435; cv=none;
        d=google.com; s=arc-20160816;
        b=Z/SZTAVzC5wVFI/GfRCXTxncRSXmArvKpv62aDg/bEbSnNNPw9+t1WiCwnFfErFL8F
         dPIlcGll7IorQz6rLApDOxtWmPOXiQzpbTSc/WJksqjM6jdE3AMoa0HEaMHKb97fdpXg
         OlDYXr8CgGFpBK/6nR0V5uKULbvITrdsTQOkBleKOcJO45gxW12O7gt45aB0gy6fwQti
         Nbj8zn8zu/MtavvgynnLFfxtveCYxTTpdyL8ZY/PlgiGIlIZ2AHf6v4ba+ixmSzaBwLL
         JDTGdcSZs7vpII68BfXqo6h7YRj4jA2KSmF8cT7nXB+HAVnumq/O1NJPYqYCSbpVmIx2
         t5Tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=zch90Kb1PH444z16gANLEx2ctA8AD9SJjapQIjqFsi4=;
        b=VWX/VpUYxz/f8P56Xm4GQvq58Si3sFCx6+QytXYBTnSUxgrZia0JEZEat9E9MzkwpS
         IolPp8bvvC7AWvYAei0GK9bdcp0P0w6ZAk8yCOV6SKEhwyn82IcAE4xYTeolRy0r5GfK
         vIEgMDzIppoFAt55hGbN7Pt+6TIcheg12thOdCXyuWegH9FiasTkRFMNfJoecSYbIaoF
         IZAYtE0F9kIanAjRSqFnFZUL6qDoipbjgxrGKS24eJyJnLkhd6UqFnrtK8DD9HRZLPEK
         FW1LZZeNKinOQVDvFtQtdU6a2IrT4XUugSjHq8atrw6gWOIFKUCFJr9xY2pBaG3HNgKz
         mD2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pnk7oQtF;
       spf=pass (google.com: domain of 3ego_ygykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3egO_YgYKCZk9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id m7-20020a2e9107000000b0025594e68748si982160ljg.4.2022.07.01.07.23.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:23:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ego_ygykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id g7-20020a056402424700b00435ac9c7a8bso1876838edb.14
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:23:55 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a17:907:3f1d:b0:726:c927:769b with SMTP id
 hq29-20020a1709073f1d00b00726c927769bmr14568479ejc.754.1656685434644; Fri, 01
 Jul 2022 07:23:54 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:39 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-15-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 14/45] mm: kmsan: maintain KMSAN metadata for page operations
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
 header.i=@google.com header.s=20210112 header.b=pnk7oQtF;       spf=pass
 (google.com: domain of 3ego_ygykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3egO_YgYKCZk9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
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

v4:
 -- change sizeof(type) to sizeof(*ptr)
 -- replace occurrences of |var| with @var
 -- swap mm: and kmsan: in the subject
 -- drop __no_sanitize_memory from clear_page()

Link: https://linux-review.googlesource.com/id/I6d4f53a0e7eab46fa29f0348f3095d9f2e326850
---
 arch/x86/include/asm/page_64.h |  12 ++++
 arch/x86/mm/ioremap.c          |   3 +
 include/linux/highmem.h        |   3 +
 include/linux/kmsan.h          | 123 +++++++++++++++++++++++++++++++++
 mm/internal.h                  |   6 ++
 mm/kmsan/hooks.c               |  87 +++++++++++++++++++++++
 mm/kmsan/shadow.c              | 114 ++++++++++++++++++++++++++++++
 mm/memory.c                    |   2 +
 mm/page_alloc.c                |  11 +++
 mm/vmalloc.c                   |  20 +++++-
 10 files changed, 379 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/page_64.h b/arch/x86/include/asm/page_64.h
index baa70451b8df5..227dd33eb4efb 100644
--- a/arch/x86/include/asm/page_64.h
+++ b/arch/x86/include/asm/page_64.h
@@ -45,14 +45,26 @@ void clear_page_orig(void *page);
 void clear_page_rep(void *page);
 void clear_page_erms(void *page);
 
+/* This is an assembly header, avoid including too much of kmsan.h */
+#ifdef CONFIG_KMSAN
+void kmsan_unpoison_memory(const void *addr, size_t size);
+#endif
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
index 1ad0228f8ceb9..78c5bc654cff5 100644
--- a/arch/x86/mm/ioremap.c
+++ b/arch/x86/mm/ioremap.c
@@ -17,6 +17,7 @@
 #include <linux/cc_platform.h>
 #include <linux/efi.h>
 #include <linux/pgtable.h>
+#include <linux/kmsan.h>
 
 #include <asm/set_memory.h>
 #include <asm/e820/api.h>
@@ -479,6 +480,8 @@ void iounmap(volatile void __iomem *addr)
 		return;
 	}
 
+	kmsan_iounmap_page_range((unsigned long)addr,
+		(unsigned long)addr + get_vm_area_size(p));
 	memtype_free(p->phys_addr, p->phys_addr + get_vm_area_size(p));
 
 	/* Finally remove it */
diff --git a/include/linux/highmem.h b/include/linux/highmem.h
index 3af34de54330c..ae82c5aefb018 100644
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
@@ -302,6 +303,7 @@ static inline void copy_user_highpage(struct page *to, struct page *from,
 	vfrom = kmap_local_page(from);
 	vto = kmap_local_page(to);
 	copy_user_page(vto, vfrom, vaddr, to);
+	kmsan_unpoison_memory(page_address(to), PAGE_SIZE);
 	kunmap_local(vto);
 	kunmap_local(vfrom);
 }
@@ -317,6 +319,7 @@ static inline void copy_highpage(struct page *to, struct page *from)
 	vfrom = kmap_local_page(from);
 	vto = kmap_local_page(to);
 	copy_page(vto, vfrom);
+	kmsan_copy_page_meta(to, from);
 	kunmap_local(vto);
 	kunmap_local(vfrom);
 }
diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 99e48c6b049d9..699fe4f5b3bee 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -41,6 +41,129 @@ struct kmsan_ctx {
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
index c0f8fbe0445b5..dccdba2ac4ecf 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -847,8 +847,14 @@ int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
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
index e5ad2972d7362..416cb85487a1a 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -145,3 +145,117 @@ void *kmsan_get_metadata(void *address, bool is_origin)
 
 	return (is_origin ? origin_ptr_for(page) : shadow_ptr_for(page)) + off;
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
+	 * to just fill the origin pages with @handle.
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
+	s_pages = kcalloc(nr, sizeof(*s_pages), GFP_KERNEL);
+	o_pages = kcalloc(nr, sizeof(*o_pages), GFP_KERNEL);
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
index 7a089145cad4b..947349399e05c 100644
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
@@ -3120,6 +3121,7 @@ static vm_fault_t wp_page_copy(struct vm_fault *vmf)
 			delayacct_wpcopy_end();
 			return 0;
 		}
+		kmsan_copy_page_meta(new_page, old_page);
 	}
 
 	if (mem_cgroup_charge(page_folio(new_page), mm, GFP_KERNEL))
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index e008a3df0485c..785459251145e 100644
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
@@ -1320,6 +1321,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	VM_BUG_ON_PAGE(PageTail(page), page);
 
 	trace_mm_page_free(page, order);
+	kmsan_free_page(page, order);
 
 	if (unlikely(PageHWPoison(page)) && !order) {
 		/*
@@ -3711,6 +3713,14 @@ static struct page *rmqueue_pcplist(struct zone *preferred_zone,
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
@@ -5446,6 +5456,7 @@ struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
 	}
 
 	trace_mm_page_alloc(page, order, alloc_gfp, ac.migratetype);
+	kmsan_alloc_page(page, order, alloc_gfp);
 
 	return page;
 }
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index effd1ff6a4b41..6973d7f1ef934 100644
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
 
@@ -416,7 +419,7 @@ static void vunmap_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end,
  *
  * This is an internal function only. Do not use outside mm/.
  */
-void vunmap_range_noflush(unsigned long start, unsigned long end)
+void __vunmap_range_noflush(unsigned long start, unsigned long end)
 {
 	unsigned long next;
 	pgd_t *pgd;
@@ -438,6 +441,12 @@ void vunmap_range_noflush(unsigned long start, unsigned long end)
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-15-glider%40google.com.
