Return-Path: <kasan-dev+bncBCCMH5WKTMGRBBOEUOMAMGQE3VZV4GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D12F5A2A68
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:08:54 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id h21-20020a2e9ed5000000b0025d516572f4sf658185ljk.12
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:08:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526534; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZU9x4Z2Vc17sOvSERg/G7scZ3E90tQo4MyFHeELap4/7KD/O6rOL/bOS448lXUi01M
         8h7LvM79hbBKuMfBuULjvEh8OkNtaaKUtJ9FIOgD1ZfVi/lQPhUlwFzHSZHBRqiJ6ztX
         4tG8X0PDEY1s95YLSDYaZlvjvzBxD4pszcBg53BTLdV/nM8JvW03BGFPR5vpTgRsrJrC
         qNdSHBvFD6DqkNdfLnJIiBIX4HNmJAJNOBaBIRQgg279dNau3Gmmzt9bmdsumrVaElar
         jWzHq24SospMK0OtaKUL1jZm92Hiy7Ft/5ty4OaixZ6yLJUYK4ZrHhbmHZ4e1UBFRezG
         9biA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=IEioKj4dDDYFcyYSUkwYKuoTABVQ76ig7H4uCdCJ7cQ=;
        b=LhxHpRRMKrGFPMPkkoyXpDKZUbc6ltNqrUX4rp8wHWRD50tiSxRmAJtjcS76Laeji9
         Jh/nQ80TLO09Ie5DlVvWwn2ef6SxEp1ftU63x3YjDbMtLK/t2ndU9P0Z14f7LC6cmRt6
         ANB4Gu05Im3RpMSgQS+OsTuBXcNmAD+0FlLdegCmCKceJ9Lf/lIM/EAcbiURmWn59BZd
         8H8dJGGeB3plyjmHVItWcy0Hk0IoHPuUI+aXjVrydFNV3gUToaGk33VD7YIa8WVvL2i5
         KyBsRL7ELmmJ/RpqP+EuzoGajgF2ePFHiJb6FXkRMuVyedMZEIeQad0CsP882WX/Jihb
         bxzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DoBVgTeG;
       spf=pass (google.com: domain of 3boiiywykcqsrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3BOIIYwYKCQsrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=IEioKj4dDDYFcyYSUkwYKuoTABVQ76ig7H4uCdCJ7cQ=;
        b=dJ4cWrUbb7pEUT/8R8G16lGyMl3tu4yyn4LGzzc52bti05hGnmy3IMxy3kBZRRt9bZ
         gMkACS5xm6TVrUqgoawThxBrpqGPkwUgin3upJUbPG22vj6W8VXlzvrMr8/fZzgIGgwS
         usu7sP6yYJg1AdUNV4ksUhuvHCZ5mDC41CLZ/POhxEnSP97IcmraWniJ/pKsVV0AAVeG
         0ylEINl0u9WqsXRen/mQQfnaAveqkP3y5C/LmYjBM+UH71IHsxqdbOW8QnwlLI40sMc+
         OXqeGyAnQpMOopqonko/roOO3ASHTzB6RchMbalnWt/n87zOfqud3t8KICtXpn296AXC
         AKOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=IEioKj4dDDYFcyYSUkwYKuoTABVQ76ig7H4uCdCJ7cQ=;
        b=TY67lZncBm8nsWi7W9xPHVrSn4hC7SItNrdWdrTd+nkG4YFr4HECPwy+xLH++VkZDb
         QfoD8jL5FZTKKfyYpORgGC+ReFdn2hAnCfsemNxXdFCYAwIE47v15z+ocqqW6bHFBmg0
         HaZjYfIQqS9AcMFyqhVXNOeHJqKcaxXc8o8N7WQjgq9Xr0+thNT6bndCXC99SiQJTExf
         EQmv7eSxpMjDZsTekpDVnYm2bxjiW/R/x+I/LDr98wPTToWGaqAmoVOEyVi/Thkaic97
         8gmayJy/ixr30f6BhWMLk2dn+Hp2pUd0uD0aEhmnivna8DFhwxVFoTWyCK6mVU0pFoIu
         jv1Q==
X-Gm-Message-State: ACgBeo0+4vaiWGY8qA7GPl81+lqg0PcF78g4UzRaZPb5J3EHSyq1dc31
	00HwqOu4rbYUT/Vbo+0uDrs=
X-Google-Smtp-Source: AA6agR4w6aXE1ftMWOqlyWXSvnuxakRh3tcTLqvugK+AhR0vbmBGz/SUyOQTi1v81GsQRRgcoKdmhQ==
X-Received: by 2002:a2e:9b95:0:b0:261:df1e:118b with SMTP id z21-20020a2e9b95000000b00261df1e118bmr2493392lji.470.1661526533903;
        Fri, 26 Aug 2022 08:08:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:238d:b0:25d:9c9e:d165 with SMTP id
 bk13-20020a05651c238d00b0025d9c9ed165ls708096ljb.7.-pod-prod-gmail; Fri, 26
 Aug 2022 08:08:52 -0700 (PDT)
X-Received: by 2002:a2e:300b:0:b0:261:b068:c287 with SMTP id w11-20020a2e300b000000b00261b068c287mr2624070ljw.458.1661526532607;
        Fri, 26 Aug 2022 08:08:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526532; cv=none;
        d=google.com; s=arc-20160816;
        b=OzcX/E51b5DmbmrDMhPfERJ9i2Vsm/AruZsnQuhmo4Qsb+DQFmQ4aJPJFl5SrDYLM9
         1rhEFcgbNyCIHeOWt9WTi7Dnq4lostI/++M4SbQgBcT++GTpa65GSuWvVjywjL6YGCFD
         PLMoN1aXsikeioUsxJKo3ZMBg70RZ0afCW5Aw0izVQO1JVLuwpXdBFlx+DXmcmXmJ7lr
         WQ7+Ka3/Gtay9Wj8BFZCyx6CBup+6QRGXYmvArOO+wJOqekat6iyXcYTmjgVCjAV1MAu
         pFqKByFPryyKVu+DKuqo08Adjy1lismwKhWag0q8U8/R3YpMTkM1kpWWc7Z1uDTjhxcN
         nH9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=RCEJUrdGaZnDzkCVeq8BsOQ2VOxKVJNx7oe/faTwpqA=;
        b=hSS/ba5spTgrdNo90dHSc+7jpfmOS/BOcCeHpxTRhrp8wg4RK2TGzAiFPAZ+A3HJFf
         /FpBw9pN7++I22jMEvDoSslKa8YLrnv1SeQc2Ah3WmdUcoDbgaqfdYVkfZCzvYia4o2q
         VpR+uZ42J55sj4/XY7C8s9P8/NIIBI2K6hipGP755YC4BLWcfOTGhmb87N6KKvGyDzen
         hLzhhQ/2HWSyFMcYGoda+hdvGLJg6Sp/HjirhAU7PRNa5is7+slVqi8YdpSiT4h5x+rT
         Ei2oXruspD4NStI0CIP/XdWrW5LSGkqpugeGdJcGzvYnP9NrXnj4O9svHo+eHe1QH2o6
         XimQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DoBVgTeG;
       spf=pass (google.com: domain of 3boiiywykcqsrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3BOIIYwYKCQsrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id s1-20020a056512202100b0048b0f16f43dsi69368lfs.7.2022.08.26.08.08.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:08:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3boiiywykcqsrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id he38-20020a1709073da600b0073d98728570so727471ejc.11
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:08:52 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a17:906:cc15:b0:73d:d87f:f039 with SMTP id
 ml21-20020a170906cc1500b0073dd87ff039mr4286773ejb.253.1661526532079; Fri, 26
 Aug 2022 08:08:52 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:37 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-15-glider@google.com>
Subject: [PATCH v5 14/44] mm: kmsan: maintain KMSAN metadata for page operations
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
 header.i=@google.com header.s=20210112 header.b=DoBVgTeG;       spf=pass
 (google.com: domain of 3boiiywykcqsrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3BOIIYwYKCQsrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com;
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

v5:
 -- do not export KMSAN hooks that are not called from modules
 -- use modern style for-loops
 -- simplify clear_page() instrumentation as suggested by Marco Elver
 -- move forward declaration of `struct page` in kmsan.h to this patch

Link: https://linux-review.googlesource.com/id/I6d4f53a0e7eab46fa29f0348f3095d9f2e326850
---
 arch/x86/include/asm/page_64.h |   7 ++
 arch/x86/mm/ioremap.c          |   3 +
 include/linux/highmem.h        |   3 +
 include/linux/kmsan.h          | 125 +++++++++++++++++++++++++++++++++
 mm/internal.h                  |   6 ++
 mm/kmsan/hooks.c               |  85 ++++++++++++++++++++++
 mm/kmsan/shadow.c              | 113 +++++++++++++++++++++++++++++
 mm/memory.c                    |   2 +
 mm/page_alloc.c                |  11 +++
 mm/vmalloc.c                   |  20 +++++-
 10 files changed, 373 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/page_64.h b/arch/x86/include/asm/page_64.h
index baa70451b8df5..198e03e59ca19 100644
--- a/arch/x86/include/asm/page_64.h
+++ b/arch/x86/include/asm/page_64.h
@@ -8,6 +8,8 @@
 #include <asm/cpufeatures.h>
 #include <asm/alternative.h>
 
+#include <linux/kmsan-checks.h>
+
 /* duplicated to the one in bootmem.h */
 extern unsigned long max_pfn;
 extern unsigned long phys_base;
@@ -47,6 +49,11 @@ void clear_page_erms(void *page);
 
 static inline void clear_page(void *page)
 {
+	/*
+	 * Clean up KMSAN metadata for the page being cleared. The assembly call
+	 * below clobbers @page, so we perform unpoisoning before it.
+	 */
+	kmsan_unpoison_memory(page, PAGE_SIZE);
 	alternative_call_2(clear_page_orig,
 			   clear_page_rep, X86_FEATURE_REP_GOOD,
 			   clear_page_erms, X86_FEATURE_ERMS,
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
index 25679035ca283..e9912da5441b4 100644
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
@@ -311,6 +312,7 @@ static inline void copy_user_highpage(struct page *to, struct page *from,
 	vfrom = kmap_local_page(from);
 	vto = kmap_local_page(to);
 	copy_user_page(vto, vfrom, vaddr, to);
+	kmsan_unpoison_memory(page_address(to), PAGE_SIZE);
 	kunmap_local(vto);
 	kunmap_local(vfrom);
 }
@@ -326,6 +328,7 @@ static inline void copy_highpage(struct page *to, struct page *from)
 	vfrom = kmap_local_page(from);
 	vto = kmap_local_page(to);
 	copy_page(vto, vfrom);
+	kmsan_copy_page_meta(to, from);
 	kunmap_local(vto);
 	kunmap_local(vfrom);
 }
diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index e578c9627b641..699fe4f5b3bee 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -14,6 +14,8 @@
 #include <linux/stackdepot.h>
 #include <linux/types.h>
 
+struct page;
+
 #ifdef CONFIG_KMSAN
 
 /* These constants are defined in the MSan LLVM instrumentation pass. */
@@ -39,6 +41,129 @@ struct kmsan_ctx {
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
index 785409805ed79..fd7247a2367ed 100644
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
index 4ac62fa67a02a..2624b4ea3d8ef 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -26,6 +26,91 @@
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
+	int nr;
+
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+
+	nr = (end - start) / PAGE_SIZE;
+	kmsan_enter_runtime();
+	for (int i = 0; i < nr; i++, off += PAGE_SIZE) {
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
+
+void kmsan_iounmap_page_range(unsigned long start, unsigned long end)
+{
+	unsigned long v_shadow, v_origin;
+	struct page *shadow, *origin;
+	int nr;
+
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+
+	nr = (end - start) / PAGE_SIZE;
+	kmsan_enter_runtime();
+	v_shadow = (unsigned long)vmalloc_shadow(start);
+	v_origin = (unsigned long)vmalloc_origin(start);
+	for (int i = 0; i < nr;
+	     i++, v_shadow += PAGE_SIZE, v_origin += PAGE_SIZE) {
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
+
 /* Functions from kmsan-checks.h follow. */
 void kmsan_poison_memory(const void *address, size_t size, gfp_t flags)
 {
diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index acc5279acc3be..8c81a059beea6 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -145,3 +145,116 @@ void *kmsan_get_metadata(void *address, bool is_origin)
 
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
+	for (int i = 0; i < PAGE_SIZE * pages / sizeof(handle); i++)
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
+	int nr, mapped;
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
+	for (int i = 0; i < nr; i++) {
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
index 4ba73f5aa8bb7..6cc35d2cae8fd 100644
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
@@ -3128,6 +3129,7 @@ static vm_fault_t wp_page_copy(struct vm_fault *vmf)
 			delayacct_wpcopy_end();
 			return 0;
 		}
+		kmsan_copy_page_meta(new_page, old_page);
 	}
 
 	if (mem_cgroup_charge(page_folio(new_page), mm, GFP_KERNEL))
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index e5486d47406e8..d488dab76a6e8 100644
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
@@ -1398,6 +1399,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 	VM_BUG_ON_PAGE(PageTail(page), page);
 
 	trace_mm_page_free(page, order);
+	kmsan_free_page(page, order);
 
 	if (unlikely(PageHWPoison(page)) && !order) {
 		/*
@@ -3817,6 +3819,14 @@ static struct page *rmqueue_pcplist(struct zone *preferred_zone,
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
@@ -5535,6 +5545,7 @@ struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
 	}
 
 	trace_mm_page_alloc(page, order, alloc_gfp, ac.migratetype);
+	kmsan_alloc_page(page, order, alloc_gfp);
 
 	return page;
 }
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index dd6cdb2011953..68b656e0125c9 100644
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-15-glider%40google.com.
