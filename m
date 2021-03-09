Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJHOTWBAMGQETQEGKCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id ADDB0332700
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:24:52 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id o8sf5654136ljp.15
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:24:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615296292; cv=pass;
        d=google.com; s=arc-20160816;
        b=VKOeADsw/vDqh4Q/eZX8g02eM+D9UrTiUf+3SPzPQYg8pAnb629K+yirvmpkjv7Y5W
         +1ZiBcf2SqJOMwxFmX1ZYofdhfWw3yOZD0sFZQ+nNZW/ZbO+lQTP7ZsWC65+nYdVkrEy
         eUJmFIEBd9gDzG/E8FYrainUkPxhIA4KJVhSZO73yKeIdii5xo3NHIunCHzTT5YjCnMb
         PbDoMMfC1tpAHdvdNL3vFOe0eA9x0UAdEAis5LM6Le+B98vbyKopvOzNwGZ4ngtnGPQg
         MM9QxkTOILVXFiDNNEdYbUC/Kgd0PCId+z39F7d9k19a2gawF4yR1RPmYDJDc9G/9Ucr
         K7qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=N6Xx7haqNlfQPO7UYqi55WE4MFScrheTY1+jIbSlZOQ=;
        b=lXmShSW8jfjKrG8JfObRkH3rVO9hYvFKmrYa4O5gcv+S7GMgpMra64RvI76JjeJ1Ke
         Pv3SmUuEvFlgPehi2zYGesvcTgAvM9CZVZP1arTGzyr0xyqc2FNn4sFgixd7pqU5ABVA
         113xYJbKovbDA33GKd8bzdjVb1s0XI1DfU6ddikcXTeVim1NroKm6k2vGMI6ckTlcgIy
         Ma5Pd3UVRkJyCbopl24+Uz2BaVn7ydjhJeA/oeWEDRFX/uvW0e8wZnGEI7GHwaCduJGU
         LS8JlGtn8WeG7MNCE7iHaiCdmOXh0SIvEMUhUYkjIYFOl2mXLrGpysnPAFH74XUShbjg
         4tMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gzJBIzAY;
       spf=pass (google.com: domain of 3indhyaokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3IndHYAoKCTcTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N6Xx7haqNlfQPO7UYqi55WE4MFScrheTY1+jIbSlZOQ=;
        b=Keg2w0DPxI+x0CE8VBdizIuGQIAC7LdkJTpMFDuZc7v4MxwuOt1W+Ph7VpF21lMKaT
         g7n73TaN8UkaugbzPxKgqthXZqFynchWQhqQv3huWwfXoyf3wTLuECrgLzefVADACFHU
         I/uk034EPME1505H/qo4AAddMK5b+71lg9gXMijwHgVTggxv2Tke5OC/nucSh0NkcPiv
         ngAgYsedGSFsFkv263t/q4ZVxLkb0CELHAoHikwmewcTVrfNE4/iHOOTyRDWEkA+OJtI
         bU+qvCpnyvde9wcDETCZCJUCDHzW9/Da1UpVsvfGNWuKJtdMG67nuvMtbjiAPojsVYDf
         VRrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N6Xx7haqNlfQPO7UYqi55WE4MFScrheTY1+jIbSlZOQ=;
        b=NKaWV9GAtyEc6qvL3aJBQe/tVDu3z39Ogr3QBWXIfK9pdKzWzW9NuEa5exS4nLts1u
         SByJkpjVjNcAi0hW4cRUk0DPPCNPbHaKbqBjfkaCXo/6oy5jDJN4POAdO4eXw6iJkLn0
         HV/Ux1ULFQnq0Nvr1ScN6qjUaXUzeVKpA+FpTNUXCuyKlgfZkg6rVMRcXEL/tvj0E39Q
         Jx2YUpHK6VsGJh6UGYeYjWuFAZ8zC7Z1G+s4IQwKEEdRrMrUGE4WMc3kaP3DObcWArmy
         sFUFSWLYPY6dRmfr+DxXZald7i/HwCoPdKz9b/2WlHrzMG5hhgabI7ZliMTXfsuF9ETT
         vRmA==
X-Gm-Message-State: AOAM532J4MN/K2kZmEBMv7m+NOPrds0Ou+8bAOMibhgMU/k5gGtRcVAj
	QqMcVF+Zc4z3V9K4cf8cG5g=
X-Google-Smtp-Source: ABdhPJxm6IFqs1QwykY6TjXreZPjzNEF/A2QorW5WtXMK5u3uUyYpiisBwbn7q1/tAFmdVoqTwWA5g==
X-Received: by 2002:a19:607:: with SMTP id 7mr18244211lfg.433.1615296292274;
        Tue, 09 Mar 2021 05:24:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6d4:: with SMTP id u20ls3800108lff.1.gmail; Tue, 09
 Mar 2021 05:24:51 -0800 (PST)
X-Received: by 2002:a05:6512:398d:: with SMTP id j13mr17085588lfu.41.1615296291213;
        Tue, 09 Mar 2021 05:24:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615296291; cv=none;
        d=google.com; s=arc-20160816;
        b=RkSJR44ORxgPxXoyvsNQgiK6ksmivziEJbR4WpKfT8s+jC89ZZHAGPjhX8XDJ4pztH
         rkElFznYb2tO1Wd8M3Jdltl4EAEDkKOtmWzgoqnaWKXFdUkWgDTtakg/QosDyhiRkFZc
         RUFigUxVpGcpAfhqslL4NHWkvB0z1KYj56OmlEjSm/IwSRVpIZ6lWyOvyQ5TbKSH1CiA
         LCFNH589aq7p8XIX7oDrq6cLH957cJAWTPncSRSd8bqrrzzsLo83JwJV2NNbFXRdPhkg
         rL5LcX4bhXkW6D45H0gw+C8INeKBnhJT9/hksWVblcbFYpBNIeZmAkKRyStaGnSBqeIa
         Xsdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=c/p2Irv0oGLny+pAqsKq0iE2bCIU3zeaZM7JLSHPDFk=;
        b=Th1wQt1GPOg/ErOi8MlD+rv1Kx8OC+6brP0XBjzwc9MTLKoIASt20u+2M66wFr1p88
         zLL7BcxkRIXZ9/fveSJUVviZCxj+r1ezFJhEqe/RTvye62Bk/D5Tk72sMN9sM5l86MXL
         0ZcPUU6QJe7vt/W/HpPUNctBY0O/8KXtbrp6P7j54vrpeO15lxMrjxcPTjJ9nKnwfg5D
         MjE6MPpOcfoLuPHX+Qv7fQYU8NRClXAkr0T2m/t7MlY2aPU27Fk2qKanTb7Hlbn/QOQ2
         /gx5fwQQ3VTZqtDlC/Q6V7Gy+qt8F+9ug6jsJ/4S8ZFlUFc78mkFaSCeIfNYVY7B0ZIX
         v/DA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gzJBIzAY;
       spf=pass (google.com: domain of 3indhyaokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3IndHYAoKCTcTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 63si365640lfd.1.2021.03.09.05.24.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:24:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 3indhyaokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id l10so6429102wry.16
        for <kasan-dev@googlegroups.com>; Tue, 09 Mar 2021 05:24:51 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:5802:818:ce92:dfef])
 (user=andreyknvl job=sendgmr) by 2002:a1c:6243:: with SMTP id
 w64mr565189wmb.0.1615296290069; Tue, 09 Mar 2021 05:24:50 -0800 (PST)
Date: Tue,  9 Mar 2021 14:24:37 +0100
In-Reply-To: <cover.1615296150.git.andreyknvl@google.com>
Message-Id: <e77f0d5b1b20658ef0b8288625c74c2b3690e725.1615296150.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1615296150.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH v3 3/5] kasan, mm: integrate page_alloc init with HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gzJBIzAY;       spf=pass
 (google.com: domain of 3indhyaokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3IndHYAoKCTcTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This change uses the previously added memory initialization feature
of HW_TAGS KASAN routines for page_alloc memory when init_on_alloc/free
is enabled.

With this change, kernel_init_free_pages() is no longer called when
both HW_TAGS KASAN and init_on_alloc/free are enabled. Instead, memory
is initialized in KASAN runtime.

To avoid discrepancies with which memory gets initialized that can be
caused by future changes, both KASAN and kernel_init_free_pages() hooks
are put together and a warning comment is added.

This patch changes the order in which memory initialization and page
poisoning hooks are called. This doesn't lead to any side-effects, as
whenever page poisoning is enabled, memory initialization gets disabled.

Combining setting allocation tags with memory initialization improves
HW_TAGS KASAN performance when init_on_alloc/free is enabled.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 30 ++++++++++++++++++++++--------
 mm/kasan/common.c     |  8 ++++----
 mm/mempool.c          |  4 ++--
 mm/page_alloc.c       | 37 ++++++++++++++++++++++++++-----------
 4 files changed, 54 insertions(+), 25 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 1d89b8175027..c89613caa8cf 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -96,6 +96,11 @@ static __always_inline bool kasan_enabled(void)
 	return static_branch_likely(&kasan_flag_enabled);
 }
 
+static inline bool kasan_has_integrated_init(void)
+{
+	return kasan_enabled();
+}
+
 #else /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_enabled(void)
@@ -103,6 +108,11 @@ static inline bool kasan_enabled(void)
 	return true;
 }
 
+static inline bool kasan_has_integrated_init(void)
+{
+	return false;
+}
+
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 slab_flags_t __kasan_never_merge(void);
@@ -120,20 +130,20 @@ static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
 		__kasan_unpoison_range(addr, size);
 }
 
-void __kasan_alloc_pages(struct page *page, unsigned int order);
+void __kasan_alloc_pages(struct page *page, unsigned int order, bool init);
 static __always_inline void kasan_alloc_pages(struct page *page,
-						unsigned int order)
+						unsigned int order, bool init)
 {
 	if (kasan_enabled())
-		__kasan_alloc_pages(page, order);
+		__kasan_alloc_pages(page, order, init);
 }
 
-void __kasan_free_pages(struct page *page, unsigned int order);
+void __kasan_free_pages(struct page *page, unsigned int order, bool init);
 static __always_inline void kasan_free_pages(struct page *page,
-						unsigned int order)
+						unsigned int order, bool init)
 {
 	if (kasan_enabled())
-		__kasan_free_pages(page, order);
+		__kasan_free_pages(page, order, init);
 }
 
 void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
@@ -277,13 +287,17 @@ static inline bool kasan_enabled(void)
 {
 	return false;
 }
+static inline bool kasan_has_integrated_init(void)
+{
+	return false;
+}
 static inline slab_flags_t kasan_never_merge(void)
 {
 	return 0;
 }
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
-static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
-static inline void kasan_free_pages(struct page *page, unsigned int order) {}
+static inline void kasan_alloc_pages(struct page *page, unsigned int order, bool init) {}
+static inline void kasan_free_pages(struct page *page, unsigned int order, bool init) {}
 static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
 				      slab_flags_t *flags) {}
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 316f7f8cd8e6..6107c795611f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -97,7 +97,7 @@ slab_flags_t __kasan_never_merge(void)
 	return 0;
 }
 
-void __kasan_alloc_pages(struct page *page, unsigned int order)
+void __kasan_alloc_pages(struct page *page, unsigned int order, bool init)
 {
 	u8 tag;
 	unsigned long i;
@@ -108,14 +108,14 @@ void __kasan_alloc_pages(struct page *page, unsigned int order)
 	tag = kasan_random_tag();
 	for (i = 0; i < (1 << order); i++)
 		page_kasan_tag_set(page + i, tag);
-	kasan_unpoison(page_address(page), PAGE_SIZE << order, false);
+	kasan_unpoison(page_address(page), PAGE_SIZE << order, init);
 }
 
-void __kasan_free_pages(struct page *page, unsigned int order)
+void __kasan_free_pages(struct page *page, unsigned int order, bool init)
 {
 	if (likely(!PageHighMem(page)))
 		kasan_poison(page_address(page), PAGE_SIZE << order,
-			     KASAN_FREE_PAGE, false);
+			     KASAN_FREE_PAGE, init);
 }
 
 /*
diff --git a/mm/mempool.c b/mm/mempool.c
index 79959fac27d7..fe19d290a301 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -106,7 +106,7 @@ static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
 		kasan_slab_free_mempool(element);
 	else if (pool->alloc == mempool_alloc_pages)
-		kasan_free_pages(element, (unsigned long)pool->pool_data);
+		kasan_free_pages(element, (unsigned long)pool->pool_data, false);
 }
 
 static void kasan_unpoison_element(mempool_t *pool, void *element)
@@ -114,7 +114,7 @@ static void kasan_unpoison_element(mempool_t *pool, void *element)
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
 		kasan_unpoison_range(element, __ksize(element));
 	else if (pool->alloc == mempool_alloc_pages)
-		kasan_alloc_pages(element, (unsigned long)pool->pool_data);
+		kasan_alloc_pages(element, (unsigned long)pool->pool_data, false);
 }
 
 static __always_inline void add_element(mempool_t *pool, void *element)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 0efb07b5907c..aba9cd673eac 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -396,14 +396,14 @@ static DEFINE_STATIC_KEY_TRUE(deferred_pages);
  * initialization is done, but this is not likely to happen.
  */
 static inline void kasan_free_nondeferred_pages(struct page *page, int order,
-							fpi_t fpi_flags)
+						bool init, fpi_t fpi_flags)
 {
 	if (static_branch_unlikely(&deferred_pages))
 		return;
 	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
 			(fpi_flags & FPI_SKIP_KASAN_POISON))
 		return;
-	kasan_free_pages(page, order);
+	kasan_free_pages(page, order, init);
 }
 
 /* Returns true if the struct page for the pfn is uninitialised */
@@ -455,12 +455,12 @@ defer_init(int nid, unsigned long pfn, unsigned long end_pfn)
 }
 #else
 static inline void kasan_free_nondeferred_pages(struct page *page, int order,
-							fpi_t fpi_flags)
+						bool init, fpi_t fpi_flags)
 {
 	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
 			(fpi_flags & FPI_SKIP_KASAN_POISON))
 		return;
-	kasan_free_pages(page, order);
+	kasan_free_pages(page, order, init);
 }
 
 static inline bool early_page_uninitialised(unsigned long pfn)
@@ -1242,6 +1242,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 			unsigned int order, bool check_free, fpi_t fpi_flags)
 {
 	int bad = 0;
+	bool init;
 
 	VM_BUG_ON_PAGE(PageTail(page), page);
 
@@ -1299,16 +1300,21 @@ static __always_inline bool free_pages_prepare(struct page *page,
 		debug_check_no_obj_freed(page_address(page),
 					   PAGE_SIZE << order);
 	}
-	if (want_init_on_free())
-		kernel_init_free_pages(page, 1 << order);
 
 	kernel_poison_pages(page, 1 << order);
 
 	/*
+	 * As memory initialization might be integrated into KASAN,
+	 * kasan_free_pages and kernel_init_free_pages must be
+	 * kept together to avoid discrepancies in behavior.
+	 *
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
-	kasan_free_nondeferred_pages(page, order, fpi_flags);
+	init = want_init_on_free();
+	if (init && !kasan_has_integrated_init())
+		kernel_init_free_pages(page, 1 << order);
+	kasan_free_nondeferred_pages(page, order, init, fpi_flags);
 
 	/*
 	 * arch_free_page() can make the page's contents inaccessible.  s390
@@ -2315,17 +2321,26 @@ static bool check_new_pages(struct page *page, unsigned int order)
 inline void post_alloc_hook(struct page *page, unsigned int order,
 				gfp_t gfp_flags)
 {
+	bool init;
+
 	set_page_private(page, 0);
 	set_page_refcounted(page);
 
 	arch_alloc_page(page, order);
 	debug_pagealloc_map_pages(page, 1 << order);
-	kasan_alloc_pages(page, order);
-	kernel_unpoison_pages(page, 1 << order);
-	set_page_owner(page, order, gfp_flags);
 
-	if (!want_init_on_free() && want_init_on_alloc(gfp_flags))
+	/*
+	 * As memory initialization might be integrated into KASAN,
+	 * kasan_alloc_pages and kernel_init_free_pages must be
+	 * kept together to avoid discrepancies in behavior.
+	 */
+	init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
+	kasan_alloc_pages(page, order, init);
+	if (init && !kasan_has_integrated_init())
 		kernel_init_free_pages(page, 1 << order);
+
+	kernel_unpoison_pages(page, 1 << order);
+	set_page_owner(page, order, gfp_flags);
 }
 
 static void prep_new_page(struct page *page, unsigned int order, gfp_t gfp_flags,
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e77f0d5b1b20658ef0b8288625c74c2b3690e725.1615296150.git.andreyknvl%40google.com.
