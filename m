Return-Path: <kasan-dev+bncBDX4HWEMTEBRBP4NXT6QKGQEVRB6VGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 04B332B2844
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:48 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id b68sf5560508edf.9
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306047; cv=pass;
        d=google.com; s=arc-20160816;
        b=dfs23ifI2qReJkReJCIh0/2T9cQJX5G1+yh2enX+mVI0uGo3dZ7HVkfTFuTiYGAiqq
         r6XhR6jJNK9G1binHaw+Bz17ZfNU8i9c/K8sJB8STAQU2oFp2C9iIFfyLke4Vh9odneI
         GaO/aT9quivzQU1c4iL9DXYzQ4cN688SrnBqLRB/MFFE4fRaA+neoR1FhfxBygwzRDIz
         ALRRL53nT86Co8bPVVBSgW4X4mRNDpja49vYSfNrffaE68WnsXBS32dVkf7ZuJUG2F9Z
         8RINujn9RjV38JmRpkuRGaQRldRkcdsPKfvXIm39Di+STMxq8w3wBu+akXEFNPDkTQ1h
         TLvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=otoHvbX0aCax31f8P7xWhFDBwe3CY19zlK6NpD7YAQA=;
        b=chcOPKaDSUC0M8l0i7JSjgvuWf5k2ip+OkSlAY7oWrIly1U7FNKVBbFyAM9YkCidDL
         n9fqnDLfe+AaLfjPjheGQq/zplmf61V/9fb2OfgTKig4U6ZVl4qrkZySjXN5+SeJbvIi
         2zAzgaWNhwNj5JjUw6RirvU8iufm2BV9knsirfBAgCK8A74asfKdqW8So7EMIZtUBjTc
         ksbDmIrx2kLRlUQi2k5B2jreOcMth8ueCtQwcr6j/pJYcjcxBtFApCVFDGztFwaibJuc
         dESlfyMplc18XMCPxZhfBncfNfI2e+DdlMGpFaStwYPDONjHsXnQ+W7YjA4FaergQxE9
         WVTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nHk4m8fI;
       spf=pass (google.com: domain of 3vgavxwokcysp2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3vgavXwoKCYsp2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=otoHvbX0aCax31f8P7xWhFDBwe3CY19zlK6NpD7YAQA=;
        b=LYjGxJjxunecxPUpCjVT1euWjvZe1xVZ9aFiZZ7xupkCzdj8Y/Zs+Gg3nBdX0/UBhR
         2Ezh3wpaksrpP/I4VY3j9RttVe9ZvXHuhRDb3ZDbxFo+7Y4kmwdUTowKTGJhXAxz9ejo
         cAri9HnWWZrcIhpfLo72TKsvreGIyYCGCl3dsE5kYU/mHQT89hgegjcXM2tnK/HwSk7Q
         6m1tFRUmGbfdbWB5KfzNTRQDlfnTKI5qmm2l7M3A4tgCCWFxw3booFKyRZi5MMgQfcUg
         BIVcd+98DjjO1htOjOWiYkVjVDPnEjVNKkElEkQAH8X1cxrd9aAboZ8jQRThPKdtA9oV
         gtZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=otoHvbX0aCax31f8P7xWhFDBwe3CY19zlK6NpD7YAQA=;
        b=lqmcw9XTmo+VLXbnCmekzbv2YtWUaJykkwIrrDQ+IwQ0M1hWJBWSp4coMeg/qKyX6l
         J+0lF1y9s1kYYSPlerkVVeN2l+6mSvhlox1VxcCIMMVyUeuH0Oe5nlRGsCCVe9te08uN
         VVl/TPuQR9j1SOQjlQJDnaN1VOsOqwkHJkpoi5svkWptvOsvfkX/3FAzBAeWRdTBirQY
         cL4oWEL4fuyLQzB87dFlU99hq7o2tTlnG/ljSEUnnnrvhHrA4VR7Ld8gGWYMgkBX7v0I
         sxu/dfjp3EAtsjax596IgDYcHUAEeFivg/J9oEExJ0vA2XHmmTP5s6mr9GsIx+wxlR1P
         44/g==
X-Gm-Message-State: AOAM532htTUdwAtrVWOWDrldpxreuy3DD7EtvWYjJnk1Wsw+0/1XABsl
	u248JK1h74WXXNCnzg1sXQQ=
X-Google-Smtp-Source: ABdhPJxldUwj+mdGxF1VEjR7Ry3IRF1dHeJ4qAI91M7hWwx5lvptE1YbhzzhN8VBHcL1Gu4EyMrTRA==
X-Received: by 2002:a05:6402:6d6:: with SMTP id n22mr4986628edy.82.1605306047800;
        Fri, 13 Nov 2020 14:20:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:cc8b:: with SMTP id p11ls484504edt.3.gmail; Fri, 13 Nov
 2020 14:20:46 -0800 (PST)
X-Received: by 2002:a05:6402:142f:: with SMTP id c15mr4936209edx.33.1605306046918;
        Fri, 13 Nov 2020 14:20:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306046; cv=none;
        d=google.com; s=arc-20160816;
        b=TH/uAvfx9vGurKeo0fBa4DuBCQkcyIrLscck+WXUMHcU5PTQ3Ac9XCqFRJMbO6TX8b
         cAA1GfI8MGXmWzqF/FdLG1lxgkp6Baw3i/ZFr/ktXHzXqk5pmoohFTCvjSxvmQwqdf4N
         xs5Z7h22Q+/AKypRhodvgMH6fy3mu+11yaVE9HxsLFZDoZ8R3lRpef88EZvLpzScPkSM
         YxEXgDH2EqgoZy1EtxthP/gwgqmXk3qb0s8YI/kc4LHVzsxgBkJrE1Im938gnM+w+OCy
         sL21Vxjm4sGU0UFj348TiK10If0GZMxvk2fdMB8WedX6YUNeoboDZQI4cWsJ5HGP+eFh
         q8PA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=2KLolIFhijPlCk9+fyMngQmrLJRsQkhazwFij5lYkks=;
        b=nNwBklXInl72DfZxjtj2Wr8D/xR9FNXlTNQv1Y6vcn2BWmBbEYTCmyXeOAPiuUdMzT
         zTn4tDUmrK6bcZ/7oCQrbjQtRbW4JvijZ7AVpTK6R1wG+3JsZqcvBYq1ZddifKccUFcI
         2HJO1dnMmaoGOW/Rewm6j1cmjSY4x7dYUOn4hwxrPy11siYcMBoIR46IMDca3lKfPvCs
         jw6vogMTJuM1kv/TXCkf9zOhAJI10bnje4DHzuR+/UL4q1kbcLUDH76o0ScP6UG5iMol
         Dn/GJyU1oEt/GT8QxmqoaORmr6ATcYcdt55uF79LR/UDo9DptUz8NaB7rhZSPR8qggki
         xHLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nHk4m8fI;
       spf=pass (google.com: domain of 3vgavxwokcysp2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3vgavXwoKCYsp2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id v7si552879edj.5.2020.11.13.14.20.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vgavxwokcysp2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id p16so4697394wrx.4
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:46 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:3d6:: with SMTP id
 205mr4665784wmd.85.1605306046610; Fri, 13 Nov 2020 14:20:46 -0800 (PST)
Date: Fri, 13 Nov 2020 23:20:03 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <798e1753fafb37151213a0ad0b1b2f08f66c3877.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 13/19] kasan, mm: rename kasan_poison_kfree
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nHk4m8fI;       spf=pass
 (google.com: domain of 3vgavxwokcysp2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3vgavXwoKCYsp2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
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

Rename kasan_poison_kfree() to kasan_slab_free_mempool() as it better
reflects what this annotation does. Also add a comment that explains the
PageSlab() check.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I5026f87364e556b506ef1baee725144bb04b8810
---
 include/linux/kasan.h | 16 ++++++++--------
 mm/kasan/common.c     | 40 +++++++++++++++++++++++-----------------
 mm/mempool.c          |  2 +-
 3 files changed, 32 insertions(+), 26 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 6bd95243a583..16cf53eac29b 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -175,6 +175,13 @@ static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 	return false;
 }
 
+void __kasan_slab_free_mempool(void *ptr, unsigned long ip);
+static __always_inline void kasan_slab_free_mempool(void *ptr, unsigned long ip)
+{
+	if (kasan_enabled())
+		__kasan_slab_free_mempool(ptr, ip);
+}
+
 void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
 				       void *object, gfp_t flags);
 static __always_inline void * __must_check kasan_slab_alloc(
@@ -215,13 +222,6 @@ static __always_inline void * __must_check kasan_krealloc(const void *object,
 	return (void *)object;
 }
 
-void __kasan_poison_kfree(void *ptr, unsigned long ip);
-static __always_inline void kasan_poison_kfree(void *ptr, unsigned long ip)
-{
-	if (kasan_enabled())
-		__kasan_poison_kfree(ptr, ip);
-}
-
 void __kasan_kfree_large(void *ptr, unsigned long ip);
 static __always_inline void kasan_kfree_large(void *ptr, unsigned long ip)
 {
@@ -260,6 +260,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 {
 	return false;
 }
+static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
 				   gfp_t flags)
 {
@@ -279,7 +280,6 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
 {
 	return (void *)object;
 }
-static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
 static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
 
 #endif /* CONFIG_KASAN */
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 17918bd20ed9..1205faac90bd 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -335,6 +335,29 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 	return ____kasan_slab_free(cache, object, ip, true);
 }
 
+void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
+{
+	struct page *page;
+
+	page = virt_to_head_page(ptr);
+
+	/*
+	 * Even though this function is only called for kmem_cache_alloc and
+	 * kmalloc backed mempool allocations, those allocations can still be
+	 * !PageSlab() when the size provided to kmalloc is larger than
+	 * KMALLOC_MAX_SIZE, and kmalloc falls back onto page_alloc.
+	 */
+	if (unlikely(!PageSlab(page))) {
+		if (ptr != page_address(page)) {
+			kasan_report_invalid_free(ptr, ip);
+			return;
+		}
+		poison_range(ptr, page_size(page), KASAN_FREE_PAGE);
+	} else {
+		____kasan_slab_free(page->slab_cache, ptr, ip, false);
+	}
+}
+
 static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
 	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
@@ -429,23 +452,6 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 						flags, true);
 }
 
-void __kasan_poison_kfree(void *ptr, unsigned long ip)
-{
-	struct page *page;
-
-	page = virt_to_head_page(ptr);
-
-	if (unlikely(!PageSlab(page))) {
-		if (ptr != page_address(page)) {
-			kasan_report_invalid_free(ptr, ip);
-			return;
-		}
-		poison_range(ptr, page_size(page), KASAN_FREE_PAGE);
-	} else {
-		____kasan_slab_free(page->slab_cache, ptr, ip, false);
-	}
-}
-
 void __kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr)))
diff --git a/mm/mempool.c b/mm/mempool.c
index 583a9865b181..624ed51b060f 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -104,7 +104,7 @@ static inline void poison_element(mempool_t *pool, void *element)
 static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
 {
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
-		kasan_poison_kfree(element, _RET_IP_);
+		kasan_slab_free_mempool(element, _RET_IP_);
 	else if (pool->alloc == mempool_alloc_pages)
 		kasan_free_pages(element, (unsigned long)pool->pool_data);
 }
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/798e1753fafb37151213a0ad0b1b2f08f66c3877.1605305978.git.andreyknvl%40google.com.
