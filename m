Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPMCRX6QKGQEE3PUMYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B25A2A7380
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:03:10 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id d6sf142997ooi.7
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:03:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534589; cv=pass;
        d=google.com; s=arc-20160816;
        b=0nh5TyAOAWygFabx2eSnxetgr8gckwKlXUoCrb1icKe7e04K0dJNrQolizwITGPQnh
         XKr0rRfVj+jOLlBN2KivwY+X6LuPO5Y6yOeRAlpKyH+sKNg6dJ94p2BaNNT3m1wG8/Mf
         1TbjkTY3TWwwflPDjwcaaL/y+lQr5xBQsqcKdjmALnqwz9hjLU3iTcwKHSZhZa+Leecm
         e1vklZ/YzzDc6EI9BWwAyEe9QmPAqprq7tVaoz81oeZn83kx7APe51SpvOc/z6nvStgB
         bgXGZwwWUyXjBNjIikmCsxOzu7KyFMrs/2Yt4QNHQ5f0qw2OwbzZl6woYic4QEQ23FSk
         jj+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=UYSunm4YeOhOx+yocoN+wrMmpstZFSQUWGhEY6Lde0w=;
        b=LfvbNaVF73qfOgic3Ozxgst8cI6WlpbDsxyXrDbKccbmGKEyqzvpzrlmfmrPyE0gxI
         ZiJCdKPmjOaBz0r5dvE4hEyR8J8aKuj5F5puEA3RHbG8IRDa1mcK+CwFr+sUERUTJ157
         hU/o6Pp87fmYGafCQP3JMMDL5ksFhDK3jNRY2gA7fAT/jRs4IrlAc7K4XGXsQFMHXlUR
         SVxZj0q59F0SDpW46c52Tu6S0tP4WT7iTZL3HH2UWe3axj/GfTkzJrZ/BJRNmPhpXlZp
         LMH/GxQ2ibN2GRWPGjXykf8xK9fge26a5hTnAxemPOVin9Z+odW5VY1kI/KICTEMABKv
         QfLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jrZ3nq9h;
       spf=pass (google.com: domain of 3pegjxwokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3PEGjXwoKCU8r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UYSunm4YeOhOx+yocoN+wrMmpstZFSQUWGhEY6Lde0w=;
        b=FurhmE6qB6B4pvRIiPvlmFDpiWdrKplefmVu+FMFvqnp/bp0D8xXlaW3joKyWRbl53
         fseBY9QLDkgBZhVW3CRFb/VbPK+AHr11xbc9zhwFur7yuPqBG0l9z+ksPuLq38NOI4zt
         ZpAevUvK3P/S053bQMHwDp77YkSucX1jpSp2H+I2ZmoK9sjoK+K8/P4GPS0o6gzkAZDw
         cj6Ls0Ci0HwnQKL0OUvrz9dTosh7hMdgV7IqifP6zaMU2hPLWSAZg00ZcO64Yd13Okih
         p7f3UWhG1vDl4KVd9Vg9/RTcQwu5Ym7D6hNIZlVKonVmZl4lrHdJWVrV+NAYH5HPIiW2
         1NFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UYSunm4YeOhOx+yocoN+wrMmpstZFSQUWGhEY6Lde0w=;
        b=i0I+ZOR0K6s2+UVNc4B8BkB5dXIWis+UX2hLHXz25Jq+GwjD0V0N5+IAiWiBERsfEC
         OJFDwnP15s48DTjuMBu1Pff3129IzeOI8XV6bJDDKnqiczNXgWrFPjQ9p2+K46fDVodL
         7h4xE0qtSiolHQk8LlIQD2qGj3SO3qBODFFu8P2UEGIY3xEWzdiS105O1w9yw104VqRb
         FWZ3PyppYzH/RkgbqYlcXgrnkC0rLa7JKvz1udqRwZdw2IzJDxE4up652e2eUGawiffL
         YgOIJ2Scpxp2D5bRs6w6vIzS3r7AgUYuhjhBFtGrPcWKUwuRMaFhDjPDUv/8/sWZS8hG
         gpCg==
X-Gm-Message-State: AOAM530dVF5I3ZNPrCBAnbxDWZyFzzABWQMiT+DfvJU/Er226BUtNoYx
	6UATsnCt0+rbhyZDMsQlcBE=
X-Google-Smtp-Source: ABdhPJwYxdxSbjEOPSPTjIT5H8WK1Q4rgSvAp0lBdzEYlz/CjyanUrutAS54KY2AdJpqHqFDkl5uUw==
X-Received: by 2002:aca:b644:: with SMTP id g65mr5191oif.164.1604534589465;
        Wed, 04 Nov 2020 16:03:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5214:: with SMTP id g20ls1014168oib.9.gmail; Wed, 04 Nov
 2020 16:03:09 -0800 (PST)
X-Received: by 2002:a05:6808:1c4:: with SMTP id x4mr175515oic.91.1604534589101;
        Wed, 04 Nov 2020 16:03:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534589; cv=none;
        d=google.com; s=arc-20160816;
        b=fQ6PIwz2z3s9If5drg8ggZcINWDi5tXvjP3dUmzttLu9RPPGuWj/0+RZEhn1nSJ97H
         VbCOXgqmjUbJvRXrjSvejbZ1V4IW2aA+FDOg/HbNO4RvIH1G6WGTAYPgc7b+DGacfFom
         TN+NY3qWFxOsyx+ocJO75h/67ceqf0Jy8F19Rnmfuphsy+AwLzznNsa8Q36hifPJVe/q
         6CNrkOSpRaDgaEmjx1CALK+/5YBT+GqHEwSlIZ13luV8Otr56DaZ1snbZWDVhjmwQJ4E
         1dqWcyoPZLVTPvI9xPN2csf/COnwQOBLnQlGw9X1GwNkC8f72LoPBdeUEctBboHWOG24
         Y+pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=n/EgrjS/0wTVW1eC4Y9BfE2JdZzS0OcWlZnzEp1P2oA=;
        b=gb56sBXMxIwLZW4gRJkPBHp4wtkHJAhWnE4d1HlR5+8kAPwC6JiHQr+oaM+AtDwBW2
         Cy1EmffrncPaSj6w8ECrZ+FJQVN+xfIsguhHqfxDCx2AoVbRjGrzKim5xi0+PaXvEh2G
         aLVG/Qbaf7FXEcOb9FihxajhyZxmI6F1gCtg9ukoT+rywyBqhBZKxBENaO9U7EXQnmL9
         qpsD1LYee5H5boYqB7DZu7zOGi2u0Hx+GdkIGchbG64VwSvxW60wggjXoPkXEotmhI8r
         FIvpzell5i0Z3KaEuP8tKHUho0Z5Oyc7QuXRDm+s1Z0fdvtfUOYeNWsXazqjcvpErb8W
         gTNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jrZ3nq9h;
       spf=pass (google.com: domain of 3pegjxwokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3PEGjXwoKCU8r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id o23si217603oic.4.2020.11.04.16.03.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:03:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pegjxwokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id t19so110116qta.21
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:03:09 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f70f:: with SMTP id
 w15mr489369qvn.45.1604534588580; Wed, 04 Nov 2020 16:03:08 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:24 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <82f01c35335ae293f6119531670354116fd63858.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 14/20] kasan, mm: rename kasan_poison_kfree
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jrZ3nq9h;       spf=pass
 (google.com: domain of 3pegjxwokcu8r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3PEGjXwoKCU8r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
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
reflects what this annotation does.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/I5026f87364e556b506ef1baee725144bb04b8810
---
 include/linux/kasan.h | 16 ++++++++--------
 mm/kasan/common.c     | 16 ++++++++--------
 mm/mempool.c          |  2 +-
 3 files changed, 17 insertions(+), 17 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index ae1046fc74e5..d47601517dad 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -175,6 +175,13 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned
 	return false;
 }
 
+void __kasan_slab_free_mempool(void *ptr, unsigned long ip);
+static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip)
+{
+	if (kasan_enabled())
+		__kasan_slab_free_mempool(ptr, ip);
+}
+
 void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
 				       void *object, gfp_t flags);
 static inline void * __must_check kasan_slab_alloc(struct kmem_cache *s,
@@ -215,13 +222,6 @@ static inline void * __must_check kasan_krealloc(const void *object,
 	return (void *)object;
 }
 
-void __kasan_poison_kfree(void *ptr, unsigned long ip);
-static inline void kasan_poison_kfree(void *ptr, unsigned long ip)
-{
-	if (kasan_enabled())
-		__kasan_poison_kfree(ptr, ip);
-}
-
 void __kasan_kfree_large(void *ptr, unsigned long ip);
 static inline void kasan_kfree_large(void *ptr, unsigned long ip)
 {
@@ -261,6 +261,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 {
 	return false;
 }
+static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
 				   gfp_t flags)
 {
@@ -280,7 +281,6 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
 {
 	return (void *)object;
 }
-static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
 static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
 
 #endif /* CONFIG_KASAN */
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 819403548f2e..60793f8695a8 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -336,6 +336,14 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 	return ____kasan_slab_free(cache, object, ip, true);
 }
 
+void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
+{
+	struct page *page;
+
+	page = virt_to_head_page(ptr);
+	____kasan_slab_free(page->slab_cache, ptr, ip, false);
+}
+
 static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
 	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
@@ -427,14 +435,6 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 						flags, true);
 }
 
-void __kasan_poison_kfree(void *ptr, unsigned long ip)
-{
-	struct page *page;
-
-	page = virt_to_head_page(ptr);
-	____kasan_slab_free(page->slab_cache, ptr, ip, false);
-}
-
 void __kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr)))
diff --git a/mm/mempool.c b/mm/mempool.c
index f473cdddaff0..b1f39fa75ade 100644
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/82f01c35335ae293f6119531670354116fd63858.1604534322.git.andreyknvl%40google.com.
