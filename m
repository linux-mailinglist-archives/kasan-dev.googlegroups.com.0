Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSUCRX6QKGQEHNBMFKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 377422A7388
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:03:23 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id n16sf38158edw.19
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:03:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534603; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z62lJn77ohcchQPeltPaypuLhWz0VPnls3u++9MFHe316Iq0U9xnd+PBrn6ji86Y/B
         EbNb+JhTJ+jdEvBVnGgStPXkD05MD9TFcBlv9Y87mf59R1KnwZWhAqnJ9wN7V+xFCcYt
         fxL+NzxdWcvM0T5m2oqaeo+6EV0lRHs8Xfd6qffEJRIzVUogOogoKdmZihVK78RnfV+j
         7v50ORF1eWdsFlv3zqt3CSXocxQ1Pw13SdKp72hyFt0v55b+BhBTcEsOI+MR81TR4mgR
         BjGQmLTSP4Xrzcast79AN2UUqVP+zbtdydz6RVDRu8/m2+qYBUGO7+n6XdhfeM4ZNggA
         XSsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=NNBRYII7HwRQlQSiverw4aCaP2qN5E1TpMbFLXmv/q0=;
        b=nWRNSaRhRdLx9Ti+q5IHCmzgHcP+OP8Zq37RLbgaEqoLxiDAgZb+Xrp9/xBILENC9p
         +gURVMZPgOdbFBqiV1ZOu7SwuO50j4H1kWKmoQ+v4aSY0oG9xqBwHWKq1mpPCdMMblkl
         JElNjJE6iDCKnLli/6zIAJvya4xLRHdwU/kXDu0bL0dGeKdem1txAl8U+HbiKyLja5Dt
         lbSnL9dggOyUN39Maz/Zx1VX5LHxX0FWVIHWOADRwkrVOIW41yzetXvYnkQ34a5QUaoO
         NPiB3W4/pjNE3BW0JhOc/Y6p2/ccLPBJyHWZnHQoANucnM19ND8/m9wgYhk808you1TF
         PhsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qJE0zOp+;
       spf=pass (google.com: domain of 3sugjxwokcvw4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3SUGjXwoKCVw4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NNBRYII7HwRQlQSiverw4aCaP2qN5E1TpMbFLXmv/q0=;
        b=SN+yQj+6QUw5SWzHZVv3DkSGdRFqlN+msI2XHmUWk89PIPq7FW+WChSkoniTSa6fcN
         PxqqGPhPISpCZzJKJr/NJiJUjGy1q7o4tYhYuhKjjm06s75KQYlXxk9cC795vIJyMz9L
         NHOHfcInNl0/vNGXbkZOWzIJRyjvqEkJd7uoW2WyOxrKh52Z7mB188YZKp2mETsD0kSW
         V2dpPc/QGmlBA6XucUb93lucsAFC3rDSk0MDQHCzY3JNBw2xbjYxQoflIm/98KsRMHUx
         ddCfLOQI1lH13J7iWR5hbrtxrio9ffJjE1ToFjtE1IuP4PVYm1L49JPNGfJfnLB7Hk8E
         vhCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NNBRYII7HwRQlQSiverw4aCaP2qN5E1TpMbFLXmv/q0=;
        b=HCy24D3QJUexi+qUe72DP4oGchGicR6p8YI+2OnQbgN1FGslHmvvW2cANwY/ZY3F6F
         OiKnJ+1pNN3oNaBGn1n/SD3J9Izp/MeI0zBLseUs2JSA1Ub2z8yATGHqoCTfBfZR6vcb
         wKEw2HtI7zR+y1z3sSzSF1EWlWmejwYork2i8vLcucoJSthUQjc+dkT1dsh17W95Ncm/
         KOybtVgPGgqjuoWN4LkhYbtfzJ/cAkY8zgDGy97Xkz9xRpQFdo5UU/i2gK9/7tYfTpPY
         SKHmaU9mluF3caUaCKAlwd3EQjde7rwjeVU8G2K4ngf0elnM7TaNQt+SezTNd+zeMfjv
         jD+Q==
X-Gm-Message-State: AOAM530BRTYYUJEF+ZyfCT3C/6uYjfonIqD9q2eQV9j8yaUCf2oeq3HJ
	Hvh+IkcaK7LTYXi9rNCrITY=
X-Google-Smtp-Source: ABdhPJwNtz/mWftvyMh6bfNfWaR7AGT6MF80hy/riRXgNRNEdQOgMu154Qh069NyNMxzj+6Q0v9qfA==
X-Received: by 2002:aa7:d888:: with SMTP id u8mr349544edq.210.1604534603021;
        Wed, 04 Nov 2020 16:03:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d4c3:: with SMTP id t3ls4219421edr.0.gmail; Wed, 04 Nov
 2020 16:03:22 -0800 (PST)
X-Received: by 2002:a50:9e69:: with SMTP id z96mr351870ede.226.1604534602160;
        Wed, 04 Nov 2020 16:03:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534602; cv=none;
        d=google.com; s=arc-20160816;
        b=aaG7bAj+pvk0Ovkya/ifC30aKYc3SiZIi5rqoj7TlY6xVuivXx4rPhBVT+D2Y+vmCt
         gLBZ3Ak5g82iYJHSKW3MJltrEArESjifUeB6CA3iSjKmKjMBFdgQa3re1CYoO9Bccc6o
         XlrkRjYI2qJyc1+apSixv+0250YsZeL55kv+sKrsf8BvLzbNzismgS1n0LrUpbub8zGO
         xcE1UhOUw00kY0Zoly4UWKIvm81nhblTq707yucKbgj8UoE1dXcyGC6NqUQb1oqh0G+i
         sD0x/ml+5Gaka2ZnY3+48gbwepFc7ggKNzCEkbh4BsrDAS+ZOqtPAXGSvATPD3jYcXnK
         ZHhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=BKsLmNNgmZaUnh/EpgjKJBz6eZxr51wf9zKFrfwsdMY=;
        b=NhnP89G35HyJ7gZ8m6FTDqbPbLwIpntctslVGrUbHeVC/0JYpXVyTDGpGnlt5grP1N
         ka5v9eIoI35zo2DRji9BJSWTn6FAVxjNoD4I4b/TCUO0w4AJqT2CYqlMULMZyrXb/Q3i
         1tGagbGtvpj0jzCM5shvpJ6fP9Evr8JdOd0eOlIdiHx/21JgFTZPP24N9Nx3TIJSfCaZ
         4bDigilr8ujDHIr+5wYl14LxQOMK/BCU/iplDvHZQpHRW6KgIgpQB2ZjLC8qLau5EnPn
         enA7/4nIBFGRW640xkhIGHkLpZM2DFju5bJ4KA49m5BYH/SNYrqJUsAnpa/9fUC3c8We
         wYpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qJE0zOp+;
       spf=pass (google.com: domain of 3sugjxwokcvw4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3SUGjXwoKCVw4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id g4si145330edt.2.2020.11.04.16.03.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:03:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sugjxwokcvw4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id t201so9532wmt.1
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:03:22 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:6302:: with SMTP id
 x2mr196504wmb.121.1604534601835; Wed, 04 Nov 2020 16:03:21 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:29 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <17ecf27ee7b275869047bef91558bd263dd243f1.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 19/20] kasan, mm: allow cache merging with no metadata
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
 header.i=@google.com header.s=20161025 header.b=qJE0zOp+;       spf=pass
 (google.com: domain of 3sugjxwokcvw4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3SUGjXwoKCVw4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
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

The reason cache merging is disabled with KASAN is because KASAN puts its
metadata right after the allocated object. When the merged caches have
slightly different sizes, the metadata ends up in different places, which
KASAN doesn't support.

It might be possible to adjust the metadata allocation algorithm and make
it friendly to the cache merging code. Instead this change takes a simpler
approach and allows merging caches when no metadata is present. Which is
the case for hardware tag-based KASAN with kasan.mode=prod.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Ia114847dfb2244f297d2cb82d592bf6a07455dba
---
 include/linux/kasan.h | 26 ++++++++++++++++++++++++--
 mm/kasan/common.c     | 11 +++++++++++
 mm/slab_common.c      | 11 ++++++++---
 3 files changed, 43 insertions(+), 5 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d47601517dad..fb8ba4719e3b 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -79,17 +79,35 @@ struct kasan_cache {
 };
 
 #ifdef CONFIG_KASAN_HW_TAGS
+
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
+
 static inline kasan_enabled(void)
 {
 	return static_branch_likely(&kasan_flag_enabled);
 }
-#else
+
+slab_flags_t __kasan_never_merge(slab_flags_t flags);
+static inline slab_flags_t kasan_never_merge(slab_flags_t flags)
+{
+	if (kasan_enabled())
+		return __kasan_never_merge(flags);
+	return flags;
+}
+
+#else /* CONFIG_KASAN_HW_TAGS */
+
 static inline kasan_enabled(void)
 {
 	return true;
 }
-#endif
+
+static inline slab_flags_t kasan_never_merge(slab_flags_t flags)
+{
+	return flags;
+}
+
+#endif /* CONFIG_KASAN_HW_TAGS */
 
 void __kasan_alloc_pages(struct page *page, unsigned int order);
 static inline void kasan_alloc_pages(struct page *page, unsigned int order)
@@ -238,6 +256,10 @@ static inline kasan_enabled(void)
 {
 	return false;
 }
+static inline slab_flags_t kasan_never_merge(slab_flags_t flags)
+{
+	return flags;
+}
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 static inline void kasan_cache_create(struct kmem_cache *cache,
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 940b42231069..25b18c145b06 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -81,6 +81,17 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 }
 #endif /* CONFIG_KASAN_STACK */
 
+/*
+ * Only allow cache merging when stack collection is disabled and no metadata
+ * is present.
+ */
+slab_flags_t __kasan_never_merge(slab_flags_t flags)
+{
+	if (kasan_stack_collection_enabled())
+		return flags;
+	return flags & ~SLAB_KASAN;
+}
+
 void __kasan_alloc_pages(struct page *page, unsigned int order)
 {
 	u8 tag;
diff --git a/mm/slab_common.c b/mm/slab_common.c
index f1b0c4a22f08..3042ee8ea9ce 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -18,6 +18,7 @@
 #include <linux/seq_file.h>
 #include <linux/proc_fs.h>
 #include <linux/debugfs.h>
+#include <linux/kasan.h>
 #include <asm/cacheflush.h>
 #include <asm/tlbflush.h>
 #include <asm/page.h>
@@ -49,12 +50,16 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
 		    slab_caches_to_rcu_destroy_workfn);
 
 /*
- * Set of flags that will prevent slab merging
+ * Set of flags that will prevent slab merging.
+ * Use slab_never_merge() instead.
  */
 #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
 		SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
 		SLAB_FAILSLAB | SLAB_KASAN)
 
+/* KASAN allows merging in some configurations and will remove SLAB_KASAN. */
+#define slab_never_merge() (kasan_never_merge(SLAB_NEVER_MERGE))
+
 #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
 			 SLAB_CACHE_DMA32 | SLAB_ACCOUNT)
 
@@ -164,7 +169,7 @@ static unsigned int calculate_alignment(slab_flags_t flags,
  */
 int slab_unmergeable(struct kmem_cache *s)
 {
-	if (slab_nomerge || (s->flags & SLAB_NEVER_MERGE))
+	if (slab_nomerge || (s->flags & slab_never_merge()))
 		return 1;
 
 	if (s->ctor)
@@ -198,7 +203,7 @@ struct kmem_cache *find_mergeable(unsigned int size, unsigned int align,
 	size = ALIGN(size, align);
 	flags = kmem_cache_flags(size, flags, name, NULL);
 
-	if (flags & SLAB_NEVER_MERGE)
+	if (flags & slab_never_merge())
 		return NULL;
 
 	list_for_each_entry_reverse(s, &slab_caches, list) {
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/17ecf27ee7b275869047bef91558bd263dd243f1.1604534322.git.andreyknvl%40google.com.
