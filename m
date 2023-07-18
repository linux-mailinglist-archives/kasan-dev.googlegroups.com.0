Return-Path: <kasan-dev+bncBDGZTDNQ3ICBBGH73CSQMGQELELLHTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 310CA75755D
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jul 2023 09:30:34 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3463fbf2ffesf37697615ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jul 2023 00:30:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689665432; cv=pass;
        d=google.com; s=arc-20160816;
        b=yBWTFur3WM2c1TwrDKt7jQ2Bg6lbTXZU3H7Ys4U43uqjwRrQBI/pGtSQ2E6h4YuwBc
         pJ3hTpJF7uUDfj0neQ300rU/hkWNqb1LzRKJYeHiW0Hyt1iJs1xBHPjFY52BjOev5KDO
         QrLyDgCkJXIqtqHwsO42hptwWhGYYApU48pkRk+ldf+n6WfGnp2kVHOAyaB6B0hJsn+X
         QJi+UMof2jphRgDCy8Fdz22YF07NZdLhvNrSc/Oli2PqN8gQsxyHyr4xveLcAKUTjSob
         IQUV9jOJkUl02QFQWsxxCEYH4UxpEtl+oyzbnEaqatCflu7KSeHz/Gc2dxMvpZ5CbCQC
         nZLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=xVj2RpMNlo4VM7BN3hhmFUfm47Hk2nGf1Xg1Do849M0=;
        fh=2vNDz2r49DP/PlWxfCRxgW7k9QySHJXLDaTm5YbQXtY=;
        b=QCEQdDdTyNIystEjbPivzIWwT+t+OqLIjGz7wvk50/28oP5cOG2qgbKwXLWgzE6Ct9
         yyG2JxgmP6hWJsfQdXDiFU03cfzEpYgQ5STTSiYF3YNs4sceE/Nc854lrqXA9Zvj/vGo
         2PypwB0BdOj5/MReuBSme8qMDC7OBPOqcjRQ7pLZMXJYI+7OG2EhvnNx9A5lai1rREpk
         yITjllttdDBX+cufX9yQozJ09MvteSSc8VeXjw7jr5T54bCc2vub5hfoPYyToVLoLjK0
         sYokOS/wZtS1iewwDXTjLev9TgzYYAPRJ/5Y26Z0WVrVzTqXSemqKlIm8pKKM9B15tIf
         r6ZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=RTBhYUAt;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689665432; x=1692257432;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xVj2RpMNlo4VM7BN3hhmFUfm47Hk2nGf1Xg1Do849M0=;
        b=BzNyB8JMZ6B3CtEGX7XeQWmdllJkPSJ3fIk6v4tDSvV5n1ll7+fHGWT7sPNY1ETyol
         0/ZCjaqDFRzgn7mKpL4h6llh1+bJZbJg6JEvtEbeB0f4GRWZdm+daRM4e97wfZ5Zggh6
         b6ra1piVVGIQNFC8nk5Uo67acHxZ9WWJOMftjjCRMyEkQRmh/hiQkmCItaIlNJJy6Nih
         tmn2LIcCLRrLb4m2bb8wknT5uy9fGdn/U8Ool+zfYFAu2bQA10tGsBVq7QoYEp6vUAnf
         bgQ0SWeB/JfMTS6jABhvOrJSgO1Scrwxed4IJZCr/EUconskVeJQXp0WcXs1NB91c5rG
         Rn2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689665432; x=1692257432;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xVj2RpMNlo4VM7BN3hhmFUfm47Hk2nGf1Xg1Do849M0=;
        b=ZKnWi5zHUm21lhyM71ltSwRC74RZiD2V1XlA09yqPtxy9Y6mr5Y4w6JlJIIiN/GDOQ
         L6Y2sL0gc/kIxEbLbDR1kU+Xvz7pm7/ShuH2LabRvbaDo6cMn4BCFGJuJg91YbQzl233
         g54cKMlcxErskZEG0Rlee2FBsxQKp9PAMmDNh/2aMlDLiiBtBB6naC47FJSJttje/U/F
         VbPAIUVFjziNbttlQGT04v6B/BAODcg3IjTQbydkTyk3/zSehQdRjXJpX7ChocuFM403
         sRF8B7KZfQXcUO6Eugt/3mYOzAGbkWtuqXBpPQbuL/PTc5IQYZKuJApVbOm8qX9TrDDy
         50aQ==
X-Gm-Message-State: ABy/qLZRsUnE+s6VMSVb9vVM/jQdqbJg5zt5DiwTzqsBSmWR0rGsP9/7
	ZeKAUMLk/04o2kzrnypJMXk=
X-Google-Smtp-Source: APBJJlE9iDk+pG8QXzUUsGhvIS2ftY4WLt8xmr6PfuhLd7PJNiiYhiv2cRH18HH8ivcgkIkocFvAxA==
X-Received: by 2002:a05:6e02:1bc7:b0:346:7a41:6c62 with SMTP id x7-20020a056e021bc700b003467a416c62mr2275310ilv.15.1689665432618;
        Tue, 18 Jul 2023 00:30:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:15c3:b0:346:2f5e:1569 with SMTP id
 q3-20020a056e0215c300b003462f5e1569ls2317465ilu.2.-pod-prod-02-us; Tue, 18
 Jul 2023 00:30:32 -0700 (PDT)
X-Received: by 2002:a92:c269:0:b0:345:af82:dc3a with SMTP id h9-20020a92c269000000b00345af82dc3amr2013816ild.14.1689665432036;
        Tue, 18 Jul 2023 00:30:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689665432; cv=none;
        d=google.com; s=arc-20160816;
        b=OtGNxBl02tyyYK70yawPLYVr9r+UXtiwCu5/lmp48duutDLOfXN2maTHDwDIh5R+RD
         GVfrFvN7FjTIBZdH1U1I7bG5KDxMl8vgsW9Q4/csFd7egdhSniGIkMBq3uvN/eVQ6qt6
         7DWpnCl28CZAW6C7ZxZztVtNjXS+SkCoRksqV3RNHZB5FAOZM58VfDuIUg3cJzEfKSzM
         supiKsQyfY4lENxIMD2962YIc2mQOczaJnkjldrsBMk+u6jdyZcgQXXsOsqlemL5b70S
         oVOlkplkLZXoAHgWUCMToeykLMHLJ02vUnFQDQvKO5UbWeotVcYbQwVkQRTivhS+pts3
         Yd3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=NbWcwbfvK0B2CiexlkN6if10zNcxlC4xkFU/ZNrDr6E=;
        fh=WeaUOvWwJDuKP9KhwGpUORxQHZzhkJChjku0draIx7o=;
        b=jXzZIpaCRM1TRlKM4j1bZsAQjdng6N9IATICsR2Pq+uXO7dHozbdggr39q7QRg8m8N
         vHPNFvWI39+ahoM0T6rpxFdUx69SjCREhh0V1s24NOjzJLbtLrtlzqMQqrRF+VLTEHV2
         MOdUyRRWthuBmcp+W+VlmgsRny1q03zGash9Niy1imfI796d+/d59iHi81KpTo7hyYvh
         EjqV0uLnNgD1P46v2odM2Y3JnJBziuX6UpPX9JhBZXV5tyPH0FUrQP9B7S9zF/QVVqbE
         5oXaEqtvt9fFXojW1h2YTaeg/eT2KFgXSoDwGiHKA1prRj8ihVBgiq1XyK4PklyJee99
         Jg7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=RTBhYUAt;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id q3-20020a920503000000b00346233ecb68si69423ile.5.2023.07.18.00.30.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jul 2023 00:30:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-1b8a462e0b0so32227475ad.3
        for <kasan-dev@googlegroups.com>; Tue, 18 Jul 2023 00:30:31 -0700 (PDT)
X-Received: by 2002:a17:902:ecc1:b0:1b8:9b78:df44 with SMTP id a1-20020a170902ecc100b001b89b78df44mr13733451plh.20.1689665431200;
        Tue, 18 Jul 2023 00:30:31 -0700 (PDT)
Received: from GL4FX4PXWL.bytedance.net ([2408:8656:30f8:e020::2:d])
        by smtp.gmail.com with ESMTPSA id x6-20020a1709027c0600b001b0358848b0sm1096315pll.161.2023.07.18.00.30.25
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Tue, 18 Jul 2023 00:30:30 -0700 (PDT)
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	muchun.song@linux.dev,
	Peng Zhang <zhangpeng.00@bytedance.com>
Subject: [PATCH v3] mm: kfence: allocate kfence_metadata at runtime
Date: Tue, 18 Jul 2023 15:30:19 +0800
Message-Id: <20230718073019.52513-1-zhangpeng.00@bytedance.com>
X-Mailer: git-send-email 2.37.0 (Apple Git-136)
MIME-Version: 1.0
X-Original-Sender: zhangpeng.00@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=RTBhYUAt;       spf=pass
 (google.com: domain of zhangpeng.00@bytedance.com designates
 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Peng Zhang <zhangpeng.00@bytedance.com>
Reply-To: Peng Zhang <zhangpeng.00@bytedance.com>
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

kfence_metadata is currently a static array. For the purpose of allocating
scalable __kfence_pool, we first change it to runtime allocation of
metadata. Since the size of an object of kfence_metadata is 1160 bytes, we
can save at least 72 pages (with default 256 objects) without enabling
kfence.

Signed-off-by: Peng Zhang <zhangpeng.00@bytedance.com>
---
Changes since v2:
 - Fix missing renaming of kfence_alloc_pool.
 - Add __read_mostly for kfence_metadata and kfence_metadata_init.
 - Use smp_store_release() and smp_load_acquire() to access kfence_metadata.
 - Some tweaks to comments and git log.

v1: https://lore.kernel.org/lkml/20230710032714.26200-1-zhangpeng.00@bytedance.com/
v2: https://lore.kernel.org/lkml/20230712081616.45177-1-zhangpeng.00@bytedance.com/

 include/linux/kfence.h |  11 ++--
 mm/kfence/core.c       | 124 ++++++++++++++++++++++++++++-------------
 mm/kfence/kfence.h     |   5 +-
 mm/mm_init.c           |   2 +-
 4 files changed, 97 insertions(+), 45 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 726857a4b680..401af4757514 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -59,15 +59,16 @@ static __always_inline bool is_kfence_address(const void *addr)
 }
 
 /**
- * kfence_alloc_pool() - allocate the KFENCE pool via memblock
+ * kfence_alloc_pool_and_metadata() - allocate the KFENCE pool and KFENCE
+ * metadata via memblock
  */
-void __init kfence_alloc_pool(void);
+void __init kfence_alloc_pool_and_metadata(void);
 
 /**
  * kfence_init() - perform KFENCE initialization at boot time
  *
- * Requires that kfence_alloc_pool() was called before. This sets up the
- * allocation gate timer, and requires that workqueues are available.
+ * Requires that kfence_alloc_pool_and_metadata() was called before. This sets
+ * up the allocation gate timer, and requires that workqueues are available.
  */
 void __init kfence_init(void);
 
@@ -223,7 +224,7 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
 #else /* CONFIG_KFENCE */
 
 static inline bool is_kfence_address(const void *addr) { return false; }
-static inline void kfence_alloc_pool(void) { }
+static inline void kfence_alloc_pool_and_metadata(void) { }
 static inline void kfence_init(void) { }
 static inline void kfence_shutdown_cache(struct kmem_cache *s) { }
 static inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags) { return NULL; }
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index dad3c0eb70a0..6b526435886c 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -116,7 +116,15 @@ EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
  * backing pages (in __kfence_pool).
  */
 static_assert(CONFIG_KFENCE_NUM_OBJECTS > 0);
-struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
+struct kfence_metadata *kfence_metadata __read_mostly;
+
+/*
+ * If kfence_metadata is not NULL, it may be accessed by kfence_shutdown_cache().
+ * So introduce kfence_metadata_init to initialize metadata, and then make
+ * kfence_metadata visible after initialization is successful. This prevents
+ * potential UAF or access to uninitialized metadata.
+ */
+static struct kfence_metadata *kfence_metadata_init __read_mostly;
 
 /* Freelist with available objects. */
 static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
@@ -591,7 +599,7 @@ static unsigned long kfence_init_pool(void)
 
 		__folio_set_slab(slab_folio(slab));
 #ifdef CONFIG_MEMCG
-		slab->memcg_data = (unsigned long)&kfence_metadata[i / 2 - 1].objcg |
+		slab->memcg_data = (unsigned long)&kfence_metadata_init[i / 2 - 1].objcg |
 				   MEMCG_DATA_OBJCGS;
 #endif
 	}
@@ -610,7 +618,7 @@ static unsigned long kfence_init_pool(void)
 	}
 
 	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
-		struct kfence_metadata *meta = &kfence_metadata[i];
+		struct kfence_metadata *meta = &kfence_metadata_init[i];
 
 		/* Initialize metadata. */
 		INIT_LIST_HEAD(&meta->list);
@@ -626,6 +634,12 @@ static unsigned long kfence_init_pool(void)
 		addr += 2 * PAGE_SIZE;
 	}
 
+	/*
+	 * Make kfence_metadata visible only when initialization is successful.
+	 * Otherwise, if the initialization fails and kfence_metadata is freed,
+	 * it may cause UAF in kfence_shutdown_cache().
+	 */
+	smp_store_release(&kfence_metadata, kfence_metadata_init);
 	return 0;
 
 reset_slab:
@@ -672,26 +686,10 @@ static bool __init kfence_init_pool_early(void)
 	 */
 	memblock_free_late(__pa(addr), KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool));
 	__kfence_pool = NULL;
-	return false;
-}
-
-static bool kfence_init_pool_late(void)
-{
-	unsigned long addr, free_size;
 
-	addr = kfence_init_pool();
-
-	if (!addr)
-		return true;
+	memblock_free_late(__pa(kfence_metadata_init), KFENCE_METADATA_SIZE);
+	kfence_metadata_init = NULL;
 
-	/* Same as above. */
-	free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
-#ifdef CONFIG_CONTIG_ALLOC
-	free_contig_range(page_to_pfn(virt_to_page((void *)addr)), free_size / PAGE_SIZE);
-#else
-	free_pages_exact((void *)addr, free_size);
-#endif
-	__kfence_pool = NULL;
 	return false;
 }
 
@@ -841,19 +839,30 @@ static void toggle_allocation_gate(struct work_struct *work)
 
 /* === Public interface ===================================================== */
 
-void __init kfence_alloc_pool(void)
+void __init kfence_alloc_pool_and_metadata(void)
 {
 	if (!kfence_sample_interval)
 		return;
 
-	/* if the pool has already been initialized by arch, skip the below. */
-	if (__kfence_pool)
-		return;
-
-	__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
-
+	/*
+	 * If the pool has already been initialized by arch, there is no need to
+	 * re-allocate the memory pool.
+	 */
 	if (!__kfence_pool)
+		__kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
+
+	if (!__kfence_pool) {
 		pr_err("failed to allocate pool\n");
+		return;
+	}
+
+	/* The memory allocated by memblock has been zeroed out. */
+	kfence_metadata_init = memblock_alloc(KFENCE_METADATA_SIZE, PAGE_SIZE);
+	if (!kfence_metadata_init) {
+		pr_err("failed to allocate metadata\n");
+		memblock_free(__kfence_pool, KFENCE_POOL_SIZE);
+		__kfence_pool = NULL;
+	}
 }
 
 static void kfence_init_enable(void)
@@ -895,33 +904,68 @@ void __init kfence_init(void)
 
 static int kfence_init_late(void)
 {
-	const unsigned long nr_pages = KFENCE_POOL_SIZE / PAGE_SIZE;
+	const unsigned long nr_pages_pool = KFENCE_POOL_SIZE / PAGE_SIZE;
+	const unsigned long nr_pages_meta = KFENCE_METADATA_SIZE / PAGE_SIZE;
+	unsigned long addr = (unsigned long)__kfence_pool;
+	unsigned long free_size = KFENCE_POOL_SIZE;
+	int err = -ENOMEM;
+
 #ifdef CONFIG_CONTIG_ALLOC
 	struct page *pages;
-
-	pages = alloc_contig_pages(nr_pages, GFP_KERNEL, first_online_node, NULL);
+	pages = alloc_contig_pages(nr_pages_pool, GFP_KERNEL, first_online_node,
+				   NULL);
 	if (!pages)
 		return -ENOMEM;
+
 	__kfence_pool = page_to_virt(pages);
+	pages = alloc_contig_pages(nr_pages_meta, GFP_KERNEL, first_online_node,
+				   NULL);
+	if (pages)
+		kfence_metadata_init = page_to_virt(pages);
 #else
-	if (nr_pages > MAX_ORDER_NR_PAGES) {
+	if (nr_pages_pool > MAX_ORDER_NR_PAGES ||
+	    nr_pages_meta > MAX_ORDER_NR_PAGES) {
 		pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocator\n");
 		return -EINVAL;
 	}
+
 	__kfence_pool = alloc_pages_exact(KFENCE_POOL_SIZE, GFP_KERNEL);
 	if (!__kfence_pool)
 		return -ENOMEM;
+
+	kfence_metadata_init = alloc_pages_exact(KFENCE_METADATA_SIZE, GFP_KERNEL);
 #endif
 
-	if (!kfence_init_pool_late()) {
-		pr_err("%s failed\n", __func__);
-		return -EBUSY;
+	if (!kfence_metadata_init)
+		goto free_pool;
+
+	memzero_explicit(kfence_metadata_init, KFENCE_METADATA_SIZE);
+	addr = kfence_init_pool();
+	if (!addr) {
+		kfence_init_enable();
+		kfence_debugfs_init();
+		return 0;
 	}
 
-	kfence_init_enable();
-	kfence_debugfs_init();
+	pr_err("%s failed\n", __func__);
+	free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
+	err = -EBUSY;
 
-	return 0;
+#ifdef CONFIG_CONTIG_ALLOC
+	free_contig_range(page_to_pfn(virt_to_page((void *)kfence_metadata_init)),
+			  nr_pages_meta);
+free_pool:
+	free_contig_range(page_to_pfn(virt_to_page((void *)addr)),
+			  free_size / PAGE_SIZE);
+#else
+	free_pages_exact((void *)kfence_metadata_init, KFENCE_METADATA_SIZE);
+free_pool:
+	free_pages_exact((void *)addr, free_size);
+#endif
+
+	kfence_metadata_init = NULL;
+	__kfence_pool = NULL;
+	return err;
 }
 
 static int kfence_enable_late(void)
@@ -941,6 +985,10 @@ void kfence_shutdown_cache(struct kmem_cache *s)
 	struct kfence_metadata *meta;
 	int i;
 
+	/* Pairs with release in kfence_init_pool(). */
+	if (!smp_load_acquire(&kfence_metadata))
+		return;
+
 	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
 		bool in_use;
 
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index 392fb273e7bd..f46fbb03062b 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -102,7 +102,10 @@ struct kfence_metadata {
 #endif
 };
 
-extern struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
+#define KFENCE_METADATA_SIZE PAGE_ALIGN(sizeof(struct kfence_metadata) * \
+					CONFIG_KFENCE_NUM_OBJECTS)
+
+extern struct kfence_metadata *kfence_metadata;
 
 static inline struct kfence_metadata *addr_to_metadata(unsigned long addr)
 {
diff --git a/mm/mm_init.c b/mm/mm_init.c
index 7f7f9c677854..3d0a63c75829 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -2721,7 +2721,7 @@ void __init mm_core_init(void)
 	 */
 	page_ext_init_flatmem();
 	mem_debugging_and_hardening_init();
-	kfence_alloc_pool();
+	kfence_alloc_pool_and_metadata();
 	report_meminit();
 	kmsan_init_shadow();
 	stack_depot_early_init();
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230718073019.52513-1-zhangpeng.00%40bytedance.com.
