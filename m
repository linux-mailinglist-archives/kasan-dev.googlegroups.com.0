Return-Path: <kasan-dev+bncBDGZTDNQ3ICBBZWCXGSQMGQE4ND7RTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id ADA3075010A
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Jul 2023 10:16:40 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-263047f46f4sf349396a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Jul 2023 01:16:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689149799; cv=pass;
        d=google.com; s=arc-20160816;
        b=XqmCmI01TUeeaAFPBodcCCwZJ8e00w+H1YR9RF7jStCXpGkaXItZqlN5N5pAoRHvTJ
         9HDPb1iKasGtDwfevZn1u2seWdtVQTwbjE4WKRvEVj5sLK+LYf3f6o+xssn0CPPfplfk
         /TSUxWkbRkaAriOXdNZ7CXcdeUkzXUnloXzabFENajGeQt/SOkE2Jp6hFWvRNHiO3/sf
         rbLQ5w05+ATpTkJvQIOsEi7tcP+3wsUdrik+g/KO/neKBHA30t9zw0mmkhUXAo1lMNJ2
         7nrdgX64f+AtrK6+KEsPAuDfweYOCyyE9MODhlUpGb/OTNQcpxO9aLQTjZOEGRjPyYJh
         Aieg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=+4CCSzV3eg3lvQq9VeEpPE9wBLdVRD4RUK8MFRdAaQY=;
        fh=2vNDz2r49DP/PlWxfCRxgW7k9QySHJXLDaTm5YbQXtY=;
        b=GEivPB9u0JGDG1F0jzn3znBNKgAHqOuKEJFADvzQU774GkdtZkoBl2udYbmsYf+23b
         eO+X3RnQ/kBo+Kdh4bZUSRtuiOHasK8nITlOC2MQKuLu/P0EasQdFD+QBlSLX9B+BRi7
         SGqgS6nxf4rR0j92UbiBOq1cBkaFe8viowqyU7Q5O9aryoMmwdZJWuMh7TMHmI8dupf/
         SKywuznaZEAjM7f9WlarYKzoiwlDLwFHwhSCu2J2W41eow+7+I2ttXHWYiGMtttvd/Da
         +UBq3mPnJ9p9hNW6yVF6EOBlO+GOPXgjOjh6JR81IoJGRldJxQzeUvAkhQ/D0U5N1imp
         515g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b="BNe6/5m0";
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689149799; x=1691741799;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+4CCSzV3eg3lvQq9VeEpPE9wBLdVRD4RUK8MFRdAaQY=;
        b=WlZ6VfQANYro5alQ5jeMxbyr+cJaH9wEhMUtkHvpQe6YzC/w63qH8qwLmwxnsWL1Cy
         FGyl1wpYUTziks462qWp/yKVM35NlTfovVyG8ydujHd1eGJhbSd9WTUKL7Kee1CvLxK4
         o6Dk05WG+nmM8gje20mqJg/Ni23AUp9ysJTj+QsUloFoXZTwpvyN1Sm5IlM4b0XXL4At
         RvvUnqpH3jV3LVIOpOOeRnUoUcuWfTjwsaPEOxb8QwqWFPGIj3yknEB+sPYGXzSEJAWb
         pqxUdiDi6SzHDolSRSA4fy+DDMznwlIGTaTaPLi88jZrJSy3nQENTPQEtxcJf2AxCNN9
         zr3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689149799; x=1691741799;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+4CCSzV3eg3lvQq9VeEpPE9wBLdVRD4RUK8MFRdAaQY=;
        b=EuMz8HejP3wEBpUBc/mOHLx0k9za7qoWAAfqnhXTLp184qoGsES+Ua3I7SbCMPllVE
         EGWqaLiHWX0sjfZEtAMvUCOir2dvdX1tp58Yp5iOP1ZAqyIRlHnabyhUe8o6SEh5Uf3v
         tJuKNVqyIVvhDL36WKzFglPG1yNzfTrrOZcnRaLa/Pi3eNVLc4dPd3Tu87Sd8WPjs8Z6
         xF1M52dGNXgY6E1Ws+DWFuWV+fLyFmQE6dmUWjij9E0HyVEAxmtv2HsLbODrtXIZS6TO
         tIaEYOdjFBexeVKkhKsuJQhcIMgmsZa97eP54hgTDTOv6NMqwqhxi/zO2BIQZQBB5000
         ClHg==
X-Gm-Message-State: ABy/qLayTrLqWGB+aFSEaHJ4cWW+AUCV2i8+psc2t52KY0i04OA9l3IC
	JBs2yrwCIvPZ89X/v++ixWY=
X-Google-Smtp-Source: APBJJlHgMzQYgbEBJXKk5rwIUNJW/QyxkvARlHpYp76UNBAVWx9NiU9ivul4Qr085hjkPAQGLDsSRg==
X-Received: by 2002:a17:90a:7605:b0:265:780e:5edc with SMTP id s5-20020a17090a760500b00265780e5edcmr1795883pjk.10.1689149798745;
        Wed, 12 Jul 2023 01:16:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3c02:b0:25e:b0af:8b59 with SMTP id
 pb2-20020a17090b3c0200b0025eb0af8b59ls269772pjb.1.-pod-prod-00-us-canary;
 Wed, 12 Jul 2023 01:16:38 -0700 (PDT)
X-Received: by 2002:a17:90a:12c3:b0:263:7d48:64c4 with SMTP id b3-20020a17090a12c300b002637d4864c4mr1504461pjg.24.1689149797971;
        Wed, 12 Jul 2023 01:16:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689149797; cv=none;
        d=google.com; s=arc-20160816;
        b=DdcLbEWdXSYPeedBxerewZYWDQNWJlTyy20XDDggy62YfrZHuadwxbfPL2cBDu24Ne
         7kKnTd4a7U4Q77EnE5SaNBfxHhVRC/MbeKaiy6ixryC7Ar7bpVgwew/YpWNt8i4gZszR
         Yc0WV13yng4huNFvFgPlVypFscCtzyJV/qNLmOpFInVPomiOK3zSTOvp9uEM8jQmwl5C
         Thnk+xu2D8bujVhktfHubTDtcngq14RS7SauPAom14US6Xcrc4gANGsIrUP/1sFOvVKd
         /DFtQ2ekvwjoY3Zb+M6HBMF8eUj4n3UertAD3DOvzZqpxKv8OtYvnMJsmbzW4hp5ZUDT
         mykw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=oC+qyxbfAgsH4hJHeKoCaJaZtcxWMG8Si4Ik9TdQp1U=;
        fh=WeaUOvWwJDuKP9KhwGpUORxQHZzhkJChjku0draIx7o=;
        b=VVwcjrZq4AUWspX3tSjUaD/7U8fV+mF4kXirAWeFntsegSYxz+TXRXUXmbAq8RYliR
         KRMrjGqTLKbKNiTOPS7MG5BGf7uYXTFDM8I4LbTI71uMQp1OKihmGyKTOqtEhrss9ZkE
         vb+mnjBnSktYbrYn/t4KsH0hdA+XhzEN7e+msWeTGUl2D/Lwy40zE/ruiOJl43OfHVtG
         Yw6H2/2MzQwaTwPF9GnKedqpyZ0E7fuW8PYyPW25CmVgvCEYgibTcms8ObkvDlekgPuA
         bwC4NvHyjDiMtkPlPF/kcl1JBSgFt/00HVn8u0qkrCmDlX/YkoBc2CmDOvifR8brChjU
         ac6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b="BNe6/5m0";
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id qa14-20020a17090b4fce00b0025679987800si166170pjb.3.2023.07.12.01.16.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Jul 2023 01:16:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-668711086f4so327015b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 12 Jul 2023 01:16:37 -0700 (PDT)
X-Received: by 2002:a05:6a00:2b8d:b0:666:c1ae:3b87 with SMTP id dv13-20020a056a002b8d00b00666c1ae3b87mr1547140pfb.12.1689149797588;
        Wed, 12 Jul 2023 01:16:37 -0700 (PDT)
Received: from GL4FX4PXWL.bytedance.net ([139.177.225.243])
        by smtp.gmail.com with ESMTPSA id d7-20020aa78147000000b0063f2a5a59d1sm2988587pfn.190.2023.07.12.01.16.34
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Wed, 12 Jul 2023 01:16:37 -0700 (PDT)
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
Subject: [PATCH v2] mm: kfence: allocate kfence_metadata at runtime
Date: Wed, 12 Jul 2023 16:16:16 +0800
Message-Id: <20230712081616.45177-1-zhangpeng.00@bytedance.com>
X-Mailer: git-send-email 2.37.0 (Apple Git-136)
MIME-Version: 1.0
X-Original-Sender: zhangpeng.00@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b="BNe6/5m0";       spf=pass
 (google.com: domain of zhangpeng.00@bytedance.com designates
 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
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

kfence_metadata is currently a static array. For the purpose of
allocating scalable __kfence_pool, we first change it to runtime
allocation of metadata. Since the size of an object of kfence_metadata
is 1160 bytes, we can save at least 72 pages (with default 256 objects)
without enabling kfence.

Below is the numbers obtained in qemu (with default 256 objects).
before: Memory: 8134692K/8388080K available (3668K bss)
after: Memory: 8136740K/8388080K available (1620K bss)
More than expected, it saves 2MB memory. It can be seen that the size
of the .bss section has changed, possibly because it affects the linker.

Signed-off-by: Peng Zhang <zhangpeng.00@bytedance.com>
---
Changes since v1:
 - Fix a stupid problem of not being able to initialize kfence. The problem is
   that I slightly modified the patch before sending it out, but it has not been
   tested. I'm extremely sorry.
 - Drop kfence_alloc_metadata() and kfence_free_metadata() because they are no
   longer reused.
 - Allocate metadata from memblock during early initialization. Fixed the issue
   of allocating metadata size that cannot exceed the limit of the buddy system
   during early initialization.
 - Fix potential UAF in kfence_shutdown_cache().

v1: https://lore.kernel.org/lkml/20230710032714.26200-1-zhangpeng.00@bytedance.com/

 include/linux/kfence.h |   5 +-
 mm/kfence/core.c       | 124 ++++++++++++++++++++++++++++-------------
 mm/kfence/kfence.h     |   5 +-
 mm/mm_init.c           |   2 +-
 4 files changed, 94 insertions(+), 42 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 726857a4b680..68e71562bfa7 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -59,9 +59,10 @@ static __always_inline bool is_kfence_address(const void *addr)
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
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index dad3c0eb70a0..ed0424950cf1 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -116,7 +116,16 @@ EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
  * backing pages (in __kfence_pool).
  */
 static_assert(CONFIG_KFENCE_NUM_OBJECTS > 0);
-struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
+struct kfence_metadata *kfence_metadata;
+
+/*
+ * When kfence_metadata is not NULL, it may be that kfence is being initialized
+ * at this time, and it may be used by kfence_shutdown_cache() during
+ * initialization. If the initialization fails, kfence_metadata will be released,
+ * causing UAF. So it is necessary to add kfence_metadata_init for initialization,
+ * and kfence_metadata will be visible only when initialization is successful.
+ */
+static struct kfence_metadata *kfence_metadata_init;
 
 /* Freelist with available objects. */
 static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
@@ -591,7 +600,7 @@ static unsigned long kfence_init_pool(void)
 
 		__folio_set_slab(slab_folio(slab));
 #ifdef CONFIG_MEMCG
-		slab->memcg_data = (unsigned long)&kfence_metadata[i / 2 - 1].objcg |
+		slab->memcg_data = (unsigned long)&kfence_metadata_init[i / 2 - 1].objcg |
 				   MEMCG_DATA_OBJCGS;
 #endif
 	}
@@ -610,7 +619,7 @@ static unsigned long kfence_init_pool(void)
 	}
 
 	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
-		struct kfence_metadata *meta = &kfence_metadata[i];
+		struct kfence_metadata *meta = &kfence_metadata_init[i];
 
 		/* Initialize metadata. */
 		INIT_LIST_HEAD(&meta->list);
@@ -626,6 +635,12 @@ static unsigned long kfence_init_pool(void)
 		addr += 2 * PAGE_SIZE;
 	}
 
+	/*
+	 * Make kfence_metadata visible only when initialization is successful.
+	 * Otherwise, if the initialization fails and kfence_metadata is
+	 * freed, it may cause UAF in kfence_shutdown_cache().
+	 */
+	kfence_metadata = kfence_metadata_init;
 	return 0;
 
 reset_slab:
@@ -672,26 +687,10 @@ static bool __init kfence_init_pool_early(void)
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
 
@@ -841,19 +840,30 @@ static void toggle_allocation_gate(struct work_struct *work)
 
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
@@ -895,33 +905,68 @@ void __init kfence_init(void)
 
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
@@ -941,6 +986,9 @@ void kfence_shutdown_cache(struct kmem_cache *s)
 	struct kfence_metadata *meta;
 	int i;
 
+	if (!kfence_metadata)
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
index a1963c3322af..86b26d013f4b 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -2778,7 +2778,7 @@ void __init mm_core_init(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230712081616.45177-1-zhangpeng.00%40bytedance.com.
