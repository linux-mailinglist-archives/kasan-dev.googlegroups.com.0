Return-Path: <kasan-dev+bncBAABBHHQS2IQMGQE3NEUMKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id D3DE94CF2D6
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Mar 2022 08:45:34 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id c1-20020a9d67c1000000b005b2353e2c03sf2114930otn.8
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Mar 2022 23:45:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646639133; cv=pass;
        d=google.com; s=arc-20160816;
        b=XPjLUfgEpR3ylPAkT5ZCrBf1PY71854fV1+3ZXEE1ozV+XJ++/A60mSFrV2O5QVaMk
         brEQFwKivdSi1Mlk6/gmcCULEvzpNxNK0w/HOAvLRpEQrUHCi2zKSABC9VTG4NMPSwCt
         dcSwscji9D0SkagHRkYQjr1yjSv5pbgj5LGILv4qSiFTjUta85PlbA5LawYh0Z8/4n+C
         MnIxuOJRNeGM9xP1vp+PFQJV7WNAdwdtTR5VT5uJFvu9GLLEAezO116uV81iPL8ep5iG
         f0ckEX31lORdQl7M8Z0xa28kOxRXoLZLJRq35fOStOK4BkTGY94MsnfmO88V9Ch4o7c5
         6eGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4jEL6Rkuzv5gGQrDMM8WvphM4hYilkUq0uybMtRUreE=;
        b=FG+7OnX1V7jDtVlznKK0rx/P+p0S5HLG+jyPK6EFZJgjlu2b0n3oMOgcZf2Z5JCssk
         nj/S5GixL/YzyIDiIoJcHqQGYiuMyKXuy+KPZIifNpx2PwuTKsx2UaAe+EvUq99bzsAx
         juMdEunJ2ucUtNlJTzvhQ1lqlGXom2GCW5vKBYatGb/ilUxGEu4Txb48Jk1dm2GcMOQi
         WKj6w088uF7d6rfjDHsQNwHalVEEk+YGETC5NvyM3IfnylD0Ty3tnEzdmBrHsqqHsn+A
         DxfY567grkNB5oI6axfX7ydsF6eXHGFevCaawZX/4oFkjqAjT3BH11dNjYmi4uOG3xEi
         pN+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.131 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4jEL6Rkuzv5gGQrDMM8WvphM4hYilkUq0uybMtRUreE=;
        b=Nzcvr+tmOjhFcbyOsXsFf04+xUaRA/Ous9Hl/giq+GjoNYDgZbmqitE+LMWriKkQ9T
         vfxoOds+ZrK+xLfj7VnA0jSrXLhtEBGKIcG81UsuonHP12eJpkIhCO/sEa11Ds2phFO0
         3UtE/WbiMmd2DCOTwVMU4gsEWprBOwK4MaLBvT2ZYWFp54sxHLIl35zERzvrdPsrztbC
         3HUG8UKfIe2pxUwi5+u0x/gqE+9Cf35JJ9x5xm2+eWbXRQu86xwhkJsdmnx7QAWC+u0t
         S8gOWD1c7LP7BS21HwQVIqN0JSZmJi6bpwaztpVMm9I13S52EJHEMrxqwis4bZli0hvs
         Fvdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4jEL6Rkuzv5gGQrDMM8WvphM4hYilkUq0uybMtRUreE=;
        b=uqqxIJ95xrf26Sk1uic+wVQ7FGYOsdeogHCtxJixCRPF5UpKMyjsttavsUncpJUBUh
         1+3yxKPhXcQAFo+p7HPCx1r2sAYUdn9eubZsINa1Tkrem+s2FB3KV3FaV79K+5AsfnQp
         jqhCUk7p8X8yBozBC9kQDEYlLD5B2x46jETzgqEb8Zuh1LUx+1vvRbJedV67tKMlO/6e
         FxQzfzGmlZN9vGrexLX85hQdKYLsm7+frDYBipRDrcicglLrivFoyWrEBVp5QY/YOBEo
         9karTf4uba5yO9Z6/rkpbwZOVNbEyFWp7ftfKieDUqkWjHzI8iw+qzKJX+dAsODibfWG
         B8Nw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533pdeukaTUJcSF5PY8kXSQi1YLzrWUjb2GFpljC5MT7vLSRI1Jc
	YeQvBfHGGCPPv5qG1cDdqBk=
X-Google-Smtp-Source: ABdhPJwFj9Tc1RCNX0rlE+To9BrSJXkInVpTnPJ6FUoZDNr8C+5woLj+/DWMoZWHiG5lMef1LhhxwA==
X-Received: by 2002:a05:6808:3096:b0:2d9:a01a:4891 with SMTP id bl22-20020a056808309600b002d9a01a4891mr6854128oib.220.1646639132725;
        Sun, 06 Mar 2022 23:45:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:60a0:b0:d3:7b7b:e67 with SMTP id
 t32-20020a05687060a000b000d37b7b0e67ls3867216oae.7.gmail; Sun, 06 Mar 2022
 23:45:31 -0800 (PST)
X-Received: by 2002:a05:6870:17a1:b0:da:b3f:3258 with SMTP id r33-20020a05687017a100b000da0b3f3258mr5017641oae.264.1646639131928;
        Sun, 06 Mar 2022 23:45:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646639131; cv=none;
        d=google.com; s=arc-20160816;
        b=lYHi4F4AXP6cr80Z7U5yfOCm/csb34Y+WCp4bIBCrI/VK2tR+j4BcGj3G5nkMdd5HF
         YqhAYDE2ANJyntrBT4lvMjbiA8czCseItUj2ICzfhEkaCllxB79xyyHn+OqUQ4gESGd4
         Eun7jeh9HG6GhZvbQAtbK2iEu011S3fy2Vo9MsN8yPUqL5Pg55rOBCTe/7IyFbVJJJMN
         jI6kM4/RUBWZL8k34TEaqDEHQjA3AVILN6TkqXkZROrmbvSgW0KDCokts5i5mK31UJ3N
         aJFSBtnE+WrrORGayfSVjLVAifyrpsnSR69NBp1+BLfqCLfATOv8ReCI4noWjl2SHNwr
         3zXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=T2iUoVzh0mFl6PeEc3NrZvYOl1di4V5AdFqmBEsXiWw=;
        b=iH6OIIsJX7Y158gscyMCBtlQk4w3Kp52rSg4nhxJ3QqWr9Zg8mTFvorK+hZasiTRT0
         HJtrSkYhcsyT/Utn3iRMP7YqAqKhdvwh9HlqAzFVTRcKGX53tlKy456661xVoo6k/EDJ
         fokI1/Op5Sh8M2Y6gJFRanRbvsdX6aeY8C9QdUdNBc1qc3509DkTfqXWq9qhKS5d2OQn
         4d/9oOozq41Db4/crgYNITHgyW+k42QdV+qkD5wpti0eXC+Y0vl3RaHCpWTa0c/gYW+b
         xjYxoDH67/WKeokzzZeaIC/I4CIN651wb1U3SFDT0bQAzWSyVxMVENgwt7EZZi18B/QJ
         Qmhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.131 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-131.freemail.mail.aliyun.com (out30-131.freemail.mail.aliyun.com. [115.124.30.131])
        by gmr-mx.google.com with ESMTPS id e184-20020acab5c1000000b002cf48b6b783si1589447oif.1.2022.03.06.23.45.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Mar 2022 23:45:31 -0800 (PST)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.131 as permitted sender) client-ip=115.124.30.131;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R161e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04426;MF=dtcccc@linux.alibaba.com;NM=1;PH=DS;RN=7;SR=0;TI=SMTPD_---0V6SREfU_1646639126;
Received: from localhost.localdomain(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0V6SREfU_1646639126)
          by smtp.aliyun-inc.com(127.0.0.1);
          Mon, 07 Mar 2022 15:45:27 +0800
From: Tianchen Ding <dtcccc@linux.alibaba.com>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v3 2/2] kfence: Alloc kfence_pool after system startup
Date: Mon,  7 Mar 2022 15:45:16 +0800
Message-Id: <20220307074516.6920-3-dtcccc@linux.alibaba.com>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20220307074516.6920-1-dtcccc@linux.alibaba.com>
References: <20220307074516.6920-1-dtcccc@linux.alibaba.com>
MIME-Version: 1.0
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.131 as
 permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
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

Allow enabling KFENCE after system startup by allocating its pool via the
page allocator. This provides the flexibility to enable KFENCE even if it
wasn't enabled at boot time.

Signed-off-by: Tianchen Ding <dtcccc@linux.alibaba.com>
---
 mm/kfence/core.c | 111 ++++++++++++++++++++++++++++++++++++++---------
 1 file changed, 90 insertions(+), 21 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index caa4e84c8b79..f126b53b9b85 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -96,7 +96,7 @@ static unsigned long kfence_skip_covered_thresh __read_mostly = 75;
 module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644);
 
 /* The pool of pages used for guard pages and objects. */
-char *__kfence_pool __ro_after_init;
+char *__kfence_pool __read_mostly;
 EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
 
 /*
@@ -537,17 +537,19 @@ static void rcu_guarded_free(struct rcu_head *h)
 	kfence_guarded_free((void *)meta->addr, meta, false);
 }
 
-static bool __init kfence_init_pool(void)
+/*
+ * Initialization of the KFENCE pool after its allocation.
+ * Returns 0 on success; otherwise returns the address up to
+ * which partial initialization succeeded.
+ */
+static unsigned long kfence_init_pool(void)
 {
 	unsigned long addr = (unsigned long)__kfence_pool;
 	struct page *pages;
 	int i;
 
-	if (!__kfence_pool)
-		return false;
-
 	if (!arch_kfence_init_pool())
-		goto err;
+		return addr;
 
 	pages = virt_to_page(addr);
 
@@ -565,7 +567,7 @@ static bool __init kfence_init_pool(void)
 
 		/* Verify we do not have a compound head page. */
 		if (WARN_ON(compound_head(&pages[i]) != &pages[i]))
-			goto err;
+			return addr;
 
 		__SetPageSlab(&pages[i]);
 	}
@@ -578,7 +580,7 @@ static bool __init kfence_init_pool(void)
 	 */
 	for (i = 0; i < 2; i++) {
 		if (unlikely(!kfence_protect(addr)))
-			goto err;
+			return addr;
 
 		addr += PAGE_SIZE;
 	}
@@ -595,7 +597,7 @@ static bool __init kfence_init_pool(void)
 
 		/* Protect the right redzone. */
 		if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
-			goto err;
+			return addr;
 
 		addr += 2 * PAGE_SIZE;
 	}
@@ -608,9 +610,21 @@ static bool __init kfence_init_pool(void)
 	 */
 	kmemleak_free(__kfence_pool);
 
-	return true;
+	return 0;
+}
+
+static bool __init kfence_init_pool_early(void)
+{
+	unsigned long addr;
+
+	if (!__kfence_pool)
+		return false;
+
+	addr = kfence_init_pool();
+
+	if (!addr)
+		return true;
 
-err:
 	/*
 	 * Only release unprotected pages, and do not try to go back and change
 	 * page attributes due to risk of failing to do so as well. If changing
@@ -623,6 +637,26 @@ static bool __init kfence_init_pool(void)
 	return false;
 }
 
+static bool kfence_init_pool_late(void)
+{
+	unsigned long addr, free_size;
+
+	addr = kfence_init_pool();
+
+	if (!addr)
+		return true;
+
+	/* Same as above. */
+	free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
+#ifdef CONFIG_CONTIG_ALLOC
+	free_contig_range(page_to_pfn(virt_to_page(addr)), free_size / PAGE_SIZE);
+#else
+	free_pages_exact((void *)addr, free_size);
+#endif
+	__kfence_pool = NULL;
+	return false;
+}
+
 /* === DebugFS Interface ==================================================== */
 
 static int stats_show(struct seq_file *seq, void *v)
@@ -771,31 +805,66 @@ void __init kfence_alloc_pool(void)
 		pr_err("failed to allocate pool\n");
 }
 
+static void kfence_init_enable(void)
+{
+	if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))
+		static_branch_enable(&kfence_allocation_key);
+	WRITE_ONCE(kfence_enabled, true);
+	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
+	pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
+		CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
+		(void *)(__kfence_pool + KFENCE_POOL_SIZE));
+}
+
 void __init kfence_init(void)
 {
+	stack_hash_seed = (u32)random_get_entropy();
+
 	/* Setting kfence_sample_interval to 0 on boot disables KFENCE. */
 	if (!kfence_sample_interval)
 		return;
 
-	stack_hash_seed = (u32)random_get_entropy();
-	if (!kfence_init_pool()) {
+	if (!kfence_init_pool_early()) {
 		pr_err("%s failed\n", __func__);
 		return;
 	}
 
-	if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))
-		static_branch_enable(&kfence_allocation_key);
-	WRITE_ONCE(kfence_enabled, true);
-	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
-	pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
-		CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
-		(void *)(__kfence_pool + KFENCE_POOL_SIZE));
+	kfence_init_enable();
+}
+
+static int kfence_init_late(void)
+{
+	const unsigned long nr_pages = KFENCE_POOL_SIZE / PAGE_SIZE;
+#ifdef CONFIG_CONTIG_ALLOC
+	struct page *pages;
+
+	pages = alloc_contig_pages(nr_pages, GFP_KERNEL, first_online_node, NULL);
+	if (!pages)
+		return -ENOMEM;
+	__kfence_pool = page_to_virt(pages);
+#else
+	if (nr_pages > MAX_ORDER_NR_PAGES) {
+		pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocator\n");
+		return -EINVAL;
+	}
+	__kfence_pool = alloc_pages_exact(KFENCE_POOL_SIZE, GFP_KERNEL);
+	if (!__kfence_pool)
+		return -ENOMEM;
+#endif
+
+	if (!kfence_init_pool_late()) {
+		pr_err("%s failed\n", __func__);
+		return -EBUSY;
+	}
+
+	kfence_init_enable();
+	return 0;
 }
 
 static int kfence_enable_late(void)
 {
 	if (!__kfence_pool)
-		return -EINVAL;
+		return kfence_init_late();
 
 	WRITE_ONCE(kfence_enabled, true);
 	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220307074516.6920-3-dtcccc%40linux.alibaba.com.
