Return-Path: <kasan-dev+bncBAABB3HQRWIQMGQEO3KZSBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 99CF84CE557
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Mar 2022 15:49:17 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id 190-20020a2505c7000000b00629283fec72sf315596ybf.5
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Mar 2022 06:49:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646491756; cv=pass;
        d=google.com; s=arc-20160816;
        b=rxFdmcIHIMzFMjoWSMzWrf8maN9tZijguiPOvfumiuuCFUisdE17qCm4zsJ0bmEC6k
         g+RoJgsuQ+vGnZzLycy0BA1lTpDF615iy8RzJ0D8xgjFzoMrJyygkG7RhjDCpk1YK/zX
         mpzQgvns2vTNB2HKKJyRXxJU+u1eZ4G8SFDrfGfLhuXfUBjud9KsfUalosNXb1nifRcu
         dSLAe9ylTfuDkU3e9MI/FpK99ZZ1/np8I1EtY72BqCy75CBoKkGDPMcYfrmjaonOpRBw
         ZcKOsxboSJr+ZTqhgtBapyvSWFfitE4bvOi6el8k9K4luPypMOwc40jOY0HDo5eVcd76
         /m7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WHlf74cgQ3M5h96cHRZsvuPlxYQuTfBl4N3HNXyucog=;
        b=uYxyRtRZ66Vy48s2Cd5WV3rkeAhYJthbPT3hkuulOBN6kEJMgn4wvGEqI06tLFHL4J
         960RvWU8cLF5WCs33vWNg2+ZQEX0MGmbBKev2bApSCzS2tlyCHofs42bkp+Y9FKkQv8n
         7F3oVeHmJQC4RhgnJhAHrsxfX2LZN/SzqSZAw/o3FI1Ab0CeS5pgW/KIn1leUJfx01D0
         0IIFYXyOqCJ+1qPOJpETDZlbJ5p4cwRp5UGrvMkqiSiMP76yi1HRlxW9r9lnO3AcGAwj
         HwkzP1xebFx/pNPj4ejnxLCdw02aJWaqrrwz6UkEe2UwUSsrCC0fDHvbdEz0v55xBMJG
         tNsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.132 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WHlf74cgQ3M5h96cHRZsvuPlxYQuTfBl4N3HNXyucog=;
        b=fB66Bg3DkjjLW6Tii282uuuknh4r8zD6+jRQiDz8SKTbd2wWJkyGdkN1SLP47eBOHh
         Q13rj8fpohFVKFoTo+vLMtvZY0WD2y/PncGwOUQD9VkV41TZgHdV3VTaaogqdqU2eY/q
         zXRowmhX9DI/X7WKkJDEc8lac5e5814UD67YEKmUv8y1BvQ8fOCQ9t+jhIFbmiSTUjCE
         8Eo4WRt8dhEujnQAnHYjHP6ZV1S41DagsbtRqH9xm/Sn4tCrIS/JsDB1wWfbCJHcc/V1
         sXIOCNJUHNXQ3js+n9wvbgVTt4Ggn9ULlD945gzTvqNNl2c3B+pl5mA4UCCvA/twc71e
         eF6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WHlf74cgQ3M5h96cHRZsvuPlxYQuTfBl4N3HNXyucog=;
        b=lDpo9qegC6d+WxJVVyZx6BH4/Aur7vOzPo+0YRYD+ftVT4JoI4fkD4s6tKtfi0sR3r
         HMhrHvK3dYtbM1tcCy2f55waT6DbexpKdV1/ETweeTbb9Hhjs+/YYps2oaa5d3lBbKTI
         elUNvmXEdVeCPrKrsKWMMlvUeZLjoUpDLYDLKERDjayDdy0vu6taq9BgsZwg2MkGiNl5
         st9VPWe51FdcAO+TBtWsM/U6us30ZNnnNfEL9UFYX8HW83npcY1r9vi6WQSEAXwcnXoh
         im7gjeJ27W8eGlBnAvF15/UyX5EUiIYV+GKKXHq79XnVeISPcR76wNBN9TTfp5O/RpHH
         0BvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530WsUJxeZwvdiQGYf1Ui3tkFzl76SZ9CnsHaxy16YOZ7Xon75Nc
	usS45gmMkVJ9bGO90v5dfUU=
X-Google-Smtp-Source: ABdhPJyzU/TwIT/t7T4LtvIlSF66YGCY8kwZNZ22RVxIBeF97VHnNDUApbxQTPlBE/qxu3wKMZylFQ==
X-Received: by 2002:a81:c24b:0:b0:2dc:7d67:a57a with SMTP id t11-20020a81c24b000000b002dc7d67a57amr2694216ywg.272.1646491756321;
        Sat, 05 Mar 2022 06:49:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1506:b0:628:b229:d51c with SMTP id
 q6-20020a056902150600b00628b229d51cls5714791ybu.3.gmail; Sat, 05 Mar 2022
 06:49:15 -0800 (PST)
X-Received: by 2002:a25:d6:0:b0:628:6c8e:d0db with SMTP id 205-20020a2500d6000000b006286c8ed0dbmr2657209yba.536.1646491755855;
        Sat, 05 Mar 2022 06:49:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646491755; cv=none;
        d=google.com; s=arc-20160816;
        b=eXN6Is+pKdoU4Jjrf4Jfd9/yevI2D6eh/n1b/GUP+gdYY7E2Pxzl98NFcwJJ+0SVRV
         UvTY6EHWjsxr+Lewr4H4Jmzj8lKXLv5i3vms367W98dHEB4zD8Wzl8ahTtGX0cYcOyMa
         JI9bgALI4WbZXN9qhQB0mWoslXl3r49NxGphgr2VSk1wQMrfIdy3JI9KTFX0exhgVhdn
         bDX+MhCrvoVFrv4qIsYorTiyfLxfnbkcH2DE/i6GyPLL+2TdBmJWindWrCX+vC5GGRQH
         lgBOBlck8LxlYB9ub2XNfZBucesOwOZxQYVdsZ4tg7PF3zlFcW71tBDSrwRdHdnnjcl5
         3byw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=06ZJxddYlVpX1xgQQovzH/SaOZ3N9Fqre2Yvr0tNU2I=;
        b=ArfliCmgJFZ9Y54GrOQxHHluuyNnhonOV0EBIDcqHCjufur6fFXRO4ni4P031ajuYh
         xUSGdkilJTPWiWJrDJem6Jgzpl6G/c8x9BguG2jsfhJ7+gfqsfei+TirVaoa4xyNAGf2
         KTdAzHpCY58h718sHWM5HVO25GXhp5zvto7UTiHBIl6nlbs2M21a4uRNm6WfpiSpBU6f
         IKG2dtUD5hwzQZ+/5rNZPTz0qdw88+10bIsm9Fk4FbUsPu9ez0H0bRxWfZYhHNq2t5Iy
         c9yd72vLRbsQeov0d3E60BmEjumgaOf7j0MZ2TbJUg41gnX58UDh7EoU0i1zIvukaXQt
         0pUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.132 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-132.freemail.mail.aliyun.com (out30-132.freemail.mail.aliyun.com. [115.124.30.132])
        by gmr-mx.google.com with ESMTPS id p22-20020a0de616000000b002dbf504c141si565076ywe.0.2022.03.05.06.49.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Mar 2022 06:49:15 -0800 (PST)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.132 as permitted sender) client-ip=115.124.30.132;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R671e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e01424;MF=dtcccc@linux.alibaba.com;NM=1;PH=DS;RN=7;SR=0;TI=SMTPD_---0V6HF7j0_1646491749;
Received: from localhost.localdomain(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0V6HF7j0_1646491749)
          by smtp.aliyun-inc.com(127.0.0.1);
          Sat, 05 Mar 2022 22:49:09 +0800
From: Tianchen Ding <dtcccc@linux.alibaba.com>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 2/2] kfence: Alloc kfence_pool after system startup
Date: Sat,  5 Mar 2022 22:48:58 +0800
Message-Id: <20220305144858.17040-3-dtcccc@linux.alibaba.com>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20220305144858.17040-1-dtcccc@linux.alibaba.com>
References: <20220305144858.17040-1-dtcccc@linux.alibaba.com>
MIME-Version: 1.0
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.132 as
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
 mm/kfence/core.c | 99 ++++++++++++++++++++++++++++++++++++++----------
 1 file changed, 78 insertions(+), 21 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index caa4e84c8b79..f46d63dd7676 100644
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
@@ -623,6 +637,22 @@ static bool __init kfence_init_pool(void)
 	return false;
 }
 
+static bool kfence_init_pool_late(void)
+{
+	unsigned long addr, free_pages;
+
+	addr = kfence_init_pool();
+
+	if (!addr)
+		return true;
+
+	/* Same as above. */
+	free_pages = (KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool)) / PAGE_SIZE;
+	free_contig_range(page_to_pfn(virt_to_page(addr)), free_pages);
+	__kfence_pool = NULL;
+	return false;
+}
+
 /* === DebugFS Interface ==================================================== */
 
 static int stats_show(struct seq_file *seq, void *v)
@@ -771,31 +801,58 @@ void __init kfence_alloc_pool(void)
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
+	struct page *pages;
+
+	pages = alloc_contig_pages(nr_pages, GFP_KERNEL, first_online_node, NULL);
+
+	if (!pages)
+		return -ENOMEM;
+
+	__kfence_pool = page_to_virt(pages);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220305144858.17040-3-dtcccc%40linux.alibaba.com.
