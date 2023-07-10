Return-Path: <kasan-dev+bncBDGZTDNQ3ICBBJ7VVWSQMGQEOWUJX4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id BEC9274CA86
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jul 2023 05:27:37 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-26304c2e178sf6826588a91.3
        for <lists+kasan-dev@lfdr.de>; Sun, 09 Jul 2023 20:27:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688959656; cv=pass;
        d=google.com; s=arc-20160816;
        b=WCx/YGZ2/l+MhIEkupT/w6By+fvtWCYaIbX5xSnE3FZwlf64XidKMj2O83yvny3sDZ
         7BxGKZ142B/KxGJ5YXbpVY13b8nQHWMj24qkxxXFLswzBPp7DCMRlGy7UNxUlQuubPY2
         89byn/CbAsXjBnyKOAu+FyFCpCwrEKt8Is9ILXxVomDsHQUmZEj9LfRoaWhUKp+P84sB
         dPZUm4ySX1TsvWDniLr+f1Z+IUrTQxj/XXvd+4TWZSmtSV1ToW1ZyfoWerVzuQiNx0W2
         t0b+3AIPByZ2iawVq3WkyDglkheJVqqHIZ/CUZGTLCDN1au9y+EJPw7zuOBKhEZ3aqD+
         M38w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=yI0M0aDpbSDhSm7aNmNOiHW/X2zy1hEwJ8wlYDndJ2g=;
        fh=2vNDz2r49DP/PlWxfCRxgW7k9QySHJXLDaTm5YbQXtY=;
        b=TvysaJp9HMMocwaf8UuEOAXai4kftA4p9N8nRlj+DBp5kt6W+QpentsnqbcOdH6CGT
         Eb5wsAiKKVTdjQ9P0noRZqaI+V3gIi3zUqhKfFPLCIKwb4BIyij1krSZlUeKYyEDfDng
         R7mkMurIGnVzPA/WgCW5Z5Nyob5WFi8T6jE/vUgrVGA3T+dvoCPyfadmVFI9JjuRoAmN
         CZ1+EdaZxvduvgLhO+/RqmRcmWhOQ9vr0H6Bkf2OGv2yGuxNdEtYaUxTi6G29aWGAIK9
         DGrLnKfB/zG9LZ4VGJqIPVPq8hW1ohreCqZ39N6fZh745978+I1j/QArPRqNoHa/y9e1
         yEHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=T0Dkrsab;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688959656; x=1691551656;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yI0M0aDpbSDhSm7aNmNOiHW/X2zy1hEwJ8wlYDndJ2g=;
        b=BRnu/HW1F1m7RLE4YVGacYsVYO+6J9qToCneKf3QQz9TbXV387Fg1Y5xKCVNbIvucr
         pXId91P/W1oMAWr6t72xgxAuZyYhhnRrVHmYsl7drQyG7T29IZQ/4tNgvFzDYUliQOgf
         5LTR/SY+MEUHnB7VDc9MDjUo7LPkY9aWh5QINm5oeM8YrZhLU0FVH64lkqwXxHU4uDIX
         l95pa6UlijCPBh1avr35BlQhu4GHDAm0XbbVB8AcIIxRE2sDlivChs8PLNTNL0CCaLFO
         afVM5bRS+Gk6YXh2E2XLi8pfp5zhRo/hv1YV/hoHIDoJQcKZifz0tovwO92c+dtLSnLV
         v3vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688959656; x=1691551656;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yI0M0aDpbSDhSm7aNmNOiHW/X2zy1hEwJ8wlYDndJ2g=;
        b=dOZIMdozRqbp0wEwE5hJRyEh1JblR6cTPnOEf9MOCrGLR7ATFxWlzsz68O0B44iY0S
         t28fZicmODZM89o/mwaAzk6CO+Xjnl0fYJ2BPL6eZW4YaeQ+qSGonYfwt+MbgH9nHnIB
         YAR30Ui3syrvBcEFjOAc6v7TdwJbIdXOKTrPibTycvqv+pxO0C9hgIV/qi8jGJ7dlony
         XJ0ab47dczGtla8A0s8n0IMKR6A3Aj8QEMnq3AreMxWN/NQP5UIiaoLbg84M1w9tMy4U
         UtU2JQW46HgOteTFLcGUKEPnsb9/YDP1C0lRS7SD//K7WcZtiWvpj3RmzevQ4teloLWw
         4zwg==
X-Gm-Message-State: ABy/qLY/JYU3GnksQ2la+7hAlS6WKRKamdT+qHdGNDCbltilVuqkHOlM
	vlelr0SuuIruO0WJ8uQzebk=
X-Google-Smtp-Source: APBJJlH6RMkjrX9v1aoE1nyfy8sY9Zgwui9krgDasw3wcnBZRyBz2ABytF6kIpFMy9QyFVHIMxtrhA==
X-Received: by 2002:a17:90b:3a83:b0:262:d6cb:3567 with SMTP id om3-20020a17090b3a8300b00262d6cb3567mr12627153pjb.26.1688959655819;
        Sun, 09 Jul 2023 20:27:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f497:b0:262:df46:d00f with SMTP id
 bx23-20020a17090af49700b00262df46d00fls3809624pjb.1.-pod-prod-08-us; Sun, 09
 Jul 2023 20:27:34 -0700 (PDT)
X-Received: by 2002:a17:90b:384e:b0:262:e821:b3f8 with SMTP id nl14-20020a17090b384e00b00262e821b3f8mr12138181pjb.38.1688959654278;
        Sun, 09 Jul 2023 20:27:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688959654; cv=none;
        d=google.com; s=arc-20160816;
        b=Mn1XE/kPnFmLjeesLVuuCSaMp8Cogp8hhTaDEroecX6EKo+WMTyAsbjnf++7uGOULm
         BlKnuzAQwmjg4ZbxIKHbxBqmHFk9P+Fgtqi5+PXCQzwU1C6AZOoWLRVLcVf/lrNy0dbq
         Lvb95ogtIxj+oUlVvKfKbcT9hOJqBDjUADoOjZdxC6/eaos9++/GtvQaE2yIZ8/xEqVu
         jnkM5vnqnR6ZLpMl27IfeGBfpiqEsktZwaEMJ8NXdfSqm/N9mzj0L8AjMlB/aA8bJs5v
         hKPCeoDI6eYNcmDVBuKy9qkJR9rwV0zOQiSwYr0W7jnG7SyYcAMXQBQBJjLvJorSp/sw
         5tbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=z+IV/3EU3GY4vUZv6vrcuErb2vDPlc1Isf1U0nOs3EE=;
        fh=WeaUOvWwJDuKP9KhwGpUORxQHZzhkJChjku0draIx7o=;
        b=f1WG4STXkRWGMXAnrSsX26HbYVZQUACEeuteirL61ksUspzBg4CJWxwQ76tu+sCDce
         vjU7M+eat3Rzs/63gxi9VUEmituVTki0m34jqjYJwgekkYzSalCtvf90CDxVd7SvQCC/
         L5ytrQJGJk9BjFt+1UKPHEZyZ8Xp75bvsevSswr8n7hc4opSMfqalBM3Bv+J4fD8T4yl
         9nPqQm656wWmaA34JBn8YwNV4LXYio+Mmjyx3heueeUEKOcnra//0mJMOcfdMjRUHxo7
         VcTY7pVONy/j+jQOUHUtjBNQJP09aYw4dUvRkSK0h1+cdHN6HslZTTRD3Zf2FOLvGAsO
         V2AA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=T0Dkrsab;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id x30-20020a17090a38a100b00262f57676a1si656248pjb.1.2023.07.09.20.27.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 09 Jul 2023 20:27:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-6686c74183cso3498131b3a.1
        for <kasan-dev@googlegroups.com>; Sun, 09 Jul 2023 20:27:34 -0700 (PDT)
X-Received: by 2002:a05:6a00:1704:b0:682:2fea:39f0 with SMTP id h4-20020a056a00170400b006822fea39f0mr13853334pfc.5.1688959653872;
        Sun, 09 Jul 2023 20:27:33 -0700 (PDT)
Received: from GL4FX4PXWL.bytedance.net ([203.208.167.147])
        by smtp.gmail.com with ESMTPSA id j15-20020aa7800f000000b00682c864f35bsm6279748pfi.140.2023.07.09.20.27.30
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Sun, 09 Jul 2023 20:27:33 -0700 (PDT)
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
Subject: [PATCH] mm: kfence: allocate kfence_metadata at runtime
Date: Mon, 10 Jul 2023 11:27:14 +0800
Message-Id: <20230710032714.26200-1-zhangpeng.00@bytedance.com>
X-Mailer: git-send-email 2.37.0 (Apple Git-136)
MIME-Version: 1.0
X-Original-Sender: zhangpeng.00@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=T0Dkrsab;       spf=pass
 (google.com: domain of zhangpeng.00@bytedance.com designates
 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
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
More than expected, it saves 2MB memory.

Signed-off-by: Peng Zhang <zhangpeng.00@bytedance.com>
---
 mm/kfence/core.c   | 102 ++++++++++++++++++++++++++++++++-------------
 mm/kfence/kfence.h |   5 ++-
 2 files changed, 78 insertions(+), 29 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index dad3c0eb70a0..b9fec1c46e3d 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -116,7 +116,7 @@ EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
  * backing pages (in __kfence_pool).
  */
 static_assert(CONFIG_KFENCE_NUM_OBJECTS > 0);
-struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
+struct kfence_metadata *kfence_metadata;
 
 /* Freelist with available objects. */
 static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
@@ -643,13 +643,56 @@ static unsigned long kfence_init_pool(void)
 	return addr;
 }
 
+static int kfence_alloc_metadata(void)
+{
+	unsigned long nr_pages = KFENCE_METADATA_SIZE / PAGE_SIZE;
+
+#ifdef CONFIG_CONTIG_ALLOC
+	struct page *pages;
+
+	pages = alloc_contig_pages(nr_pages, GFP_KERNEL, first_online_node,
+				   NULL);
+	if (pages)
+		kfence_metadata = page_to_virt(pages);
+#else
+	if (nr_pages > MAX_ORDER_NR_PAGES) {
+		pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocator\n");
+		return -EINVAL;
+	}
+	kfence_metadata = alloc_pages_exact(KFENCE_METADATA_SIZE,
+					    GFP_KERNEL);
+#endif
+
+	if (!kfence_metadata)
+		return -ENOMEM;
+
+	memset(kfence_metadata, 0, KFENCE_METADATA_SIZE);
+	return 0;
+}
+
+static void kfence_free_metadata(void)
+{
+	if (WARN_ON(!kfence_metadata))
+		return;
+#ifdef CONFIG_CONTIG_ALLOC
+	free_contig_range(page_to_pfn(virt_to_page((void *)kfence_metadata)),
+			  KFENCE_METADATA_SIZE / PAGE_SIZE);
+#else
+	free_pages_exact((void *)kfence_metadata, KFENCE_METADATA_SIZE);
+#endif
+	kfence_metadata = NULL;
+}
+
 static bool __init kfence_init_pool_early(void)
 {
-	unsigned long addr;
+	unsigned long addr = (unsigned long)__kfence_pool;
 
 	if (!__kfence_pool)
 		return false;
 
+	if (!kfence_alloc_metadata())
+		goto free_pool;
+
 	addr = kfence_init_pool();
 
 	if (!addr) {
@@ -663,6 +706,7 @@ static bool __init kfence_init_pool_early(void)
 		return true;
 	}
 
+	kfence_free_metadata();
 	/*
 	 * Only release unprotected pages, and do not try to go back and change
 	 * page attributes due to risk of failing to do so as well. If changing
@@ -670,31 +714,12 @@ static bool __init kfence_init_pool_early(void)
 	 * fails for the first page, and therefore expect addr==__kfence_pool in
 	 * most failure cases.
 	 */
+free_pool:
 	memblock_free_late(__pa(addr), KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool));
 	__kfence_pool = NULL;
 	return false;
 }
 
-static bool kfence_init_pool_late(void)
-{
-	unsigned long addr, free_size;
-
-	addr = kfence_init_pool();
-
-	if (!addr)
-		return true;
-
-	/* Same as above. */
-	free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
-#ifdef CONFIG_CONTIG_ALLOC
-	free_contig_range(page_to_pfn(virt_to_page((void *)addr)), free_size / PAGE_SIZE);
-#else
-	free_pages_exact((void *)addr, free_size);
-#endif
-	__kfence_pool = NULL;
-	return false;
-}
-
 /* === DebugFS Interface ==================================================== */
 
 static int stats_show(struct seq_file *seq, void *v)
@@ -896,6 +921,10 @@ void __init kfence_init(void)
 static int kfence_init_late(void)
 {
 	const unsigned long nr_pages = KFENCE_POOL_SIZE / PAGE_SIZE;
+	unsigned long addr = (unsigned long)__kfence_pool;
+	unsigned long free_size = KFENCE_POOL_SIZE;
+	int ret;
+
 #ifdef CONFIG_CONTIG_ALLOC
 	struct page *pages;
 
@@ -913,15 +942,29 @@ static int kfence_init_late(void)
 		return -ENOMEM;
 #endif
 
-	if (!kfence_init_pool_late()) {
-		pr_err("%s failed\n", __func__);
-		return -EBUSY;
+	ret = kfence_alloc_metadata();
+	if (!ret)
+		goto free_pool;
+
+	addr = kfence_init_pool();
+	if (!addr) {
+		kfence_init_enable();
+		kfence_debugfs_init();
+		return 0;
 	}
 
-	kfence_init_enable();
-	kfence_debugfs_init();
+	pr_err("%s failed\n", __func__);
+	kfence_free_metadata();
+	free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
+	ret = -EBUSY;
 
-	return 0;
+free_pool:
+#ifdef CONFIG_CONTIG_ALLOC
+	free_contig_range(page_to_pfn(virt_to_page((void *)addr)), free_size / PAGE_SIZE);
+#else
+	free_pages_exact((void *)addr, free_size);
+#endif
+	return ret;
 }
 
 static int kfence_enable_late(void)
@@ -941,6 +984,9 @@ void kfence_shutdown_cache(struct kmem_cache *s)
 	struct kfence_metadata *meta;
 	int i;
 
+	if (!__kfence_pool)
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
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230710032714.26200-1-zhangpeng.00%40bytedance.com.
