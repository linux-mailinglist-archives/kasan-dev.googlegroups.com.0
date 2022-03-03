Return-Path: <kasan-dev+bncBAABBSPFQCIQMGQEY5B3TQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A9D104CB544
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Mar 2022 04:15:22 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id x16-20020a6bfe10000000b006409f03e39esf2622846ioh.7
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 19:15:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646277321; cv=pass;
        d=google.com; s=arc-20160816;
        b=IQSYWHCxq3FJ7TDYqREsKkt7i+75fyLUghkVIWWWNd5hpSsFHfMk8iKQZ/UAJOu9Nw
         JHRdKZkfFa6dt3rY4vGtpiqT9nX3LvTeys/kvP7YLgLHnNrbHY+XTekCNlxr1U9y8K4b
         LFSkTOg8yMBPGk1ll6bY9NTk1jS5ollPXwmmLF+KpAiKYgL5Wyow6fu6X6JdEgPzBcQs
         KPquOrtK6o7ZQwOn62LylwwZNopZtXEFb12W7jRoHp5jbGXXJjo66VeJlsVTXjLZgMqa
         kGOMz5m4w6oksGDMcV4pN1Qg4h1sWnnM/7hcCJCmvEDE8maPY60yRfBfFBfLNCCumsEK
         EJeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IjddSU2z/MP+44v+Nb+z3HcuZ9bJhfvzJLnqX9WF5hQ=;
        b=eUIdjVqmi9EP07cTHYNAnVqWvGOpeaIDTTKN66mheZDZRkLVa47k2Mf1v2Z/dhnqNG
         gLbTElhbr6e8P8nQCiMLRAywI2SvD0HOkz0aSQU0O3CfyFdDCYjqQYDFfKqhPG+BHmgh
         haLWafrQTZXOAiEqZ/TIf1li9JP8t11zS5INeNGJkJbo3I2tDDSQfOXEadsyzSbolPuj
         fkJBcav2fBIo6zpGcJScxyo/p4VveuyxwlcYTDCj5LqgofJCa7+fwEvvOOn4Op++3Fcg
         yPfPyJ94Xk6V9K3RZvfoNUXcDVvoVF+zySWBvAZx2+j0yY8y7dIScamoVD6b7UgAMcgM
         JVGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.42 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IjddSU2z/MP+44v+Nb+z3HcuZ9bJhfvzJLnqX9WF5hQ=;
        b=p76MI7BNX1KpxRBr8nMUd0YDvaIfOgX/DkFqsKZCy79VyqrUDShfH0srCUGkkD7qe8
         yCnJy+159/CQmhIm+yZB5mrK3sItgP1t+L9hQfDQWP5YdXsCOt0FLl/M9pvh7Ig1rjms
         8XcEDq4pczdswWtFsmDmOvWHyXrQMAu/wYYFy63VddabLQ6CpA8d4sFht0b6l3OW/++R
         xa/XVHnVunygDJBpld9rmL6fPYMA1qa1J34rcBDhz+T+PHFbrNIYZdRSzzk+QPD6SMdH
         Bloow597bZv6D/wbYsq6RrBRaWmTFqNZUjZBPnQffLXIg8/COCQCa0fBUeecNkUr9o/T
         uHEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IjddSU2z/MP+44v+Nb+z3HcuZ9bJhfvzJLnqX9WF5hQ=;
        b=F32+0QqyUlqgNYAYiymSD/x94g+TB/V7DHIFB4EJ5Nh2OqQ4XSacIKzK32RYhlR89r
         E4KsonqVkskfMStqqvPxxOASbcDYbqV3C55dlksix2mmvM2b1uG5OjzeoF0qTxZgfSgJ
         fJ/aKJP6iBFfK48D/k/sMa2UQRwXgorpEkixUn3J/RltWNW8iwHriS6p3jmrUA3zcquf
         Z8pBxwJHU586kcPyq303ip/gI9Z8twsWt0R/i+wdDGc13Tk43S7jJVEKGZngmiXpH82h
         z+dmXGyyNLDqOu/hEn+tp/Uf8we1S4fFOIxYZmgXBpK/Fl7nSugHzGrhLdNpzh/gbPnt
         4S7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53333iuTkP/CzKbjisgS0G/SGN4MCW4Tcwiromt9CRAdXX7kolSY
	9rtBW2y9Acj9HVIb7EEhzdo=
X-Google-Smtp-Source: ABdhPJw/tQ12HyvzvJtjqiOJ0tdKgNHx9KNgraBT4iLhDdExpw8JfNOS/BrIJsQvTb2FWTPw5RrStw==
X-Received: by 2002:a92:cd41:0:b0:2c2:a257:98d4 with SMTP id v1-20020a92cd41000000b002c2a25798d4mr28129498ilq.307.1646277321365;
        Wed, 02 Mar 2022 19:15:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2252:b0:641:2788:aad7 with SMTP id
 o18-20020a056602225200b006412788aad7ls152325ioo.2.gmail; Wed, 02 Mar 2022
 19:15:21 -0800 (PST)
X-Received: by 2002:a5d:8946:0:b0:63d:aa75:40ad with SMTP id b6-20020a5d8946000000b0063daa7540admr25298019iot.148.1646277320985;
        Wed, 02 Mar 2022 19:15:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646277320; cv=none;
        d=google.com; s=arc-20160816;
        b=NKZ7p8qLfuKVMqzPnUxf/e1vhRE2ZsIbrSf33Vmqk7qwMJS0ScuY3k3CxmlvtaXiL0
         14Z7PggPeHkJgEPMK+rZp2mYp3WirBEbpQW6wVK23XD0ElmQD/yhN+m2RS2h9npFxIAl
         T9Na8pgty7DImdgaxn70AEVBC/aejDML8KcyD1fvJKCRM8oSgHPKaCZeQ7dH9aRvBY86
         QQ9UM5koNO0ZlAB5vG5pPEFD8Q3Z+9vCQpCea5iEmg3/xW2CCH9R91iBK8kRG6coUmaW
         KGJJwBy0IclykGjagE3odCUuQd1pV+z0xHUSUqpLZWFA4I3UqDAMsFCh2lx2NC9/966c
         ABog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=tFumf1uxPHXey7k74/mmLJmz1siOSZWFmTx6iHT6xnM=;
        b=V9d7/d+kHvCfnv458XZino8cKT1O6YuAtHPbQgYkz1yiVuda0t7fpykrGNx+Fmr/hA
         WFNFIuMa5bRIPt9kK1LCTY6RYtn+zliV/Z5o6Sm8HlKn9A7FDLQGYtjmuX3VO1MgXMJg
         f4N/6U/EqaDZragyGTJq4myXph6cQLquvTL+aIPi4gQfN5gNQc6i9kqal071Y0vixqzQ
         NIIF+9iQ2uJumM6s7uKAwyatoDZkoobkcckPoAv1byNsrpc7y2RY6bseA54gsKCwrU/I
         mBGNsnOVI8UwlCWIBnDL34FALOqgIXXy+db0O6dagL+XOB3tApEYpP7TmnpY8ukDSShg
         hgcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.42 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-42.freemail.mail.aliyun.com (out30-42.freemail.mail.aliyun.com. [115.124.30.42])
        by gmr-mx.google.com with ESMTPS id a15-20020a92660f000000b002c51ea34d0fsi54867ilc.1.2022.03.02.19.15.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Mar 2022 19:15:20 -0800 (PST)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.42 as permitted sender) client-ip=115.124.30.42;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R591e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04423;MF=dtcccc@linux.alibaba.com;NM=1;PH=DS;RN=7;SR=0;TI=SMTPD_---0V650kGb_1646277315;
Received: from localhost.localdomain(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0V650kGb_1646277315)
          by smtp.aliyun-inc.com(127.0.0.1);
          Thu, 03 Mar 2022 11:15:15 +0800
From: Tianchen Ding <dtcccc@linux.alibaba.com>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [RFC PATCH 2/2] kfence: Alloc kfence_pool after system startup
Date: Thu,  3 Mar 2022 11:15:05 +0800
Message-Id: <20220303031505.28495-3-dtcccc@linux.alibaba.com>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20220303031505.28495-1-dtcccc@linux.alibaba.com>
References: <20220303031505.28495-1-dtcccc@linux.alibaba.com>
MIME-Version: 1.0
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.42 as
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

KFENCE aims at production environments, but it does not allow enabling
after system startup because kfence_pool only alloc pages from memblock.
Consider the following production scene:
At first, for performance considerations, production machines do not
enable KFENCE.
However, after running for a while, the kernel is suspected to have
memory errors. (e.g., a sibling machine crashed.)
So other production machines need to enable KFENCE, but it's hard for
them to reboot.

Allow enabling KFENCE by alloc pages after system startup, even if
KFENCE is not enabled during booting.

Signed-off-by: Tianchen Ding <dtcccc@linux.alibaba.com>
---
This patch is similar to what the KFENCE(early version) do on ARM64.
Instead of alloc_pages(), we'd prefer alloc_contig_pages() to get exact
number of pages.
I'm not sure about the impact of breaking __ro_after_init. I've tested
with hackbench, and it seems no performance regression.
Or any problem about security?
---
 mm/kfence/core.c | 96 ++++++++++++++++++++++++++++++++++++++----------
 1 file changed, 76 insertions(+), 20 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 19eb123c0bba..ae69b2a113a4 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -93,7 +93,7 @@ static unsigned long kfence_skip_covered_thresh __read_mostly = 75;
 module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644);
 
 /* The pool of pages used for guard pages and objects. */
-char *__kfence_pool __ro_after_init;
+char *__kfence_pool __read_mostly;
 EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
 
 /*
@@ -534,17 +534,18 @@ static void rcu_guarded_free(struct rcu_head *h)
 	kfence_guarded_free((void *)meta->addr, meta, false);
 }
 
-static bool __init kfence_init_pool(void)
+/*
+ * The main part of init kfence pool.
+ * Return 0 if succeed. Otherwise return the address where error occurs.
+ */
+static unsigned long __kfence_init_pool(void)
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
 
@@ -562,7 +563,7 @@ static bool __init kfence_init_pool(void)
 
 		/* Verify we do not have a compound head page. */
 		if (WARN_ON(compound_head(&pages[i]) != &pages[i]))
-			goto err;
+			return addr;
 
 		__SetPageSlab(&pages[i]);
 	}
@@ -575,7 +576,7 @@ static bool __init kfence_init_pool(void)
 	 */
 	for (i = 0; i < 2; i++) {
 		if (unlikely(!kfence_protect(addr)))
-			goto err;
+			return addr;
 
 		addr += PAGE_SIZE;
 	}
@@ -592,7 +593,7 @@ static bool __init kfence_init_pool(void)
 
 		/* Protect the right redzone. */
 		if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
-			goto err;
+			return addr;
 
 		addr += 2 * PAGE_SIZE;
 	}
@@ -605,9 +606,21 @@ static bool __init kfence_init_pool(void)
 	 */
 	kmemleak_free(__kfence_pool);
 
-	return true;
+	return 0;
+}
+
+static bool __init kfence_init_pool(void)
+{
+	unsigned long addr;
+
+	if (!__kfence_pool)
+		return false;
+
+	addr = __kfence_init_pool();
+
+	if (!addr)
+		return true;
 
-err:
 	/*
 	 * Only release unprotected pages, and do not try to go back and change
 	 * page attributes due to risk of failing to do so as well. If changing
@@ -620,6 +633,22 @@ static bool __init kfence_init_pool(void)
 	return false;
 }
 
+static bool kfence_init_pool_late(void)
+{
+	unsigned long addr, free_pages;
+
+	addr = __kfence_init_pool();
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
@@ -768,31 +797,58 @@ void __init kfence_alloc_pool(void)
 		pr_err("failed to allocate pool\n");
 }
 
+static inline void __kfence_init(void)
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
 	if (!kfence_init_pool()) {
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
+	__kfence_init();
+}
+
+static int kfence_init_late(void)
+{
+	struct page *pages;
+	const unsigned long nr_pages = KFENCE_POOL_SIZE / PAGE_SIZE;
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
+	__kfence_init();
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220303031505.28495-3-dtcccc%40linux.alibaba.com.
