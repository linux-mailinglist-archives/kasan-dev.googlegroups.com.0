Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHN2XKFQMGQE6MDHK3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F0F2433377
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Oct 2021 12:25:34 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id v18-20020a7bcb52000000b00322fea1d5b7sf965597wmj.9
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Oct 2021 03:25:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634639134; cv=pass;
        d=google.com; s=arc-20160816;
        b=C6ci74+OrpENfQBKRWOddPMu30VM3oqsoQrLzaYyIXh0mgkROvXGNdFEJWYiIpeOoz
         NGw40dueQdYBXMQAYBK1a/f1/NGVpHr/hEYvbzBCeTjWeTJYUeTWzKC7b0IvdpXfpF1J
         waQfVXQipVs4Ulj1Cd2VEAuzmmCxAphQ8DUe0KtB0N0QSU/uWLS+8t8BlZWCtqn8IJk0
         ULudCi/bwGV/8qgglU51jNwZsODwWyhaQP1bGBadADYFWNy7gR8aJwEWuEdsvzA8LZe3
         UHOzw03SnDpy9HShU4Snq9x5Gb4G9VK6Nsky8A+VOcUNXzvZuBOCcaaabysdnu9FLD/W
         dZ4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=hWck5ef4lbqf9jnh1fwSzsL7D8AgRG2QClkk1dBiJN8=;
        b=YHMJyivTyTGRdDHJ+Q8vm5zeMh+TGw7nBVBDnyZIt9kG6tyDj+lwU6eR7ViV8TDp3p
         rTL/7PYeV0MaJ8VeLXZsjJuoVCewvEpMRfa2uuu1Zbsk1Az8SkkSBgR5vN6tp2675zJl
         1QEb5QUAjtv2LQiLlbhmM/VIQ/JsafohyRav42HfzS5zaYi0qxiuj86w7VJxfc/jnt9W
         cGzhnT5Edlzoq1rjHBLI1JKpAR5cs+QtE8k6tAexi/fQrdiCDbvm5KoZ8CrKEz+2RZAO
         f/EbWEPNCP2N/3DTpaLBhiPVP1Cigp2Gv/ehHB/AC5osxr98HOYZjs0WTFgfySWW/aWK
         GoEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bLgLHB1E;
       spf=pass (google.com: domain of 3hj1uyqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HJ1uYQUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=hWck5ef4lbqf9jnh1fwSzsL7D8AgRG2QClkk1dBiJN8=;
        b=XeyYoCiIjgRcOXTb2d1Qu2jTfxETHbf0Ram59n951Mhf7YB0eLz3lfcEhcxgBGWQQ3
         lXmIsaXLocRILLkCGuYG4xBUiNdkAMp7001kgTXUbvh3gcjOmNtD9iAG9hWvcLVMPu9H
         DiF9+0OmHTxMB14JmOyL5MXWXRYNb0NEnsGW8ZllUTeAr6EVQ+1J6UOPIInyisogWADV
         P+Xc+NWwI70voj1cJ7Y+iSgc8KXZxuyblHQaQ3iiS54yhm1gyEuqt6ZJPtjobUJ6myi2
         R1Lu8rwOTaWtmz2usRBMAcJzf9IBv17JQLj9NtmougmmWvjEuJsIUU4q+o1v1E01vSO1
         JVyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hWck5ef4lbqf9jnh1fwSzsL7D8AgRG2QClkk1dBiJN8=;
        b=4k3tebHuH6bQzP3TnrnDBmYU2zlXNYYUJX+dW9znHDRx+uVtmOIPQYF+E2B9LASJaO
         /eLPYeaxtrz4FPmvl9zDr4O/CCJIZextVpJQw1Grdc37un8r6WfAvrMV9oCdelIKfNIl
         tL1cwshnZSwQR/YfUujNxT/Mv7etlsl3UG53fq0vGOJdQ7pkVCC50Fa9FKPDFW0vf78o
         0wYyx3APWDKns/Ouel2KnrkUm4SxkqpMcm9xNjau/OL4+M5dmWtd1zJh1tgYoWofDv4t
         dCdAa5c10wFr2p5JG2lFZBgSMI0xTxm+KYoUnwtXIIVYIkWqoe7/F2wn0XrItdW1bJyH
         DYVg==
X-Gm-Message-State: AOAM530tYDFbuvLscstxjjRi0iQVrCdrI8BiJ2lxhCK5L8Oa8ZZ7Eppr
	9Q8v4IXM1xYLTmYVWjaz5eU=
X-Google-Smtp-Source: ABdhPJwbuPFmFKRrbh3nCLgXaFAxOmq80DTiZnYXvAMAj5BLwo0qhrweuGIwq/ndBOVk8LS0A9xURA==
X-Received: by 2002:a5d:63ca:: with SMTP id c10mr42190725wrw.407.1634639133961;
        Tue, 19 Oct 2021 03:25:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2983:: with SMTP id p125ls967061wmp.2.canary-gmail; Tue,
 19 Oct 2021 03:25:33 -0700 (PDT)
X-Received: by 2002:a7b:c76b:: with SMTP id x11mr5194700wmk.83.1634639132987;
        Tue, 19 Oct 2021 03:25:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634639132; cv=none;
        d=google.com; s=arc-20160816;
        b=a1ZOASbJ1SRtwgvdFARWo5HA2znAU3/xiWYKIYnTCuMmZH48OGXAwk0fcHJbsSzrxl
         jxBK3kXIlZ/lQUP14hhzYe+hP2c5/gMSRzr9BbX+hbszdycB77e4sxdQy3byu4J0cJXe
         tnce0oh6fjXG8UBGJ8hz4eneIEAApiqc4QuDZ74RODinARCAhcER4B9Mxkh6H7Li41Pt
         bBZaQi0xpEptuE7VHbb6tbfJbmER/qESTE9zsA49QQHTgi0eMaZBpYSWuLnx7KuwBUVq
         QKXhmCpOJmbDHCdapyA6YGWG/Qa5ooMBaaek8OuAPUtLq5Gcb3Zmt9oEK1QPJSn5l/bu
         5VpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=QtB1JTnzUP+wCjNXipQfBq+gxdYpMqzkTaAZVfPtWwI=;
        b=ptU7C6H1mzwNqZwrKeauLhdoZB2dnlllr1daE8RjM/+CsXPaCAe9SLmEaNxTegEBEw
         tmRvwWLcxFqMkrlixqsXGHZwy3W81nEyYRPtYtT6vQX+la8GJMR+e+ChEnV3TmBDTp5X
         N+Hcg4tQzxxlpiwwWCAUPuwa/i1zNmSlpZJYewH0tCx12nylA9UIQwzqivls42pjlmYN
         5e+ku26I5m5JwFxNKMzhjOXMXij7ef7ZbkouIzBPDcAXrOGzrLSDAKhzWAP6d6r3HNK1
         WrZs43bpoKj6tEj0jWlYbNnZ6p5M58zwBT1Q6RxP0lC6On02rdEJYPNBvI3DEMIu6ICt
         HIrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bLgLHB1E;
       spf=pass (google.com: domain of 3hj1uyqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HJ1uYQUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id g2si179207wmc.4.2021.10.19.03.25.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Oct 2021 03:25:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hj1uyqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id k6-20020a7bc306000000b0030d92a6bdc7so974735wmj.3
        for <kasan-dev@googlegroups.com>; Tue, 19 Oct 2021 03:25:32 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:feca:f6ef:d785:c732])
 (user=elver job=sendgmr) by 2002:a1c:f31a:: with SMTP id q26mr5061343wmq.148.1634639132518;
 Tue, 19 Oct 2021 03:25:32 -0700 (PDT)
Date: Tue, 19 Oct 2021 12:25:23 +0200
Message-Id: <20211019102524.2807208-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.0.1079.g6e70778dc9-goog
Subject: [PATCH 1/2] kfence: always use static branches to guard kfence_alloc()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=bLgLHB1E;       spf=pass
 (google.com: domain of 3hj1uyqukcsmdkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HJ1uYQUKCSMDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Regardless of KFENCE mode (CONFIG_KFENCE_STATIC_KEYS: either using
static keys to gate allocations, or using a simple dynamic branch),
always use a static branch to avoid the dynamic branch in kfence_alloc()
if KFENCE was disabled at boot.

For CONFIG_KFENCE_STATIC_KEYS=n, this now avoids the dynamic branch if
KFENCE was disabled at boot.

To simplify, also unifies the location where kfence_allocation_gate is
read-checked to just be inline in kfence_alloc().

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kfence.h | 21 +++++++++++----------
 mm/kfence/core.c       | 16 +++++++---------
 2 files changed, 18 insertions(+), 19 deletions(-)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 3fe6dd8a18c1..4b5e3679a72c 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -14,6 +14,9 @@
 
 #ifdef CONFIG_KFENCE
 
+#include <linux/atomic.h>
+#include <linux/static_key.h>
+
 /*
  * We allocate an even number of pages, as it simplifies calculations to map
  * address to metadata indices; effectively, the very first page serves as an
@@ -22,13 +25,8 @@
 #define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
 extern char *__kfence_pool;
 
-#ifdef CONFIG_KFENCE_STATIC_KEYS
-#include <linux/static_key.h>
 DECLARE_STATIC_KEY_FALSE(kfence_allocation_key);
-#else
-#include <linux/atomic.h>
 extern atomic_t kfence_allocation_gate;
-#endif
 
 /**
  * is_kfence_address() - check if an address belongs to KFENCE pool
@@ -116,13 +114,16 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags);
  */
 static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 {
-#ifdef CONFIG_KFENCE_STATIC_KEYS
-	if (static_branch_unlikely(&kfence_allocation_key))
+#if defined(CONFIG_KFENCE_STATIC_KEYS) || CONFIG_KFENCE_SAMPLE_INTERVAL == 0
+	if (!static_branch_unlikely(&kfence_allocation_key))
+		return NULL;
 #else
-	if (unlikely(!atomic_read(&kfence_allocation_gate)))
+	if (!static_branch_likely(&kfence_allocation_key))
+		return NULL;
 #endif
-		return __kfence_alloc(s, size, flags);
-	return NULL;
+	if (likely(atomic_read(&kfence_allocation_gate)))
+		return NULL;
+	return __kfence_alloc(s, size, flags);
 }
 
 /**
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 802905b1c89b..09945784df9e 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -104,10 +104,11 @@ struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
 static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
 static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. */
 
-#ifdef CONFIG_KFENCE_STATIC_KEYS
-/* The static key to set up a KFENCE allocation. */
+/*
+ * The static key to set up a KFENCE allocation; or if static keys are not used
+ * to gate allocations, to avoid a load and compare if KFENCE is disabled.
+ */
 DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
-#endif
 
 /* Gates the allocation, ensuring only one succeeds in a given period. */
 atomic_t kfence_allocation_gate = ATOMIC_INIT(1);
@@ -774,6 +775,8 @@ void __init kfence_init(void)
 		return;
 	}
 
+	if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))
+		static_branch_enable(&kfence_allocation_key);
 	WRITE_ONCE(kfence_enabled, true);
 	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
 	pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
@@ -866,12 +869,7 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 		return NULL;
 	}
 
-	/*
-	 * allocation_gate only needs to become non-zero, so it doesn't make
-	 * sense to continue writing to it and pay the associated contention
-	 * cost, in case we have a large number of concurrent allocations.
-	 */
-	if (atomic_read(&kfence_allocation_gate) || atomic_inc_return(&kfence_allocation_gate) > 1)
+	if (atomic_inc_return(&kfence_allocation_gate) > 1)
 		return NULL;
 #ifdef CONFIG_KFENCE_STATIC_KEYS
 	/*
-- 
2.33.0.1079.g6e70778dc9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211019102524.2807208-1-elver%40google.com.
