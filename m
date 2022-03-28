Return-Path: <kasan-dev+bncBDKPDS4R5ECRBF7QQ2JAMGQEJNV3EUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C9A24E982B
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 15:28:57 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id c189-20020a1f4ec6000000b0033eaed65c5fsf2518664vkb.8
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 06:28:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648474136; cv=pass;
        d=google.com; s=arc-20160816;
        b=vmpfk7/qJZNIY2vRjg500cBmB5IuxTh3EKKhZDBg+iPmHBWYEy8FdRRqxItTOagFUu
         3sbmiFUcq5jxigq1A4OlTcF+UETFTHE+WdHA2dLWWHx3CiZnpNYKrCv41SuPZQRSGA0M
         TfxK+HYZzFFr08OLD6eU5qogIJLK+v3NqneG9xKDX3ggjY6tZUydQ5IqE9r5jEizC/G1
         BRvSwAjHhFIYxL1V+pbRuc+qIVOYI2Ytl5j1R02swi3dNo8L0wkNADqDHxIjADeuJI6l
         YwHDieBBejnp5+wwZM6z+zQuDoDlhfwcSVr2f/tChiZytwk22BZnBhUYTaapW/4hOrbN
         NaWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=PAd9PTuo/x8z5fPC/vHBFy9BV3KcXNj7zeRt1Fx1cls=;
        b=ojjKbCpL1aOgiAv5XEj6qaY/SA4apQuhwRGj/MeuJp5uZQV29SPXZtkP2eUV5XvTK6
         yduEiO6jPXY3ti+DL5dqS2RL4ETurbWaYv2lveR2IOB4MYdyaNr9SnhwKRXUEAzfmusl
         gp56NiBVlu9mWyBaQMtjGRea/9/c4LjyNTihVrve29BZXoVQobTrasD6lDMA6tzfZXQE
         TgbTmTLKRwion5x9U2XW+LWiyY7sDiIMSHa9O01yT5pjpPLbx1icROFtahZNpuReRZRD
         qSnq2lZLULErzt+PPakRg8ZREnqBGEHTzFXsxT7iuL9HM5+R0J7W6zgTFzAyyZETBQtI
         YeLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=YJ+SNrGd;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PAd9PTuo/x8z5fPC/vHBFy9BV3KcXNj7zeRt1Fx1cls=;
        b=kNXQ9P4OQYrYleapwMfqshwZAHXihoG0GGr0CcxqC39iHTyd9topcqja/3ilKN3f4Q
         VRh21VovI2mz4CrV4uiGdtfZ/O6Z0bwfdHFK59I2FA1Mu/wQ6QoMIGJ7SPMoO+3N+b2M
         mKFLbN5hUVdyO6Y8jK0PXn/dJ9h2g6hJjzuqLwf+L1WVIUPBorCYDn1Cq+9xhqo8mmP+
         Klau5shmdbYDh9XNrVlWfe7FYpwadyXNcIfGHZAnZ7ski/uZAL8HorHiCMeIkVgjvvsb
         KraA2v6voyAyZalZ8ZIVmq+BYR9pPemNCBvWUvSY+pgt3ccfN7JX48EpSnFRNNhvBkgy
         YE3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PAd9PTuo/x8z5fPC/vHBFy9BV3KcXNj7zeRt1Fx1cls=;
        b=l68TfOhfglesJhYBpK3zpBJrlIVxQUx9PsmgPtTAugDZjmMROj6zBgCAA2KCxzUX1T
         EeLpJepynBXP9Qe255INO9+DfBSRn1IMw2i49T+7O6wWpe2Uc5a9ImDE3PrgvqAmhFFC
         8mwLe4Ke2BW9VIisgQETrq6/G2JTKglCQvp6SO6R37DV1lFbIxzsnh1g1mFG3/0eyWLj
         +WgvWqitzIo9kkTrfUUhSxYJc5MoAyhGAbTvw/bPn/PsEIBtdZOieE2u8G+JDcif6Ip8
         6n6CwGnf3Gh+NMssbHSrwIpoJXfFKPGlCowxFz/wjXSyHq8YHfOfOXnpizBIHwtHVM4x
         iJXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531r4LLHmpGf4JAL2K5BMVrYRUCi0IWznt8ECShQDBzMVY9J5XJw
	+Sx1vLtoKU/TbrE1sE/uY58=
X-Google-Smtp-Source: ABdhPJz7EALyNhcbLlyY8YUxAyXeA3yzeW1JoSYrE6wHxN1W4WmZMj8OTQOnJy9koZxRscWf8jrGgw==
X-Received: by 2002:ab0:6989:0:b0:346:b33f:7b94 with SMTP id t9-20020ab06989000000b00346b33f7b94mr9555029uaq.5.1648474135858;
        Mon, 28 Mar 2022 06:28:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ce94:0:b0:325:6e4a:9372 with SMTP id c20-20020a67ce94000000b003256e4a9372ls2098888vse.10.gmail;
 Mon, 28 Mar 2022 06:28:55 -0700 (PDT)
X-Received: by 2002:a05:6102:3e95:b0:31b:524c:e311 with SMTP id m21-20020a0561023e9500b0031b524ce311mr9840988vsv.21.1648474135055;
        Mon, 28 Mar 2022 06:28:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648474135; cv=none;
        d=google.com; s=arc-20160816;
        b=tC9g8O1egEE3hnohkNGbYrxdCKdTXMHSdM4yGLBDjbd7N6u1svLgJqlck5Hnv9ByFy
         L9xWfu0eTRr737wtDK4o5PUvhSWkRFz3+m+fM+kcTlSa5O6TNs0zaXFoxJ8FK9KTODak
         SXtWBQB3zWWkz9bD67BMO4eKq7WGTLiGHFnPu5CyoiKusXOm3R8AK/rURvX8lonb8Wwk
         UBgf2a4hA6PpvyYQAII+3c+Ulzy5s9FWc/B6WXwvxU218GeE+Bnlwf5VT7Sb/+Sce37J
         e+nBeSPWxCqmJce/gUjZY7iKAX323UJUS9LmW6UW4g1V2DnuS63Zi1fUKsLyQDJW7vO7
         oqGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=OWWkThZzG6fg+LvXYQeO6VrIXNOo2Za760j3Jl9Casc=;
        b=V9eNWzXL1F7DkMl2ERW5JRnvsal2kHe6Po3yMWggE8/fix8fXuvevArsQuXjagJ2e5
         zuqTJSPigcKrBuCv1fax9U+RpiG7dw+juD37yhciLx2oBaf1U6l2EvU/97tMrxUWV6xg
         wIEmFzih/JNZ6rh6JU82OVvZfwKfNqFS0GaA3uwq9trtGqVfLeD/iDVjA6o1ut1TN29g
         QecOjr/JOSYLs/Z3tjXeiisughIxOvk2pHlgoV0O5VowXruV1R6Ly6bFQGvGCo0WBs65
         fYqKPCN6zMvoNY6CLMEdYS1rU3H+kHChjS34XQKPYq64WZE2dDfxS46d/+cMeTWOk3BF
         oT5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=YJ+SNrGd;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id d13-20020ab0378d000000b0035971916a9dsi909990uav.1.2022.03.28.06.28.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Mar 2022 06:28:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id y16so1297369pju.4
        for <kasan-dev@googlegroups.com>; Mon, 28 Mar 2022 06:28:55 -0700 (PDT)
X-Received: by 2002:a17:902:d48e:b0:154:b6a:9ff with SMTP id c14-20020a170902d48e00b001540b6a09ffmr26164352plg.2.1648474134256;
        Mon, 28 Mar 2022 06:28:54 -0700 (PDT)
Received: from localhost.localdomain ([139.177.225.239])
        by smtp.gmail.com with ESMTPSA id m7-20020a056a00080700b004fb28fafc4csm9980936pfk.97.2022.03.28.06.28.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Mar 2022 06:28:54 -0700 (PDT)
From: Muchun Song <songmuchun@bytedance.com>
To: glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	duanxiongchun@bytedance.com,
	Muchun Song <songmuchun@bytedance.com>
Subject: [PATCH v2] mm: kfence: fix objcgs vector allocation
Date: Mon, 28 Mar 2022 21:28:43 +0800
Message-Id: <20220328132843.16624-1-songmuchun@bytedance.com>
X-Mailer: git-send-email 2.32.0 (Apple Git-132)
MIME-Version: 1.0
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112
 header.b=YJ+SNrGd;       spf=pass (google.com: domain of songmuchun@bytedance.com
 designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
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

If the kfence object is allocated to be used for objects vector, then
this slot of the pool eventually being occupied permanently since
the vector is never freed.  The solutions could be 1) freeing vector
when the kfence object is freed or 2) allocating all vectors statically.
Since the memory consumption of object vectors is low, it is better to
chose 2) to fix the issue and it is also can reduce overhead of vectors
allocating in the future.

Fixes: d3fb45f370d9 ("mm, kfence: insert KFENCE hooks for SLAB")
Signed-off-by: Muchun Song <songmuchun@bytedance.com>
---
v2:
 - Fix compiler error reported by kernel test robot <lkp@intel.com>.

 mm/kfence/core.c   | 11 ++++++++++-
 mm/kfence/kfence.h |  3 +++
 2 files changed, 13 insertions(+), 1 deletion(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 13128fa13062..d4c7978cd75e 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -555,6 +555,8 @@ static bool __init kfence_init_pool(void)
 	 * enters __slab_free() slow-path.
 	 */
 	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
+		struct slab *slab = page_slab(&pages[i]);
+
 		if (!i || (i % 2))
 			continue;
 
@@ -562,7 +564,11 @@ static bool __init kfence_init_pool(void)
 		if (WARN_ON(compound_head(&pages[i]) != &pages[i]))
 			goto err;
 
-		__SetPageSlab(&pages[i]);
+		__folio_set_slab(slab_folio(slab));
+#ifdef CONFIG_MEMCG
+		slab->memcg_data = (unsigned long)&kfence_metadata[i / 2 - 1].objcg |
+				   MEMCG_DATA_OBJCGS;
+#endif
 	}
 
 	/*
@@ -938,6 +944,9 @@ void __kfence_free(void *addr)
 {
 	struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
 
+#ifdef CONFIG_MEMCG
+	KFENCE_WARN_ON(meta->objcg);
+#endif
 	/*
 	 * If the objects of the cache are SLAB_TYPESAFE_BY_RCU, defer freeing
 	 * the object, as the object page may be recycled for other-typed
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index 2a2d5de9d379..9a6c4b1b12a8 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -89,6 +89,9 @@ struct kfence_metadata {
 	struct kfence_track free_track;
 	/* For updating alloc_covered on frees. */
 	u32 alloc_stack_hash;
+#ifdef CONFIG_MEMCG
+	struct obj_cgroup *objcg;
+#endif
 };
 
 extern struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];
-- 
2.11.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220328132843.16624-1-songmuchun%40bytedance.com.
