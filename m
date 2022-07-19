Return-Path: <kasan-dev+bncBAABB3PM26LAMGQE2DCOTOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id CEFAD578EC1
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:10:22 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id z11-20020a05651c11cb00b0025d8baefafdsf2259403ljo.9
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:10:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189422; cv=pass;
        d=google.com; s=arc-20160816;
        b=DEx49RYYEe/4NXTjEbFVdK5RdAW4ZQ3Y2ddz51LZRqJn/Sa0caMjJZ5Wfm8AoSktvl
         ZCK6gPkW+BWouxLD/8oXcWi4KGHfYOv+0H7u7QWgefTILiljXOgzk4K8qYI/mwf0c0nF
         uDjZxxzQURE7Esu3UvFh3vUCJcU4fnpqRirAj/hxT2OvVUWkZD39n4pYFdV9O1Z47Wz9
         nLjRJPHXlTk6IXmf0XVawIpwZ0STGvurmchmee9sb97Wn/rUPFdxFZa336hHdDoa7aW4
         5wuEjab7h0zLDlJt6RJv8EfgX4zkJthbY96WELuV+VaOvaOQ6xFKjZQFOpSrBQ1rTB69
         BC9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nrll9dqUBmr1jhC7t1RwL8Cv+KJzlVbgTMPPXzvyNMM=;
        b=bux3qu1ufvgb5zBHuftJytoDaIXZNejpgQJmGcZFIGpRhDdrvFhaoNdCLlOPgqP7Ce
         VBgGUzn4Z2SuWyFk6sTHiMPWX3tQBkPZIU9i2EB8/zqFng2JzvyoAIFmy0FMXtjHXR6B
         mx6bGOn5lrEidE9xo0CeJqbPbNrhDdnlURL2K1DFP2Vsh42/IehZr5VhMgpTgrjvPfz7
         NnwHFqHpVPtCWWPvTgXDrkVrbBB2QM6ZZw4bi74mSlz5cRTvSMwVMIrKwAoHS85rQ23j
         2O/3sUDrnc7Qa95OGRMBzMAmyJqNAgQ/QGU/IqeaTk+jDpNiXZzuBsYbwJJKcmHVmyLq
         v1dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LpPHqJwP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nrll9dqUBmr1jhC7t1RwL8Cv+KJzlVbgTMPPXzvyNMM=;
        b=sOm3pdTzNr1FXsnkuKic6KCvgq3I7+UdZ+f2U3UrYWYizY+YT1f5QfWhigpSOd5bYr
         TnXO8npw4r1TTu9hwkxtDlAzk6LUxxJWdwtCKDCNmBuueoHz0UhcfYkoomHmjWxSt0fs
         4JJtukMGkwMFTX4+KFYTAUK6FcyToNwW1nWGm7BnN/js6AFdrD54Idk0JQtVp2lLR2AX
         k1YQKvuDheAVtFoWjWEYTaN4AGts43Pmou5VEzH6EVZUUsSSwinTHeGYeM+uMQgX1P2e
         I5HbCcI9Zmq1jf1uNvqP5A4Xxx12/Um5goxwgMOwaZYVfehASoZT/CmNh+QUqOHcLUw5
         Griw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nrll9dqUBmr1jhC7t1RwL8Cv+KJzlVbgTMPPXzvyNMM=;
        b=j3wOKqiP80RzDK5K0wxgiqbxd8oHgJwQEa44p2L95Gm4ovqkTRxT7ocCZrYS5GOmPg
         IfYhiRk4tuurqq6BBUmsK/mA7sDITpPR0kC9GQcUwFvF9bYVsrjb+Mt9qGnIPK0KX3Z5
         ZC97R8suCUg16BaYrafvFUEaURGXhsst1pufIyNaTBqyEDauhgXjl2dXS/OFqHJEAIAg
         yhibwNFlPxILrt/yxc5nysR/sYxOLz+JsdSAFVaVMCsMe+aYqqT9MUIr92VVmGSEMyzw
         7Huc0wCzeWNUBBVwZ1KooFSF1n856GzFyxeHy1QGge2N1fnIwIweX2/Y2Bb0PnMNfUYw
         BaAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8b/AeiOdVPrMnPX9iQphR7lhMmsoMcC+F0piNDc3x3JcWONWwC
	+CA9LKpRjtRQgo1FnvMu2lg=
X-Google-Smtp-Source: AGRyM1vUJEKBDvb8A4FlGbh84xvz3YaXgFiWSS8WDolc55IBdQdrLvYbx+LLrOakQ8RnkZtgqHHtDA==
X-Received: by 2002:a05:651c:1026:b0:25d:8f2a:fcd3 with SMTP id w6-20020a05651c102600b0025d8f2afcd3mr13753911ljm.519.1658189422017;
        Mon, 18 Jul 2022 17:10:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:154c:b0:25d:6f75:eea with SMTP id
 y12-20020a05651c154c00b0025d6f750eeals115529ljp.8.-pod-prod-gmail; Mon, 18
 Jul 2022 17:10:21 -0700 (PDT)
X-Received: by 2002:a2e:9bc2:0:b0:25d:53a9:65e1 with SMTP id w2-20020a2e9bc2000000b0025d53a965e1mr13952514ljj.158.1658189421145;
        Mon, 18 Jul 2022 17:10:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189421; cv=none;
        d=google.com; s=arc-20160816;
        b=el4drWt3+uTopopYTi1A5xsyCO3/iG/f459VRHBIblMVnTZIL1B3KrtlUEJfZ3Htjd
         MupdvYvMv309hbgF6k2WEBctcYXFV1W6wJMIJPYiMjUaa88ilAkmws6YpHeRhTvPRMLJ
         xK2f6FmRCRgWWXl43Ap9eip5JD5Ze9e43OIzyg2pE2Coa9nvwxGtsbHVVi/I5eax9xaM
         Mu2elKinAGcY6t6ZR3KFFShm2ZTFAu37XGsOe9b3wgrEYGjYqK+O7f6uvk2uWXtRWz/C
         L2MTgCbnwBebUzxJwqA1kOuqX1iomnAkMzEfMd7cx5yohXFemTto174TqatxqSF4dqIE
         BAyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8oJ9fJQdymQKyxJOUtOhtMcD9KzdUX/sibmD9n9qf0w=;
        b=FWZKSI8/c99Ya5kkQXiQCGqdiybha84xWaMTOV9l1PsnX3AscqDMVXxS2B7m8J0987
         GnHuch3g8KcjoE8qXNJ7+oPF3oc4XquB5fn0qQvSpLe1Sh+H62kJlAyl7bB4PBtO4D/9
         H1mucU7COjjvWhJZog31+KlYqurqBC2PjAEGTFCwX1t6pquyV6nC8SjuCOLAzsK81xVQ
         DlkbuqL6RvyF7CN+XlW/Cs4H5zdeREqSoAgNFYXztqrx0wJk5Hro8jVY7NP2zrjLyJYA
         GiWqqYaNhzKWBGEdm1F3jjTCtywa5V92sCObh4pTpG+Uweb+ogVfkpefw/n9BH0BOkzZ
         wKIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LpPHqJwP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id s10-20020a056512202a00b00489d1a6dca6si401204lfs.8.2022.07.18.17.10.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:10:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 02/33] kasan: rename kasan_set_*_info to kasan_save_*_info
Date: Tue, 19 Jul 2022 02:09:42 +0200
Message-Id: <c3d067bfd8c54d26b3a961e715f71be578d76a5d.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=LpPHqJwP;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Rename set_alloc_info() and kasan_set_free_info() to save_alloc_info()
and kasan_save_free_info(). The new names make more sense.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c  | 8 ++++----
 mm/kasan/generic.c | 2 +-
 mm/kasan/kasan.h   | 2 +-
 mm/kasan/tags.c    | 2 +-
 4 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index b7351b860abf..4b2bbb6063cb 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -364,7 +364,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 		return false;
 
 	if (kasan_stack_collection_enabled())
-		kasan_set_free_info(cache, object, tag);
+		kasan_save_free_info(cache, object, tag);
 
 	return kasan_quarantine_put(cache, object);
 }
@@ -423,7 +423,7 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 	}
 }
 
-static void set_alloc_info(struct kmem_cache *cache, void *object,
+static void save_alloc_info(struct kmem_cache *cache, void *object,
 				gfp_t flags, bool is_kmalloc)
 {
 	struct kasan_alloc_meta *alloc_meta;
@@ -467,7 +467,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 
 	/* Save alloc info (if possible) for non-kmalloc() allocations. */
 	if (kasan_stack_collection_enabled())
-		set_alloc_info(cache, (void *)object, flags, false);
+		save_alloc_info(cache, (void *)object, flags, false);
 
 	return tagged_object;
 }
@@ -513,7 +513,7 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
 	 * This also rewrites the alloc info when called from kasan_krealloc().
 	 */
 	if (kasan_stack_collection_enabled())
-		set_alloc_info(cache, (void *)object, flags, true);
+		save_alloc_info(cache, (void *)object, flags, true);
 
 	/* Keep the tag that was set by kasan_slab_alloc(). */
 	return (void *)object;
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 437fcc7e77cf..03a3770cfeae 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -358,7 +358,7 @@ void kasan_record_aux_stack_noalloc(void *addr)
 	return __kasan_record_aux_stack(addr, false);
 }
 
-void kasan_set_free_info(struct kmem_cache *cache,
+void kasan_save_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
 	struct kasan_free_meta *free_meta;
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 01c03e45acd4..bf16a74dc027 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -285,7 +285,7 @@ struct slab *kasan_addr_to_slab(const void *addr);
 
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
-void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag);
+void kasan_save_free_info(struct kmem_cache *cache, void *object, u8 tag);
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 				void *object, u8 tag);
 
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 8f48b9502a17..b453a353bc86 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -17,7 +17,7 @@
 
 #include "kasan.h"
 
-void kasan_set_free_info(struct kmem_cache *cache,
+void kasan_save_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
 	struct kasan_alloc_meta *alloc_meta;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c3d067bfd8c54d26b3a961e715f71be578d76a5d.1658189199.git.andreyknvl%40google.com.
