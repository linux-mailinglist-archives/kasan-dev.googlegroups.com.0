Return-Path: <kasan-dev+bncBAABB747ZSEAMGQEXTUMPXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BF7D3E86AF
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 01:47:12 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id w1-20020adf8bc10000b0290154bed98988sf110908wra.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 16:47:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628639231; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jyd86T976BfwISm2HMr15grQBL0iYikF0qq2cDXKRi0Lzm/KSt5DwgzZzaJXEmttU5
         FRHSbtAQS8cCuizSox89OMwwMAUkXA3ib+jvqlIh2/kemc3JkUA/nkWwehs8BExXUBAu
         w46ns8pmeuq7oWxEP+eJZXYLmaqk3LPUl54Cb2crgQcgJBidMUiTgAAmUwIyKjkZWBD0
         htRA+LJBK7YGyi0fAhkn+A/pDmcKrVk4CGbYSMs1w9ZlkO0FT+tBYNVld1DHlMHReuzY
         rDuAssLO/1NOZufxbOnYoruaK10/n7D4nkvL9AF+onA273CciFCilLlh6eDBQGcjhGDH
         5b8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=6ftGw4Wd1SV/i3R29erowrx2iQbXxFAfE2nuWNL45wc=;
        b=SmspAjzwPdtb7A3F4BUaFvsT40pUcdWOSeL49UMmZ/4Xvm04762z4SzA9hdFfhmEUA
         Hcw7ObT1uhhPoB9V6UljOKyREs1eYcioLY5BH4aNrpti1nAnbSeS5BtF7rLZiL8Fb1E7
         u9kgDXtJdNtN5Qnh8AAEhxxkoUbKBBLJ8ksKHZ1zwSgfJ7guSjr6s9zfOn9Gz2exOfMH
         8AaByTdKbHogY6sBfBOK6V+DfN7sbjj/uTITBF7iAIdy8cJ+N9f8S8UTupJZfFEFGUbr
         eUIV57d6yIcjag/U0tbzduTiz6tvpeKOT/qzUpTBT21JtsQOU+NAk+JwLp1YFi7XPGcX
         Ilow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XF1pS+k7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6ftGw4Wd1SV/i3R29erowrx2iQbXxFAfE2nuWNL45wc=;
        b=tWMhyXr70NLy184dV15a5hDr9e/DWGa+LRY04SWD8UGkVi3LmwtV1aSt9giKzkVXch
         FyuzmOnLReBg4ds/ZbEIGzHLzL2kCoI8qo5Tp6q5RuuZfg9pqTiHG8oPHk0Loz6XXJ4F
         6+HG9d4tkPkoJwKBz4oELNq//RB9Cj0CWo+vm4cX6Y0qJ5g8DT+dx38OsbOHS25BgSKZ
         f7iH1vD1tYRK7hnImaWoaJ7WuFTtgCq557uvXsqFgeIlCY7LJdIOvLNFEUQP97HpJbG/
         tuixzDhco83sxSCF+BTkcfILHs9siqfRmIue1UsA1PGVERfRvVyWuNppuCRgHgKKVOGj
         RLkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6ftGw4Wd1SV/i3R29erowrx2iQbXxFAfE2nuWNL45wc=;
        b=cnPDXZwXhenjTQWEqc3GYFogv6fo5Vzh/ctMgJfRVjDTSg7XYsVLXAt20AcWIuoWSp
         mU/Otu7GUYdrzVJpu3YNMHPb8GOh/9xj0YAFcpuUhYlEOfGkYxwUu8mUCTtakD84ihXA
         hNsqCig8fwdnDwF/kDpyb2i1wfX8Pak1Pm7YBBDl+3LgtC9tasigVv+9l4AwT8mfEPMo
         cDzaSqzLYrvcU1q9AXDXa7bCmaa6Ux3PJxB7MMqxuwgHMYHJMcRtXMS2eIQPp7rbOR1Z
         7jtR9hJEjzlOOtNe1kfPYBlElS0z6bmhML4uQemcwxDd9W7Anx6kAvVNJxRm9q7rbz28
         v+ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533/bUrPQ0LezpxrK1ip06x67KfC1bGKpJAhCXmSAsAHQI5H0vUB
	kjWb5EjopjwYr+9hnTvXJ2s=
X-Google-Smtp-Source: ABdhPJyy2yCCvP9CfU2ZqW7vsPDDii/7EVHyIaNM3UTsWzluCafITlNt2gjuGVZVLjcX6s+jVUMDrA==
X-Received: by 2002:a5d:4bc7:: with SMTP id l7mr16583570wrt.146.1628639231620;
        Tue, 10 Aug 2021 16:47:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cb09:: with SMTP id u9ls159917wmj.1.gmail; Tue, 10 Aug
 2021 16:47:10 -0700 (PDT)
X-Received: by 2002:a05:600c:4f4d:: with SMTP id m13mr24967014wmq.32.1628639230855;
        Tue, 10 Aug 2021 16:47:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628639230; cv=none;
        d=google.com; s=arc-20160816;
        b=W13p/wvGajOjkePHVyxALaVFCKQBppG/TMQejfFuhJ3D6jq707orKFPFNqmB+OFjNI
         c33kRFMC2fKQn+6oFHjj4bkPD0GbSxkfPf0P2dr30ikvtBN90Waxm/O7E9JBBV7vKUML
         Nyo7Q8fcmHN0bd756BKmhpaY80XUGmwz6LOhYsitiCY5y/KxKXgkVAWXtkR9sXeVTIJr
         0hMs+wHn9xM5oe9SNP44D8K0Wxul9Je9N8PBg3doCreR0hGG0m7VSdSkXpJ4iG8gY4nH
         D0YZIUhG1aMBBgzMmWAI1N3yTe2AnTcWWcnMOKEFEa5vKHu5YE1XVmUWXlgDiDBdzqcI
         r5dQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ggLsS7yz1kOGaLQ3EmXt3GWbT2jgyKyTzpDsbhnW9U4=;
        b=jdutiz1gbwQ1kuHZKWZwAF7W2y2QuCkCnYCoIABL2FOLBsJKp/FGMlhQ2mCrTvzx1q
         SvofaDMGNhSWOwoBRVUaVxHUbbnPfLfJdnUKJPyd+nJIeNhI5rLQ+LNqf92/dcTxvETs
         6V6ySdP+k7W7J587eYAeSjmcdbJbzNRdoXdeYZK+HbON910h+K9nOJlypRUcwnutpb9f
         XZJobN6nUgEk17mOlUjjLZo+qP7xGLFPCOP3EI7qk2rrKo4zgllahYscfAmpxsHUH8px
         MmLWgCaNMt/OdJ+pHDv9wPKmVRrsJIZM3TAw7UAbcyUrqSPyoTOLrKkXRZUncKMKVyhh
         4PSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XF1pS+k7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id h7si239519wro.2.2021.08.10.16.47.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 10 Aug 2021 16:47:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Shakeel Butt <shakeelb@google.com>
Subject: [PATCH] mm/slub, kasan: fix checking page_alloc allocations on free
Date: Wed, 11 Aug 2021 01:46:51 +0200
Message-Id: <ef00ee9e0cf2b8fbcdf639d5038c373b69c0e1e1.1628639145.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=XF1pS+k7;       spf=pass
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

From: Andrey Konovalov <andreyknvl@gmail.com>

A fix for stat counters f227f0faf63b ("slub: fix unreclaimable slab stat
for bulk free") used page_address(page) as kfree_hook() argument instead
of object. While the change is technically correct, it breaks KASAN's
ability to detect improper (unaligned) pointers passed to kfree() and
causes the kmalloc_pagealloc_invalid_free test to fail.

This patch changes free_nonslab_page() to pass object to kfree_hook()
instead of page_address(page) as it was before the fix.

Fixed: f227f0faf63b ("slub: fix unreclaimable slab stat for bulk free")
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 mm/slub.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index af984e4990e8..56079dd33c74 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3236,12 +3236,12 @@ struct detached_freelist {
 	struct kmem_cache *s;
 };
 
-static inline void free_nonslab_page(struct page *page)
+static inline void free_nonslab_page(void *object, struct page *page)
 {
 	unsigned int order = compound_order(page);
 
 	VM_BUG_ON_PAGE(!PageCompound(page), page);
-	kfree_hook(page_address(page));
+	kfree_hook(object);
 	mod_lruvec_page_state(page, NR_SLAB_UNRECLAIMABLE_B, -(PAGE_SIZE << order));
 	__free_pages(page, order);
 }
@@ -3282,7 +3282,7 @@ int build_detached_freelist(struct kmem_cache *s, size_t size,
 	if (!s) {
 		/* Handle kalloc'ed objects */
 		if (unlikely(!PageSlab(page))) {
-			free_nonslab_page(page);
+			free_nonslab_page(object, page);
 			p[size] = NULL; /* mark object processed */
 			return size;
 		}
@@ -4258,7 +4258,7 @@ void kfree(const void *x)
 
 	page = virt_to_head_page(x);
 	if (unlikely(!PageSlab(page))) {
-		free_nonslab_page(page);
+		free_nonslab_page(object, page);
 		return;
 	}
 	slab_free(page->slab_cache, page, object, NULL, 1, _RET_IP_);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ef00ee9e0cf2b8fbcdf639d5038c373b69c0e1e1.1628639145.git.andreyknvl%40gmail.com.
