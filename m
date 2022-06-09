Return-Path: <kasan-dev+bncBAABBC7TRCKQMGQEDRZWNWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id AFB2E5453F5
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 20:18:52 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id w16-20020a197b10000000b004795bcb0bbbsf4984962lfc.14
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 11:18:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654798732; cv=pass;
        d=google.com; s=arc-20160816;
        b=T0GUp2nBZfPfaf1yACk52IRsqUCCxl+sTnGoPIbJeAOyWwm4s+ts2jQBThiUO/kK97
         2SPHDZuDR8eAzQybEvt9hpCO156PJKaRlh58enFD03qQyVuN9Zccmqqo4E4UIMmZXdfC
         vgkmnA9H9UhAH7JdR5kYcIP6k3Lkknq3RMcfZ0VI+j93kqUfppo3dli7B59UEuvxcN46
         DgMmkDB/iL8lyiGdJxVtWVHTbCDGiNOZbZaeL0PUV+OkVqKLoE7Yb148St1cyb0W8s90
         8Sxzml0kEFzWO7DO//w8DBcudHs4Kc40a3qtgcTtW2zmzIWBUcqTklcslT1Admalknsj
         3ZIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=h42+QxPS9AkbiQiqLQbDDb9nA/FeF43khWw0Tsi1PMQ=;
        b=nLmlHvVFFceg+hMfDOiC+DlXkBzuiQ2R4QLM2Xc+FWL7HeaKsruu5C4VN6RSclHm8I
         YuYL+TwqKyRYl6USqBG9h9Kpd2IM6UkFG0xiFEpoi6nODgr4lSB7Zk04H41w5aruv2Ku
         RGrwynRQ+DXoUQGQaQBLxpECAyNeQ9mTOqS2J8MkUECWyycPCFWYHq7tSRYgfScb8Bi2
         uneQo5By3tMHn7Oc2vSjV9DOGOj8c0uQsgmkRbMlYuIMpdND6AyaLaEONOD9sIkIxXWw
         g3hTQvjPA/ILUGYUmFd8Y/Wwk5ZAGKtdd+XJw1NQo9/15BFDMxTDIDwNOyzG/cC95jq5
         Wo9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XNdLbz37;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h42+QxPS9AkbiQiqLQbDDb9nA/FeF43khWw0Tsi1PMQ=;
        b=X0eUEc+xlVSZ/t3T0JZy+Eay47fxYq2vbrJLsykLOHzDl3NpUyUJTV0Iaa2/bXmtBF
         P660CeQB+lQcSTiOJltaIrf1aB3NApOB2hdZgvflcdaikHj+/gGN+E+adGnwONxoO1Xh
         L5vdNB8k6nULtUiMmsyb9GvFsETan8inMMXhtktU8cUL0g93jLCpW1CmqSCp3Q2TVFJZ
         UcWITe4mcXDwnSV3xODRz2s2ynXKv76gDpee6IsY8Zdb+Z7jrVilW9rGdsd2nKPENVPP
         qCGRAy85m8rJYh44/c4RpmRKjU+Hs4yBLjA9Xn+bkUwjzdDS6z45c5Lw+tR5jAcPxZKI
         p2OA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=h42+QxPS9AkbiQiqLQbDDb9nA/FeF43khWw0Tsi1PMQ=;
        b=Ffy2lHPS61WzWRse/anZFRDMw0UVyJZL1laRYtZy7mi/xFA4pFOWafbBbdb30akxHd
         KsSLAnvC29xjGDDlEy85cggax4rhHciOfw9d2XUQBFlyMLj4ep3b8KUEYZ0PtmKusZHS
         SSdW2h+3avq6mds0gjW8vPOIC3vAXuAZ6ueYneWInzPzvYVMnEL4zGUzw2Ho1OA6gnDf
         Krvoc8xQyR+scTyRi+gGBMdkCjtOZrDHpYhXmvzXdhsDbD6FJSXpmsOASbHWndiQ+7L/
         nUOXIo6ESr/cizz6W92Cscoi14bv2evLA6NWM0BArgDG+ySYqNuzwXhym/UZLsQlsEZe
         gMjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531TrwqVcyYPTCl+xV2MM/KW6x4Aok5gq0/apbog4o3De+H18rVk
	Dbbg5q1Z8095cyk9fPwiSX4=
X-Google-Smtp-Source: ABdhPJzo8/m5pSkP+AG012xkpvRgQXaMphMf7fMVBr3CCid0ePBJHen1N3W3T2KWZ9ulfYVAG5uX4w==
X-Received: by 2002:a05:651c:50e:b0:255:c133:f495 with SMTP id o14-20020a05651c050e00b00255c133f495mr5041360ljp.233.1654798731866;
        Thu, 09 Jun 2022 11:18:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als9110lfa.2.gmail; Thu, 09 Jun 2022
 11:18:51 -0700 (PDT)
X-Received: by 2002:ac2:5f48:0:b0:478:f230:52a5 with SMTP id 8-20020ac25f48000000b00478f23052a5mr23369165lfz.218.1654798731014;
        Thu, 09 Jun 2022 11:18:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654798731; cv=none;
        d=google.com; s=arc-20160816;
        b=HZ5w+oeKKsb6Xe+w+wymqCyO01CQFKu1YHpM4Y8zK8ShGVfhOvCp6oQe+dtx8Q+Hsx
         +Y2K9N0myD+R8HUKOgHiJd+jMobfeVNxfFRwc9zg6F2ZyQiZ0Ik6sImvVGwNFqNGuR0A
         HC29qLjgVSFmVwl3aeiTc+Hrzm37sULx7evw+RQJMi5juyuyuT4cwF4u18/0u9F+h3eQ
         3TlP+BlyuYfA/L6f3GRZ9sw04CAEQ33jqE43qkT8cBvTmjpg7XaZ1JAldxIRcVxt2s97
         MjrM4tF+E2um06iwO6myBcjPRalbmjxFEJXyAF/VhuAfHuOfPea3Z/ExLih0Ie0s4cPe
         zBQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=EsGrAYAp6IJFxcDVn2/7Z4jT50O8LabBUCsC9BUqAmM=;
        b=URl5hwLYfJpJiL40BD7A61PRIi+66awWzl4vhzojYX3qIqaywedu+GAxECJGFo6KiK
         FMzcCFRLwKZnAqH/Bi6J2JYLQMdhxk3e7SiiJRoZAJjvPakMcj9m7QBbqfl7vObJsMFD
         m3ApmPMwg1Uzg3aR/HPDXrnFD9r9MtlpLzyg/S2OllUfMRxZSp+YvmeohFJfOp+ysO1k
         GCEBUPxYtts5/7aqcJp/qmkwxxOJcAjoXkkiFGS7DLRrqJUfsgDgLNzekIjoUuSqbsN2
         uot2fv/LWs/GDgmGNig2iagzJO4kZS97BFi7ebPvow/AETy3cMbEWIBfTcU6p2/HqgKk
         /i3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XNdLbz37;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id u5-20020a056512128500b0047ac395e518si267350lfs.10.2022.06.09.11.18.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 09 Jun 2022 11:18:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 1/3] mm: rename kernel_init_free_pages to kernel_init_pages
Date: Thu,  9 Jun 2022 20:18:45 +0200
Message-Id: <1ecaffc0a9c1404d4d7cf52efe0b2dc8a0c681d8.1654798516.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=XNdLbz37;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Rename kernel_init_free_pages() to kernel_init_pages(). This function is
not only used for free pages but also for pages that were just allocated.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/page_alloc.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index e008a3df0485..66ef8c310dce 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1296,7 +1296,7 @@ static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
 	       PageSkipKASanPoison(page);
 }
 
-static void kernel_init_free_pages(struct page *page, int numpages)
+static void kernel_init_pages(struct page *page, int numpages)
 {
 	int i;
 
@@ -1396,7 +1396,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 			init = false;
 	}
 	if (init)
-		kernel_init_free_pages(page, 1 << order);
+		kernel_init_pages(page, 1 << order);
 
 	/*
 	 * arch_free_page() can make the page's contents inaccessible.  s390
@@ -2441,7 +2441,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	}
 	/* If memory is still not initialized, do it now. */
 	if (init)
-		kernel_init_free_pages(page, 1 << order);
+		kernel_init_pages(page, 1 << order);
 	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
 	if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_POISON))
 		SetPageSkipKASanPoison(page);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1ecaffc0a9c1404d4d7cf52efe0b2dc8a0c681d8.1654798516.git.andreyknvl%40google.com.
