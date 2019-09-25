Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBOHUVXWAKGQEAN7OIKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id AD1C3BE003
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 16:31:20 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id j125sf2279343wmj.6
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569421880; cv=pass;
        d=google.com; s=arc-20160816;
        b=wAngCIQZzOfQ6yAHj/Alh2qgzVldX1yYIcGd13OjcC8C6zPOhj0KaPzcwT1omiXB9R
         vqN/2z5VcPVAGvIjYJ2pjpFKkN01V2Dnr4GbFCdZrjdUnisOmCoMcUMiDaKnh8hlRi39
         RAo38sy68eBeGBP+mNGAsKMj5Xa9aGHQ4++7s8B5ofWZkC8b0fxz1uECat2/Wop3MVR5
         ihMV0DRvhIxFXMyP0zUyAmxe/uG6J5j27kdhaXVAsrXyJEPrnPffTRDNdwt8BoaqgVm7
         UmGiR2J3FyiZf/rcd9qi5p1msuKh/d7se2lkd3lGNlH+wk272uJYYMJ5cgobNVXEDeTi
         2GxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=O4vfIUiTQYDG1+OasmWcykQ5CGsUHJI8AHifBtbuHBw=;
        b=nEJSLOqejgNAEMsdKrdnYM/vQFuJDG9YiJHZs5ILIbjD70OgaBNGjyopYLnq5AW2lE
         BWy8Ed66LHkARNBNihI39tsl/lRYKuBN2eVBuwyyrWCngKcR0aNEb/melv0lOVP09qCV
         QdRTlKFHRcddl+UsQK2PWYogYpyQTSDZ/nhTH+T2GHzJ0uEjMjKexgZa9x3hOtyU2cY/
         uIJ0G+touIxgs/MplR6M1vJs5tFAN05TUiBss3aYuStMj8sPZgEZi1LBCUkjtMZB1M7e
         Ls3ZasegVyHG59xgAkUFEHKLoH5/kH12MFFf4/FcphwB/QTEAwglkiVPhR8XTg44ati9
         9Itg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O4vfIUiTQYDG1+OasmWcykQ5CGsUHJI8AHifBtbuHBw=;
        b=QmEo6DX8u2D9CW3jFkhVa2NA+/VCeBpm5EXK3Xz8gEIlrgPJ+hXoqJ3eFvnybS4xDm
         XLREjUcmf6oPNSD+dVgUVPTHyCjSsxE6Lt+uU3o5FxbOfVT4hWJIhhdG4ta9G3Wy46b0
         AVG/lNSmIWTnNE/wUXrr9oFiDquz9cWQbnZe42RPxg4QS7rkZhOUVhF4iVSL0webHrCr
         8WMkgcKoFWVSxL0HDqinWZilQsgB2u1iwBTz11xwh78HYC5Kdhj9QFZSDT+RqEPNGjKq
         pZXXCjpU+Vjfzx2Vx0KVv81frcBDZQ8vwRAKNYGFZAVEyiNAXU+Tlg/YRsznIIfb94XB
         /NSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O4vfIUiTQYDG1+OasmWcykQ5CGsUHJI8AHifBtbuHBw=;
        b=iL79ouhgXurVn2XPXO9yI2Md6Nh+Txyqn1cWCa6J9UguoIuxt8usWa7Bz8T/NYLcyB
         oNnBRpySJPSBfYnu84PmJHoaBsjxarP24L36SBeM8DXHCuSrANu4DbPgyWrOwVf+l5jE
         ZLT/zb/eLKp7qe1Azvz0JySwbQAa0/PVNJZGUS22/G+cwZTAv/cWWRHfLRmIimfk/kln
         Tbx6WAFGq7HVQN5D2NfEhyo9Lu0AYvuWdbt3bL1W5+fPtJuCxv7MtBAvaHJCVr45xupr
         2nVC3zrh5jhI8iIeH6sWLcbLsUtOU2WEvcOBNI4qw86LzgsJtro8Oex7zcBKWS9A7wdx
         6x6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUgSjdMxmCDoCR/U6ab2/XIeR1kNT6aj0IOprnxLly321ExvbUD
	qiWHHfrw4GHzpYmV/S8c1HI=
X-Google-Smtp-Source: APXvYqzfpyymJ+XzUKv7eCnm0KThH2ho+Ai3NWjsnv3y8Oz8W/7N82jt4a5Rr0PM3WpiG73YbLm75A==
X-Received: by 2002:a5d:5642:: with SMTP id j2mr9958891wrw.345.1569421880341;
        Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c8d9:: with SMTP id f25ls1845238wml.5.gmail; Wed, 25 Sep
 2019 07:31:19 -0700 (PDT)
X-Received: by 2002:a1c:f01a:: with SMTP id a26mr8001037wmb.84.1569421879747;
        Wed, 25 Sep 2019 07:31:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569421879; cv=none;
        d=google.com; s=arc-20160816;
        b=A7EW4QNiYYfaruCiu2oas5zrQDliFML2DIZGTO59jQJRXN+gptcQ5aAHowtjrJIKx+
         gDjvQcg0AEm7ljs5GmaD7k/ZVhR3NMEP8tqeg6Tt2o7f58wmQlpAtlQWnqLq8dSWuRFz
         aLiE1Cl0a8mmq0tZno9EWp9Nh6jgCgNxTOQB0XohI230xtVaU7ML40xKL0n7e5q3D0Js
         UPP8CjGRIsfkWvG/YGCcZ4Qhs5ktdsH/lXVgHUpv0YNMcwvjDx+JKaCWbI5mya4o0GbF
         5nFeYPJJ0Vc5T+kuqXsGQwsW5w72Gc46MgXauGXWX/X8uGtxJplhh8U+t3jiVb1NTdNB
         iKqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=6twQ3YD+O6lKWXv7FZ10wY/RISPC4Rrqd2xo9NNSTbE=;
        b=TPEQnWfJmNrbY+WicA96d0e543Do0KWITpRpwTDC9CP1VdaBbVmsOFsb0sfDA3ypqF
         7DRLBTAscTHiex8S4/NUk+mnsdXRCMX3TwQl1umyxIkgzD+Q3OAU7iIDXWCTQlUFcDEB
         3D/61PWuZDOmcNzR9Q1Bei9T0p9zxjLP68MwJOq9rfmSCnNysCJ46RQIv4F8X6DJpXOP
         ZIawf+gmPpiRNoEAaBKviZxZLzGIWKHpOaGC+zzorPMFhhA9r1DnLzhM0b3DDNBT+Mip
         PwfyrPy3HY1UuSm18T5mDHvvaftGD8C9nMvM+l29AWlpNHP/tkYmri40XrVZ0wE5vpG6
         CG+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id j4si337966wro.5.2019.09.25.07.31.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Sep 2019 07:31:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id EC307AF5A;
	Wed, 25 Sep 2019 14:31:18 +0000 (UTC)
From: Vlastimil Babka <vbabka@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Qian Cai <cai@lca.pw>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Matthew Wilcox <willy@infradead.org>,
	Mel Gorman <mgorman@techsingularity.net>,
	Michal Hocko <mhocko@kernel.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	"Kirill A . Shutemov" <kirill@shutemov.name>
Subject: [PATCH 1/3] mm, page_owner: fix off-by-one error in __set_page_owner_handle()
Date: Wed, 25 Sep 2019 16:30:50 +0200
Message-Id: <20190925143056.25853-2-vbabka@suse.cz>
X-Mailer: git-send-email 2.23.0
In-Reply-To: <20190925143056.25853-1-vbabka@suse.cz>
References: <20190925143056.25853-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

As noted by Kirill, commit 7e2f2a0cd17c ("mm, page_owner: record page owner for
each subpage") has introduced an off-by-one error in __set_page_owner_handle()
when looking up page_ext for subpages. As a result, the head page page_owner
info is set twice, while for the last tail page, it's not set at all.

Fix this and also make the code more efficient by advancing the page_ext
pointer we already have, instead of calling lookup_page_ext() for each subpage.
Since the full size of struct page_ext is not known at compile time, we can't
use a simple page_ext++ statement, so introduce a page_ext_next() inline
function for that.

Reported-by: Kirill A. Shutemov <kirill@shutemov.name>
Fixes: 7e2f2a0cd17c ("mm, page_owner: record page owner for each subpage")
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/page_ext.h |  8 ++++++++
 mm/page_ext.c            | 23 +++++++++--------------
 mm/page_owner.c          | 15 +++++++--------
 3 files changed, 24 insertions(+), 22 deletions(-)

diff --git a/include/linux/page_ext.h b/include/linux/page_ext.h
index 682fd465df06..5e856512bafb 100644
--- a/include/linux/page_ext.h
+++ b/include/linux/page_ext.h
@@ -36,6 +36,7 @@ struct page_ext {
 	unsigned long flags;
 };
 
+extern unsigned long page_ext_size;
 extern void pgdat_page_ext_init(struct pglist_data *pgdat);
 
 #ifdef CONFIG_SPARSEMEM
@@ -52,6 +53,13 @@ static inline void page_ext_init(void)
 
 struct page_ext *lookup_page_ext(const struct page *page);
 
+static inline struct page_ext *page_ext_next(struct page_ext *curr)
+{
+	void *next = curr;
+	next += page_ext_size;
+	return next;
+}
+
 #else /* !CONFIG_PAGE_EXTENSION */
 struct page_ext;
 
diff --git a/mm/page_ext.c b/mm/page_ext.c
index 5f5769c7db3b..4ade843ff588 100644
--- a/mm/page_ext.c
+++ b/mm/page_ext.c
@@ -67,8 +67,9 @@ static struct page_ext_operations *page_ext_ops[] = {
 #endif
 };
 
+unsigned long page_ext_size = sizeof(struct page_ext);
+
 static unsigned long total_usage;
-static unsigned long extra_mem;
 
 static bool __init invoke_need_callbacks(void)
 {
@@ -78,9 +79,8 @@ static bool __init invoke_need_callbacks(void)
 
 	for (i = 0; i < entries; i++) {
 		if (page_ext_ops[i]->need && page_ext_ops[i]->need()) {
-			page_ext_ops[i]->offset = sizeof(struct page_ext) +
-						extra_mem;
-			extra_mem += page_ext_ops[i]->size;
+			page_ext_ops[i]->offset = page_ext_size;
+			page_ext_size += page_ext_ops[i]->size;
 			need = true;
 		}
 	}
@@ -99,14 +99,9 @@ static void __init invoke_init_callbacks(void)
 	}
 }
 
-static unsigned long get_entry_size(void)
-{
-	return sizeof(struct page_ext) + extra_mem;
-}
-
 static inline struct page_ext *get_entry(void *base, unsigned long index)
 {
-	return base + get_entry_size() * index;
+	return base + page_ext_size * index;
 }
 
 #if !defined(CONFIG_SPARSEMEM)
@@ -156,7 +151,7 @@ static int __init alloc_node_page_ext(int nid)
 		!IS_ALIGNED(node_end_pfn(nid), MAX_ORDER_NR_PAGES))
 		nr_pages += MAX_ORDER_NR_PAGES;
 
-	table_size = get_entry_size() * nr_pages;
+	table_size = page_ext_size * nr_pages;
 
 	base = memblock_alloc_try_nid(
 			table_size, PAGE_SIZE, __pa(MAX_DMA_ADDRESS),
@@ -234,7 +229,7 @@ static int __meminit init_section_page_ext(unsigned long pfn, int nid)
 	if (section->page_ext)
 		return 0;
 
-	table_size = get_entry_size() * PAGES_PER_SECTION;
+	table_size = page_ext_size * PAGES_PER_SECTION;
 	base = alloc_page_ext(table_size, nid);
 
 	/*
@@ -254,7 +249,7 @@ static int __meminit init_section_page_ext(unsigned long pfn, int nid)
 	 * we need to apply a mask.
 	 */
 	pfn &= PAGE_SECTION_MASK;
-	section->page_ext = (void *)base - get_entry_size() * pfn;
+	section->page_ext = (void *)base - page_ext_size * pfn;
 	total_usage += table_size;
 	return 0;
 }
@@ -267,7 +262,7 @@ static void free_page_ext(void *addr)
 		struct page *page = virt_to_page(addr);
 		size_t table_size;
 
-		table_size = get_entry_size() * PAGES_PER_SECTION;
+		table_size = page_ext_size * PAGES_PER_SECTION;
 
 		BUG_ON(PageReserved(page));
 		kmemleak_free(addr);
diff --git a/mm/page_owner.c b/mm/page_owner.c
index dee931184788..d3cf5d336ccf 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -156,10 +156,10 @@ void __reset_page_owner(struct page *page, unsigned int order)
 		handle = save_stack(GFP_NOWAIT | __GFP_NOWARN);
 #endif
 
+	page_ext = lookup_page_ext(page);
+	if (unlikely(!page_ext))
+		return;
 	for (i = 0; i < (1 << order); i++) {
-		page_ext = lookup_page_ext(page + i);
-		if (unlikely(!page_ext))
-			continue;
 		__clear_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags);
 #ifdef CONFIG_DEBUG_PAGEALLOC
 		if (debug_pagealloc_enabled()) {
@@ -167,6 +167,7 @@ void __reset_page_owner(struct page *page, unsigned int order)
 			page_owner->free_handle = handle;
 		}
 #endif
+		page_ext = page_ext_next(page_ext);
 	}
 }
 
@@ -186,7 +187,7 @@ static inline void __set_page_owner_handle(struct page *page,
 		__set_bit(PAGE_EXT_OWNER, &page_ext->flags);
 		__set_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags);
 
-		page_ext = lookup_page_ext(page + i);
+		page_ext = page_ext_next(page_ext);
 	}
 }
 
@@ -224,12 +225,10 @@ void __split_page_owner(struct page *page, unsigned int order)
 	if (unlikely(!page_ext))
 		return;
 
-	page_owner = get_page_owner(page_ext);
-	page_owner->order = 0;
-	for (i = 1; i < (1 << order); i++) {
-		page_ext = lookup_page_ext(page + i);
+	for (i = 0; i < (1 << order); i++) {
 		page_owner = get_page_owner(page_ext);
 		page_owner->order = 0;
+		page_ext = page_ext_next(page_ext);
 	}
 }
 
-- 
2.23.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190925143056.25853-2-vbabka%40suse.cz.
