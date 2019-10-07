Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB3EF5TWAKGQECAYUQDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id E4D08CDE17
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 11:18:36 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id w26sf3279248ljh.9
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 02:18:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570439916; cv=pass;
        d=google.com; s=arc-20160816;
        b=tVDR8LxpliVz6tvMYnWdcdnl9FTldRA1BxInQaG+44GuU4ddp3oLoWJfkIjEO8L3rK
         nMYRtooFYFJDK/yiA1iTlGZMehCMKbqYEhZZCklP+TyaqfzaQtps2IHKduPGc9i/czI8
         ZZuOYirVzKCLzRag9ATC1RsIcp8TQBx4SnCNYLC/Two6PHKsTZdaHv+FLPBTtBwVGO0r
         +VKzG/t8a4XvqEOj2cELFYcq3yX71+00ql5mWpk3jEJaSYTfERguX0h0MNlRe0ZB+iP5
         +droQ9E739JiaxIqyWiMqVjhPRljnlm0MGbwBD2z4p90V2Qq/d8vMyEPKzdXODhGk6os
         xxAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Zgw6oXeH6bVgBAU0i1WCkGYRz0JnoALXhe0pIFFieXQ=;
        b=FIorWgcLwe1Nj4sMIsJkHGStIcWQ8bBa2MB0ElIcH2a3sgbIImICGdiQFJ3N8vh3xr
         m1UT0OVzJ8JEXXpeHQtjZ7+yMMavE5v6skx6cWX2p2PVSPiuLHFA9GAlNbTL+7upgmlg
         fSWhi4T+RWrPa/Z3uC/7k23z6J6gHayqZP8MgvOQXQqwq0cyal1xb1AIZTKNjA2PILjy
         8MyN6l/qkRwKS54YNL7QCwBYFAOxTr1DYZ/BcGwFonXWJVTFFsDVapUnL00Dpmma5io6
         QOXZABdkqiEtc+9u+9gNpGCpGowkCwvJWD1T9zgfkHiN5xY2eBcsIpQLMbSf4wWhxV8y
         FmMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zgw6oXeH6bVgBAU0i1WCkGYRz0JnoALXhe0pIFFieXQ=;
        b=e+qJfmtvctrFEX37KyEp4K4gyW5g7v3GymYDIAPGizkptaNcZcfZ4IB/RBscfMexUz
         otsiHItS813tD6mJuVeWK97quSsbjHg+W9pjHAHtOzYFU1QeVPKuqZ9RJgiehOCASpZv
         b/ZvMTjWr/9JIltI5bRmdULPm82QDY43fTqnRoeljF8iZB+4lCH5/4YwpWz9kMTqH41f
         xdzaCTWh0Pu6XjLV+wMg18viuE13XVCjm2mZUhAdPv/A5w0EOqINKkGcmUwIIhEy5/sY
         3ctKHCbtzoXX/GWKwtqxkY6e88brTPY6mAKBXrVnOfPqHovM6HfV8s5k1W0tzIu89JmN
         GQ6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zgw6oXeH6bVgBAU0i1WCkGYRz0JnoALXhe0pIFFieXQ=;
        b=EU5fgHYB3buxgszj5Iz7nfTieVUUMeKpg3k5Eo4aD2h91QnAeee91qj341YFTG+7TB
         vOa90JaZVuyq2SZXMnDLzKfiD5TY1fIgCAMdtVJTE+4xamlk23/n78N0xW1EVSwfGQ3I
         J4mbxoPADDBRyYTlTEQiCCQ/kTmssD+O4s0Et+ZpHYkKAjuB3JFlGBTr9wiUwoIXpDBO
         Gewb7tqhTnR9KVKKXGD8UcNWcNvvz73BvBB3dz4QtW76XQY6sSBSH/CAmNgSfc4ziQel
         qe+IMMS1DTuLFPjLdxwOneH/XDBLsW1BQlyaSgHa3zBhw5ciYP4vnmNJf2R/VQQyS9fd
         TZAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVy6X6LZHmeaKZ22l88uBJ9VUW95fy6WFTSJP3F/gCLbwoeb1LX
	2c+zVhePHoOi6SnyM82qNUg=
X-Google-Smtp-Source: APXvYqyp0Lmr/iwsn8egvrYfg8ijxKE4TTibXO8nO/+etv6LN/vzwEDsAzKVxtpTH/FXzU7Kt65kgQ==
X-Received: by 2002:a2e:530d:: with SMTP id h13mr17725913ljb.109.1570439916456;
        Mon, 07 Oct 2019 02:18:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1043:: with SMTP id x3ls2044566ljm.14.gmail; Mon,
 07 Oct 2019 02:18:35 -0700 (PDT)
X-Received: by 2002:a2e:5d98:: with SMTP id v24mr17347808lje.56.1570439915407;
        Mon, 07 Oct 2019 02:18:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570439915; cv=none;
        d=google.com; s=arc-20160816;
        b=xWntAsx7ojlU0nO14t1hhoQUY1eMzys/CnOW1pDHsIUw+J37V5omUoSIJo4r046llz
         XIPPpBKFbwJ8FVMUw2Fx7rpoNQ3l3z7xSoYlLHDUv47Busdcz9pp2VjCSkwgY2E/kNJk
         crM4RgaQLTJe1PgXMMvJbu2o01sKhWGZroOu2dDkDZeURuebT7pMyu/DUaCl392jlw18
         Lp4oA/aHsA8vpRc7zirEw1rCAnzNKzejQ/Zl6qF4Eyzl430P+eIdeQxd5So3aP9r9Kp5
         ZpKOId5WC39u+GMecLT6rssG32/2V4GFzpWQz92oxWVo2bJdfKlSTZ/qEB6dkjrI2zvz
         LbDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=HbD7zZSSV4IxOzMYf4szfFOvkybJ2sRLxxhlV54DdPk=;
        b=wrLrvoWr0C6jvxuT6hOiVD/euGMTilE62x+IP7+wGewnnub3i01fjdlVZ0d4tI3Jjx
         M6XCh1RkffMhyGA05FwIDgh2NgXOmCWyPAGmLU85gVeWI+U8x5EbS9oi67vvPGrPgwqz
         Qsnl0qbDr1cNP856YzzWgPfScJb1Eq0gHggKJuL+UN99N502aRTfqc3v9PgVPpXLze1E
         ZuAQxEYCNfIIQ/1D50gJitQDWnOMW67nlMN4SGFUYY99bdEgYjvOxmkb4nS8uXUQSAXo
         fs2QZjmoA9nWNpOYO9PCQjdH/vyb/FH/+O8rXfKz2oyChInmu1WCTsbLV1wEh73fvoya
         WYqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id k2si582289ljj.1.2019.10.07.02.18.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Oct 2019 02:18:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 20F76ACAA;
	Mon,  7 Oct 2019 09:18:34 +0000 (UTC)
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
Subject: [PATCH v3 1/3] mm, page_owner: fix off-by-one error in __set_page_owner_handle()
Date: Mon,  7 Oct 2019 11:18:06 +0200
Message-Id: <20191007091808.7096-2-vbabka@suse.cz>
X-Mailer: git-send-email 2.23.0
In-Reply-To: <20191007091808.7096-1-vbabka@suse.cz>
References: <20191007091808.7096-1-vbabka@suse.cz>
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
Acked-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191007091808.7096-2-vbabka%40suse.cz.
