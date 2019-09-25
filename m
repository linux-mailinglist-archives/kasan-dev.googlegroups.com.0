Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBOHUVXWAKGQEAN7OIKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 212C5BE007
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 16:31:21 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id z205sf2275834wmb.7
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 07:31:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569421880; cv=pass;
        d=google.com; s=arc-20160816;
        b=U1hWChpqv5FLvWVCLcCqlm62HFpG/laHYOUEMh0gC0BHqK9KqcNpz226y8NCEo2cxe
         0kKroKjBuQX+0cvH0l3rRfqs0HeZ0nFqv9tGDLG797BLL2MttcnZqN0r7StLTbLAbd2z
         hZ9Czjb9Qf9SmWY72tcxNglmBtaW4ecV7QXcNt4TNa7tE7MHASreYWKmVWofr7uY5XLv
         +1C8AMeGt6ueeiN588u+slZDqWPt1p+3wMG5LbOG9eRL31vUfHGf1+mKnomnBs+X8/n5
         3GcwKihIOx+4cn2MFZf6mQ6kr9g8/1IJ598EJ/MdKQK6dzVB94kWc0Wq+TtkNjm5nmbl
         AHjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=R7kCGztf/L9PAIxmwQuz9IsJJwuMA7A+uxcpdffeDu0=;
        b=k47bN4KHvpAGYZrv1oJ6bRoLfq5xQV6++U0bJ2MYV1oq7c+EiHXVq5HshjK8Q/LpXv
         K2mg4+NW91MWZB03fzGXgJMUAhI7dybv1EWY+pNkh0bOGtQfj94AgXPrsXvU77h1O0FG
         3EDsjGiy3ifuZA6dGmzFZi3EW0yfAl/4ck33/gYBCG1bOhk95AlGhDlCe+p7aPbz5Vmu
         0HC7WJQrU+xLDrEArZyRwb7HJARZtqRKRlyjLI88Qn+F8MMNIZcqoE0bfwszUgEzFmm1
         tk8wGdaHU14M8u1xtSPk8fEOu00/roaksEnrCD79pMmevWLOcsU9bof6/21UozaGuZrM
         0wzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R7kCGztf/L9PAIxmwQuz9IsJJwuMA7A+uxcpdffeDu0=;
        b=o+dpKrvoKQ68XcLjev9sHcHlrpZxREqbU8PSizIfC8RuYFWYSuRr5j2shUQcFDAocd
         PymWwC8x1l4Gu8npNTfVi8/AD2PP1OrJFkdmvR7gn6Q6xXhFck+GoSRvckOGesuMO6w7
         7/1LUwUK+oUc++5Lnm7wbRkD00OTn5EoHEh4pWAR+zI42TC0woDS7PdnAJVkkLTLxCkh
         GemZOhYaGBcTpt0vXefLnsfGtehZh/RJHHOB+5PoAefjSlSfZ7amSXebpicWgzUyMN49
         IA7Ba3uuYY07VClpPkCRrGXEzftt30nzvSKM8dvuOx4zoJOVU1I+TlrvuSfOQu+eLxaU
         kEKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R7kCGztf/L9PAIxmwQuz9IsJJwuMA7A+uxcpdffeDu0=;
        b=ERC7UhFcmauIAf67l48w+8bYBkEdPmPCJFb7nXuI7sKa4mFMwasqQps0hzKc1MKjs+
         OQXPYY3vtK0wooEIMgG4u84T7D+uYcpb5m2I/QRjrHCjYyr9xh/Zf+1IyKa5NTcLqc6U
         0S4TS7yUoS9zNRhpOkt0DqvA0e1b46gSJYh9XLJfyCU1ZoYG6VtHmDXL2zBjNG7uXDPw
         cHIHKnomF0iTqpCDNy4URITW3Jn6uF1RxMmmWaT1IDaou6iYPJy2SYvKi0TRYUuzgp1q
         fpjYa6v/1Ya4liR8ED3z3VD18C0CjIOazwWBLbqEuQpV6orMCKIMuyi/grhkhNgYR0DV
         sztA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW34x8TEwuV5qTr6fjLTQ4cJTROFBchIb3I1GqbJQkqHLb4y43r
	T+dWwuy4LbgpHyqremdB0Eo=
X-Google-Smtp-Source: APXvYqwQz0tpH06HKS0jrM52h9++2daugOAZpHIw+q4ehXcSOAV4ac9eSdJKgIGb0jqZCJ2ZOjF1Yg==
X-Received: by 2002:adf:e84c:: with SMTP id d12mr9401319wrn.373.1569421880811;
        Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4c42:: with SMTP id n2ls2306307wrt.8.gmail; Wed, 25 Sep
 2019 07:31:20 -0700 (PDT)
X-Received: by 2002:adf:e7c4:: with SMTP id e4mr10433877wrn.62.1569421880238;
        Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569421880; cv=none;
        d=google.com; s=arc-20160816;
        b=a5uMOREDIXNG4KtQfrBu6nBEHB5Cf2AJcJBmEKbRnuh8c9tg6qc9BzWCb+1amwhyd4
         Xv9XSBy512Aljbnxbqr3ADJG3rlY0Qo2CdU+mi5/tmYH0Zb9o9Wga4+lyiisPZ5+ENlG
         Q9Zgwgf2phdkkNYXP4ul0L49W/dQQf1ar9U+Gsl619ZsaTSzpg36UX1aoUQ8/sCOuQSl
         BGf7v5sDaBCRcaD7to8T4z3dKg3YFbeKwjaW+JMGRK9tRFQ4ELmitvbSSNXdq48CjN6E
         /JLFYeH7LKEy7YnmeRVJMePYdzU8UBqTikdA66dt+lUUqR6xtCUS0EmvRsrY7YNV/r3c
         g3wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=6twQ3YD+O6lKWXv7FZ10wY/RISPC4Rrqd2xo9NNSTbE=;
        b=JZtln/TdYCuYHyjImqscTDf4S0LBWOiInouEoT9PnfyJZsHet63oPhbG2DCeo7J7FD
         XInMSNSzr+jHJz8bIBjqBJFaWP06VtDBLDV7hmHM9/g0XSYAlHRzuFvw8dkzW9p0ha5R
         ri6/XUaLsJNFQHxpeAorJ9SAX3BVpnzTfCaX6agRJtbKXiFu8MkZOuurTcE9y5nhBu/h
         1qYRjyNBFYblRHFpQnszUj1qSbmxEPjNM1688/98UCuOiRMvqaxb+t57Wm9BY71OurHz
         KcZud04e+4sPpOnq4FjyaDbZ0PX97FnN5NbmNPiBDZVUVnUwdg+GegOr+rWvaEcmUUcv
         5qPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id r1si343675wrn.2.2019.09.25.07.31.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 5FAF5B60C;
	Wed, 25 Sep 2019 14:31:19 +0000 (UTC)
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
Date: Wed, 25 Sep 2019 16:30:54 +0200
Message-Id: <20190925143056.25853-6-vbabka@suse.cz>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190925143056.25853-6-vbabka%40suse.cz.
