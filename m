Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBKXKY7WAKGQEC5OFN3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id A8B30C2099
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 14:29:31 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id b64sf2986600ljb.14
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 05:29:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569846571; cv=pass;
        d=google.com; s=arc-20160816;
        b=QfMHrC6DQvYYZ3/BvFnhNIwLayXQ1jugGwzNcJSdl5zPT1E/qVIOmR77xMuGMVotXo
         TNKQ6WdHffqU3ElflnPnURdiKH1mRhBr8ILyM0XjdA4Pxozpt9exr+hKblQT2VIqbx/F
         HeSZ28CJiCxE6fkRXw+ybe0oJ9ElU10wIESM4C5De16dsc4aPXKg8wI6pb52+f2wHo/h
         X1YUa4tf5HimCvbSCufSJAN9tm1lDHQ1gy8smuczw9gZz/8yNlcmH7hAzDODbKdcF41u
         qStqaaUQ+hIMLlEsXnfKQHYwaoPfeF7kIHn57tv8EbUuXVuhLEl0WjDqr9C8sg6hL/QB
         TL4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zilBxdg6SF3IL7EDnS9LTZ4CiovknR1Yl8ZU12tQw48=;
        b=y+K64lpTVoicZK4PX+7mzqW07lgwBYHColcgOGLwTJzV6fOsSXUjaqRLUBDIvWZ9s7
         BAx6AR9gO2GUBc3l1Htyx6eQUvyCY12ciNz2i28AQIIX8KY6hcxy6WQc9TzmC8ip37gB
         of3nrB3PtUzP6ZEVYo0CeRSYrvRVogNvFmmiHqATMvE/47yTEF0nBHpTy8wrgh6/x9Fa
         204eVZlyIVMMENhU8V+CIS+qDCGR+OKtp8kVgZ2Q1LhNp9Fzl01Dxi09nUsN7YTn4l8p
         X/p+qfnNYq8y0/FIQD4BijmnO13xcpwoZPhgpUuFW3zQOGWyd1N2qYYcvh+8AQ+GWhqk
         5R8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zilBxdg6SF3IL7EDnS9LTZ4CiovknR1Yl8ZU12tQw48=;
        b=rn48BREDFBT7j3FO6HtezENHJNx4CImCjHv2XkxgVib22f2a38DDfAKvXsftqOLsM0
         qLSgfiBjdmN6qSw5ALKI0vrxL+6Ebhp+yDwNHMwnak3cKJnAUpuwgJGPTNPhCUNE4Ibj
         IE7BpoINvrfL3sP/le5oP3AJdN/ANswkBZNb27gzWyymRL65DiFIOCkmLyxlnTlJlr+U
         kdpb7F01o/TH+zt69SFLKmZ10S7b3yAgOO9C2aSB03n3Wqof8LJz723QmKBEljZf1yZr
         M5Ega6BQfesPWUTFkCYThMnEq3doW/xYS6V8mABlkCQHGdnkYaWUMlmoIEgwFzCGQDCr
         cNvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zilBxdg6SF3IL7EDnS9LTZ4CiovknR1Yl8ZU12tQw48=;
        b=JS+eROwAM991iceprBhlJ1X2rjONINbZ0o+BGXc3lR2WGcZuykLaXhjGgTuBhkg1nM
         0at9p4yhXSlPfZJ+k5La7rDaUQ6LliW2kWbrRUcStlJ0lFnOPyrzwY3H1wD40/SPSI73
         rWMyNAvUNbsM7dxEclcsPz8f0VyK4uK3/0f4wZYD9++l8akYUHIKOur/9vzl9zoEat7S
         BY6epl87J+y7xRwlF5QVB55QC2z+xcv5HJGrxW3/mQyA6bycDuHXDPcL7vb4U9sQRIn9
         N3vm+e1FI58h0TZcbg/mGMa2EkkIwfxxbA8zxER8OTLKumXSMQ7Ihsh3uSrDSH/cw9uo
         zVbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUJFnxLgkxI6UIVbtwboiNofEuluj568slxOMHbfG1uH0Va1y06
	BHb5ZRD3N6Zvget5WgX7Eqs=
X-Google-Smtp-Source: APXvYqx9/pi7dPPHiswQjsxHXSuzFMrfDmNRHAm4oA3gbDDiqj/XBdivCcXRP8qNzF8Zhl2QbyP2bQ==
X-Received: by 2002:a05:651c:1127:: with SMTP id e7mr12152511ljo.186.1569846571112;
        Mon, 30 Sep 2019 05:29:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:7102:: with SMTP id m2ls1110370lfc.15.gmail; Mon, 30 Sep
 2019 05:29:30 -0700 (PDT)
X-Received: by 2002:a19:4f5a:: with SMTP id a26mr11084377lfk.116.1569846570279;
        Mon, 30 Sep 2019 05:29:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569846570; cv=none;
        d=google.com; s=arc-20160816;
        b=YLreoVLamfZ7+yFNhQzhImBG5eWxO4lh3Thr5VTmFloYN1HSWL3CJXPQAW94twijK5
         JVqEudq0taenHPLdLOoZoa+LXNrIWTdbK4ipyfWgUvSTLyB++tjoq1hJsmScKIU6nRco
         R/kMAVm2twUbfhs02gXt85Qou1atdb2WGnpOGqbxFsBHT14WTAYJOB68AdaPJ6q31EHf
         gODKms8lXOiuEg0Dl3N7asqGsES5nTO3vdCGGbPtzgoeVUunUBRghpBtshvQz4ukmIoA
         s0huc/9v/u02es+pPo0wHCkX/NPZerhjWfPbKIGCZnJWmwIXLW/iE+VOYs4NxGvkLzmQ
         0mOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=HbD7zZSSV4IxOzMYf4szfFOvkybJ2sRLxxhlV54DdPk=;
        b=Rl2FtGxq4kka8k1Ts4zi06uuVYXjMuIq0wkDUpgilCf4Gwox8Z+dtNXdtUqyInJ/Tn
         4j/8boZnffFZQW5JF5FNK4hJgqOkL+CKkK5iKhedsoMVu3L0an04ONyBoZahRzUb7DKb
         BWccH4CdqoeXuAtP4iQgBW0D7CIB//Ga8LHDqUdlRzJEF6oIQsrA+yRvR/5aoCv8xaIX
         GgqTNRSRq/4IyQZzMJeXWkJ73MvrOGyFxQxho5ABu0XId7yUxJfRFakEtvb0h24Stk6T
         OqiutHquBKuJQplRKjj8WfnGEcKqV6Fcwhbm40CCNILvqCXCUlA+8KWlpaICFElBiNlN
         q6Cw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id c8si839511lfm.4.2019.09.30.05.29.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Sep 2019 05:29:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id D4FB9AE0C;
	Mon, 30 Sep 2019 12:29:28 +0000 (UTC)
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
Subject: [PATCH v2 1/3] mm, page_owner: fix off-by-one error in __set_page_owner_handle()
Date: Mon, 30 Sep 2019 14:29:14 +0200
Message-Id: <20190930122916.14969-2-vbabka@suse.cz>
X-Mailer: git-send-email 2.23.0
In-Reply-To: <20190930122916.14969-1-vbabka@suse.cz>
References: <20190930122916.14969-1-vbabka@suse.cz>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190930122916.14969-2-vbabka%40suse.cz.
