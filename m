Return-Path: <kasan-dev+bncBD2ZJZWL7ICRBSP3WSUAMGQEUNTIADI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FEB67AA9BE
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 09:10:03 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-31f79595669sf1438970f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 00:10:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695366603; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q7ENbBE3xzxyyCXYVm+ulHADq7roJikV4/Osssll5WqhSWIcQV1V93rxjfQ+4jLqg2
         DEwROUVLQHMkodvglKXbWtJoByCZQWZe/ELqmnYui91ap5uGne3/XEbjhfLVYrPBrOZq
         eJfwuZG4Miu7BtA5/jIbYnXWV3e38J9nJfhyKMxA3+8wn6NCUvyLwFQCFBfDHS4453nF
         B8mAODD6niyuqk0GvJPyfo6Y6bclQTpQdTVynPpCnvK25ent5aWPglP6Wp839jTrXJl/
         KvkiChQgnrc3fdTIFuTdbpGwBEtXdCPrNwzhSOCg6v2zm3R8neaiMOqzmmgzZJuK6JSL
         N7EA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=X9O9+66JFQHrE0sPigFJL1wTitWySBEhLPvxXr4R9F0=;
        fh=KSy1dDf6lUvgdoPctzpy47/Mjv6bi14N3nvpkZLQDdc=;
        b=sd1BIyJs/oOVsxmxmkJbJ/Y5wqpj/t2qhVnYQjaVHwTCjMMztMlateQb+xDpf8jhZD
         fboG6A3+S0KUO7JRCRx9LTRX4V7W+kH2oYzWK4JjD2agQh+rDI9vLuaF0eCVg3ZYbqXM
         t9lIC3TExAB4LUuuAyqkf7nrWkScUhAUbi/ayva0xCGfhMhp8ChGsF+Zj9EvStX3T75J
         BRyNhM3sFkaqWhpJ2MSlc/Vs2wy2Z85zzv53bXq12LUtW9RUrTREO9Wfb5G5+wGms4Ns
         1fu2vkLkB3/tzZlijTbSlV18L7RnvoGLWRjI5kKX9JI3nU1Pv+xynyok5yiGJ7M2+Jz7
         LAfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jxWX0Bgf;
       spf=pass (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::d3 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695366603; x=1695971403; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=X9O9+66JFQHrE0sPigFJL1wTitWySBEhLPvxXr4R9F0=;
        b=nRIUyhBESRd2fRODw24pn06zeV2kf2CkQZSUskPPe4KMhMrKjhx6RPeRLnontIVloN
         CABzbsi/PN6rWMggM46vKd6bm18jPxbNam9Sm6qBj+tsS87+CpBFFyrow2FhtfQm94ba
         9qutSVcpeCldAEZm2ImIkehc0ta61Kk3kMW68QtlCrkjNfg4NkSwE8s3yFdemsm7vtIj
         EKzRA1ocuqtXBiRR+5mc7Tpgua2ltfgpTHYPL1wqg1xDERw4gRksjy0ypujksJj5f9Ne
         a3Av2e5ui65fSo+UztVg57AIsDWLsXAE9KtY3XiZPH5e+/a1pd/nI4AQklmYY87JGdhQ
         GmJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695366603; x=1695971403;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=X9O9+66JFQHrE0sPigFJL1wTitWySBEhLPvxXr4R9F0=;
        b=s0eqfrYBKTD2wuVeZ30WRhmai7CKCuspV3SFRnowUjpgI5ZAxRV1sAG0yPvAttQqKx
         wbWnDv0xj2RZBOvCdy6MWvDIc4D4sJC7/TmM5Ap/sfRk3hCkgOQOE+SlIkUvfXx/3vvJ
         nDUsRSuD57GaqZgQ0TMclWbxsDitM+10+d2j1ykyprhhdy6r/1opsI4obO4+dV1oMPec
         VXlhvEKjfyippT5z+gMZWwEhKqU4IihLKyeJceljA7LwnVUel0UYWjfLfJtDOivs5lrY
         uBUcpbJRoFyQV72yZ1ipNAgR4lsFxcT8RdJYDOPwz+E9L8mLgtEGeFWzUKVZrdufeltT
         Du4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzOZBzLuj5LBBnU2jRq5IHsdYrGVZwvYlN4XXVCCS+OzPQ9ECJF
	cgHqOKYBK2dsWpPoz2GDeF0=
X-Google-Smtp-Source: AGHT+IHh9cW2g6GQ5hmHG6Wp/yEjqeEbkgT+UjAGiNlG6D3WyoXLJ3KLARiDp8DnzIGfG75o6hb38A==
X-Received: by 2002:adf:ec82:0:b0:318:416:a56a with SMTP id z2-20020adfec82000000b003180416a56amr1301163wrn.13.1695366601906;
        Fri, 22 Sep 2023 00:10:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:db48:0:b0:313:f4ee:a4c1 with SMTP id f8-20020adfdb48000000b00313f4eea4c1ls449581wrj.1.-pod-prod-00-eu;
 Fri, 22 Sep 2023 00:10:00 -0700 (PDT)
X-Received: by 2002:adf:ec82:0:b0:318:416:a56a with SMTP id z2-20020adfec82000000b003180416a56amr1301112wrn.13.1695366600318;
        Fri, 22 Sep 2023 00:10:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695366600; cv=none;
        d=google.com; s=arc-20160816;
        b=cuLvkdZ2B9jVC2PqkQtKLKVZWMeyHsh8M9ZsUpZdvSZEXPR39GHUp+BmyPKzD0jEtt
         +VDcMIQSpY0oAJQUVmw+8Nlilfd1caPm1irNtH/eKJNV5NjwblXHJGMydfAifWBRADBG
         8rIHb3JthzlpC2NSmoOzoiwQsnxArBgClTy2eebXMlsOjdizaX9MRBqMNPgVr4OjGNAV
         57Rtiu79HzTHyGr3PktLNo8EDqBEX9MjME9LkvgJJvx5YhQY1D2QGfd4FaFnR7YmFC8M
         5XMlmP7qzFwdhVa4j2d4Kt8SCjWkNsWY4YPN/WvFWU1aTNMud0UokTTtN/8LMMBJKWPH
         Rjbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=k0mCgISWNiznjjM6SFzdDoz9gB321AuL+FXt04gr7LU=;
        fh=KSy1dDf6lUvgdoPctzpy47/Mjv6bi14N3nvpkZLQDdc=;
        b=YDnxPGSoiOfOqY7fTZUgeeIeJRbS8xE/rdXYsgyW5nhqHD7l6K3zF9xUpL43KBJWYk
         HCYys4cht5v3AbaD7DNO9PpuOU2ZSoGDYkbC2ZpwDj0fK++mT3V/lQkt9bQ8epoU5X/P
         Mpc/qDZV894TAvOFRVLKz081Qj+/HtKg6tRqUQKv9LCN1lcHpmWHnAx2V9uUmgMKzn+D
         9fc4CmFu6djLlylTvM5l8xeTCGnlJ2Ykm369oR/sweBtBEEUPd1IEq4OSNrt9St6Rd75
         xhDKEdwRtsL70M++hviDbTWHxreiBpE2iouDK+dNQ9RFpJnF1Vjeyk8w0y6nekU46N5D
         3Wwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jxWX0Bgf;
       spf=pass (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::d3 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-211.mta0.migadu.com (out-211.mta0.migadu.com. [2001:41d0:1004:224b::d3])
        by gmr-mx.google.com with ESMTPS id ay35-20020a05600c1e2300b004050f52a552si590178wmb.2.2023.09.22.00.10.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Sep 2023 00:10:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::d3 as permitted sender) client-ip=2001:41d0:1004:224b::d3;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Yajun Deng <yajun.deng@linux.dev>
To: akpm@linux-foundation.org,
	mike.kravetz@oracle.com,
	muchun.song@linux.dev,
	glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	rppt@kernel.org,
	david@redhat.com,
	osalvador@suse.de
Cc: linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Yajun Deng <yajun.deng@linux.dev>
Subject: [PATCH 1/4] mm: pass set_count and set_reserved to __init_single_page
Date: Fri, 22 Sep 2023 15:09:20 +0800
Message-Id: <20230922070923.355656-2-yajun.deng@linux.dev>
In-Reply-To: <20230922070923.355656-1-yajun.deng@linux.dev>
References: <20230922070923.355656-1-yajun.deng@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: yajun.deng@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=jxWX0Bgf;       spf=pass
 (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::d3
 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;       dmarc=pass
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

When we init a single page, we need to mark this page reserved if it
does. And somes page may not need to set page count, such as compound
pages.

Pass set_count and set_reserved to __init_single_page, let the caller
decide if it needs to set page count or mark page reserved.

Signed-off-by: Yajun Deng <yajun.deng@linux.dev>
---
 mm/hugetlb.c  |  2 +-
 mm/internal.h |  3 ++-
 mm/mm_init.c  | 30 ++++++++++++++++--------------
 3 files changed, 19 insertions(+), 16 deletions(-)

diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index e2123d1bb4a2..4f91e47430ce 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -3196,7 +3196,7 @@ static void __init hugetlb_folio_init_tail_vmemmap(struct folio *folio,
 	for (pfn = head_pfn + start_page_number; pfn < end_pfn; pfn++) {
 		struct page *page = pfn_to_page(pfn);
 
-		__init_single_page(page, pfn, zone, nid);
+		__init_single_page(page, pfn, zone, nid, true, false);
 		prep_compound_tail((struct page *)folio, pfn - head_pfn);
 		ret = page_ref_freeze(page, 1);
 		VM_BUG_ON(!ret);
diff --git a/mm/internal.h b/mm/internal.h
index 7a961d12b088..8bded7f98493 100644
--- a/mm/internal.h
+++ b/mm/internal.h
@@ -1210,7 +1210,8 @@ struct vma_prepare {
 };
 
 void __meminit __init_single_page(struct page *page, unsigned long pfn,
-				unsigned long zone, int nid);
+				  unsigned long zone, int nid, bool set_count,
+				  bool set_reserved);
 
 /* shrinker related functions */
 unsigned long shrink_slab(gfp_t gfp_mask, int nid, struct mem_cgroup *memcg,
diff --git a/mm/mm_init.c b/mm/mm_init.c
index 06a72c223bce..c40042098a82 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -557,11 +557,13 @@ static void __init find_zone_movable_pfns_for_nodes(void)
 }
 
 void __meminit __init_single_page(struct page *page, unsigned long pfn,
-				unsigned long zone, int nid)
+				  unsigned long zone, int nid, bool set_count,
+				  bool set_reserved)
 {
 	mm_zero_struct_page(page);
 	set_page_links(page, zone, nid, pfn);
-	init_page_count(page);
+	if (set_count)
+		init_page_count(page);
 	page_mapcount_reset(page);
 	page_cpupid_reset_last(page);
 	page_kasan_tag_reset(page);
@@ -572,6 +574,8 @@ void __meminit __init_single_page(struct page *page, unsigned long pfn,
 	if (!is_highmem_idx(zone))
 		set_page_address(page, __va(pfn << PAGE_SHIFT));
 #endif
+	if (set_reserved)
+		__SetPageReserved(page);
 }
 
 #ifdef CONFIG_NUMA
@@ -714,7 +718,7 @@ static void __meminit init_reserved_page(unsigned long pfn, int nid)
 		if (zone_spans_pfn(zone, pfn))
 			break;
 	}
-	__init_single_page(pfn_to_page(pfn), pfn, zid, nid);
+	__init_single_page(pfn_to_page(pfn), pfn, zid, nid, true, false);
 }
 #else
 static inline void pgdat_set_deferred_range(pg_data_t *pgdat) {}
@@ -821,8 +825,8 @@ static void __init init_unavailable_range(unsigned long spfn,
 			pfn = pageblock_end_pfn(pfn) - 1;
 			continue;
 		}
-		__init_single_page(pfn_to_page(pfn), pfn, zone, node);
-		__SetPageReserved(pfn_to_page(pfn));
+		__init_single_page(pfn_to_page(pfn), pfn, zone, node,
+				   true, true);
 		pgcnt++;
 	}
 
@@ -884,7 +888,7 @@ void __meminit memmap_init_range(unsigned long size, int nid, unsigned long zone
 		}
 
 		page = pfn_to_page(pfn);
-		__init_single_page(page, pfn, zone, nid);
+		__init_single_page(page, pfn, zone, nid, true, false);
 		if (context == MEMINIT_HOTPLUG)
 			__SetPageReserved(page);
 
@@ -965,11 +969,9 @@ static void __init memmap_init(void)
 #ifdef CONFIG_ZONE_DEVICE
 static void __ref __init_zone_device_page(struct page *page, unsigned long pfn,
 					  unsigned long zone_idx, int nid,
-					  struct dev_pagemap *pgmap)
+					  struct dev_pagemap *pgmap,
+					  bool set_count)
 {
-
-	__init_single_page(page, pfn, zone_idx, nid);
-
 	/*
 	 * Mark page reserved as it will need to wait for onlining
 	 * phase for it to be fully associated with a zone.
@@ -977,7 +979,7 @@ static void __ref __init_zone_device_page(struct page *page, unsigned long pfn,
 	 * We can use the non-atomic __set_bit operation for setting
 	 * the flag as we are still initializing the pages.
 	 */
-	__SetPageReserved(page);
+	__init_single_page(page, pfn, zone_idx, nid, set_count, true);
 
 	/*
 	 * ZONE_DEVICE pages union ->lru with a ->pgmap back pointer
@@ -1041,7 +1043,7 @@ static void __ref memmap_init_compound(struct page *head,
 	for (pfn = head_pfn + 1; pfn < end_pfn; pfn++) {
 		struct page *page = pfn_to_page(pfn);
 
-		__init_zone_device_page(page, pfn, zone_idx, nid, pgmap);
+		__init_zone_device_page(page, pfn, zone_idx, nid, pgmap, false);
 		prep_compound_tail(head, pfn - head_pfn);
 		set_page_count(page, 0);
 
@@ -1084,7 +1086,7 @@ void __ref memmap_init_zone_device(struct zone *zone,
 	for (pfn = start_pfn; pfn < end_pfn; pfn += pfns_per_compound) {
 		struct page *page = pfn_to_page(pfn);
 
-		__init_zone_device_page(page, pfn, zone_idx, nid, pgmap);
+		__init_zone_device_page(page, pfn, zone_idx, nid, pgmap, true);
 
 		if (pfns_per_compound == 1)
 			continue;
@@ -2058,7 +2060,7 @@ static unsigned long  __init deferred_init_pages(struct zone *zone,
 		} else {
 			page++;
 		}
-		__init_single_page(page, pfn, zid, nid);
+		__init_single_page(page, pfn, zid, nid, true, false);
 		nr_pages++;
 	}
 	return (nr_pages);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230922070923.355656-2-yajun.deng%40linux.dev.
