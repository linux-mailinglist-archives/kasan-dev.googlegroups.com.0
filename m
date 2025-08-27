Return-Path: <kasan-dev+bncBC32535MUICBBXUBX3CQMGQESSBYVSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 80D5BB38C2A
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:04:16 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-327709e00c1sf282996a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:04:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332254; cv=pass;
        d=google.com; s=arc-20240605;
        b=kfJ+FGsAT/QSie1zBOdDe1xdoAaf7d0fDI7OmPVl/fZel+WTMOvPb+d90HmofugO1d
         3RaWPOoTM/lm++3UaeOouQd76omxCFV5TiVqATYk2uIPFEqQMdUP6pK11s6ByBgCS+ug
         CL+aMSNBGYvzDMnaRRZx795hQuG69vyiDZr5a1ee2y9ik8naqXdsFkHJfQXT2jaOeLQB
         vJOxWdA4mu3uX1O4R7/Tap28hx4lDy5MxreupIV3hv9SFzmguYJRTjBqy1dt1NigFuHb
         9iPdbhz2unpS2U0JDb6ZbRsMybwNOjk3A/DPCDin6SAUAIru7HYyS39xWPJY2/6vvCWc
         hwmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=hBu91QINpPmLwa+XSZCyt90u4E3gWwEn2cMnFylrKSg=;
        fh=TBvccn7o7Ii6+6xFwZLzsVmMCyW9OIOE9H72bBGFDw4=;
        b=TGl+DqkVODr66hRaSmcFkhgxuRibRnzhaVH1juOPmYtsILA84el7LhPCybYx9+tv6K
         iJ4+RCyXIaTdiIAsdupzBVjWc7jZCLr5buhwe4mV5urRYVAfPgdMUSF5ymLlYNY0dTvA
         RCipRE0OWj4IeYjITmiKOD1ryhIY03sRclfEhlRM9a2Bt6Cpi1iRAVVLGJHa3bD60Jij
         nRNcKcVj+HeR99HeX3DnL+zl0zAse/7dI1AHPzlmaEH7A1dTLUDtlXWxUhYv+uQ6CXka
         DX1Y4v4DLGFAcfltjg7z/i4uEKlKG/gQxAUM6+cc3veggzyScOgg/8M/YGaebYyQmAJ4
         N+Bg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dPOAzf+g;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332254; x=1756937054; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=hBu91QINpPmLwa+XSZCyt90u4E3gWwEn2cMnFylrKSg=;
        b=wA+GO/Fl2yurehkLq41YDraq1YTluQKEDVNKI0f2UverhrS1QWwXdcfvwXQHf/X8XA
         35y/gzM+h4j9MXvuBSPhJ0v6f34cOHtqouYJ+6obMCOrs1rlPNwRg8SD396lzIwNNmtw
         LQSF9t9Pau/RbrZ1XHJpT5n3ziAXrTvoQPoj3OgIIMmdhwqNRBD3zOZtPqBjg2+pNmZy
         C/rMWRVkGdJ0+3vLYaSywTE57GkSEr8aAniNxnG4i9d+NEAvqboVHVL7jFMT90uCh/NU
         XwN6w++MrHb/WVgZ4Zv64sshpgda19YwSpUP5lhoyAB2t9ozSV5uwPMARUDfgLDCFT5H
         B+qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332254; x=1756937054;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hBu91QINpPmLwa+XSZCyt90u4E3gWwEn2cMnFylrKSg=;
        b=nRhvcdutOQkYAlIz1rP+qB6Yzduc0mOndkSO67NYwXKm2zPo9Pk+QUJZ62ooxo0GpZ
         e2fGJC7Fq4FMfag9Oo55Qbgerqeo609Z8UUDthnlD2aeE6ouDZLe88LfHjyPMqsUkKpu
         g+ezDCJqO1EmPr3rzOjFj0lLd4RBOVtxm9b8Q7Zqp1O9MUmajkXNEkpQsInt0qGh1bKx
         SPPVvNqx4Fa5J8rq26YxNBXoS6o2NLiE4Hf914IPnqpE4oEJLLLmv9v+r8FGqLZQvwpn
         1bjYBRnch8soHGx3j5GbPWH9cYQ14FpKk3Ye1mjRZwNMVwkhHVJb1H9X9f0I3HG67MIz
         BCJA==
X-Forwarded-Encrypted: i=2; AJvYcCVXi4SJCwaaOtD+y6CMxldgxkMl24rmmLRR5izLduhyERmZYv7irHrUjDGSdB+NzZKJsXvyrw==@lfdr.de
X-Gm-Message-State: AOJu0YzChOwdX0LwwbSIUC/64vvfbiR4i4eLd02IXCHx4UaRFly8aQQq
	XVqYITzmP+qgaujPUFtYO7Rmu2qLLjA/naraIA8/I633LTKkIR6RIYkb
X-Google-Smtp-Source: AGHT+IGVFVDNr7QOIdhocWfVV16UYEmSWQ/zADYv0vk2tCcBbGTHdEZA2nbX3AVn6QIAL1PHQLfIEA==
X-Received: by 2002:a17:90b:4c48:b0:327:734a:ae7a with SMTP id 98e67ed59e1d1-327734ab03amr4003101a91.11.1756332254331;
        Wed, 27 Aug 2025 15:04:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd7ZIiok76kufUfSy8m/4zNIEURK0va/dRuz6Q5DsU8EA==
Received: by 2002:a17:90b:5082:b0:325:7c02:d093 with SMTP id
 98e67ed59e1d1-327aac6d100ls139458a91.1.-pod-prod-04-us; Wed, 27 Aug 2025
 15:04:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWfV6JqccGWYojFhBIGOyCdzj28GeveCJX/iISLpgdAM+5h7xkSfI5QJcCn8kKQ4U7EyInutuzGpSg=@googlegroups.com
X-Received: by 2002:a17:90b:384d:b0:325:5df8:ecb9 with SMTP id 98e67ed59e1d1-3255df8f0a3mr23126462a91.16.1756332252795;
        Wed, 27 Aug 2025 15:04:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332252; cv=none;
        d=google.com; s=arc-20240605;
        b=OOE6ePGB44CAhkPKcEij4PhmDVy6rV8fXD1GMTzuBxwbDmMjTP3aRpts/TB4TBHiWL
         ESwrOzK9iF1avgo9ppxmo595O8s7lUL/tANAdjoMns4KjtaGD1fT47ERPctIEIDPBbLO
         wxw2ebj4722xdsWot6aknPKdWuoJpDms3KMJRhxPBrFjHGCLYmAEICqyimpagwAc0skl
         Rf/JaLvkWAko5l5y08LtscWrpa2+9RqLZWCZesWe6tTDsWeUgS4/oyo2uIuajpnW8dZx
         tcl6bBhtKVjlTJzJ6yrCpULxM0D21Z15mJIcuqarkwpX//h2p2nrgZzCekUudOrFs7p6
         UiXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eNV0RLrXImII8MTHVic+30uUi4HjChlJ3z+rf2azYps=;
        fh=7WZHKFLmSTGgrjxSHS251Xhut7Qc+R4owhf2H8udVyM=;
        b=CQ2X8BNJwFmXxvXzpvjuAP+46cgMBe+aXG6rRJc2c21klTyyYXPRkJ3skDy4lE67W8
         QjzoaKbnSE4Z/NOhBE1qz3NPQJAKPSoElC6tSRdnnhicSZGfuEvYNgJwFuTmfcH9Nixb
         AGLTGWeATncUAMmCOobMR99sqIGpXag02Trex05CXG2/7OWafNmTsGXtU8vw5MJwT2ZT
         lyvmTwMlzUAwrHUtlzM0/r0wXyXt387Beuh7X86U3Wpi4juKHLwzWPdMlWxCrfS5udMg
         c0gkvYc0Xh7Bz/DktBK8kyHnTW4rruf8W/QhOInZMBBOBoo9jAIPipffOf/o48DMatvx
         y8Yw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dPOAzf+g;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7720e184669si93540b3a.3.2025.08.27.15.04.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:04:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-41-stGls3aeOcqifozns1n-DA-1; Wed,
 27 Aug 2025 18:04:08 -0400
X-MC-Unique: stGls3aeOcqifozns1n-DA-1
X-Mimecast-MFC-AGG-ID: stGls3aeOcqifozns1n-DA_1756332243
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 1021B19560B8;
	Wed, 27 Aug 2025 22:04:03 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 14DAD30001A1;
	Wed, 27 Aug 2025 22:03:47 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Zi Yan <ziy@nvidia.com>,
	SeongJae Park <sj@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>,
	Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org,
	iommu@lists.linux.dev,
	io-uring@vger.kernel.org,
	Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com,
	linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org,
	linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>,
	Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com,
	x86@kernel.org
Subject: [PATCH v1 06/36] mm/page_alloc: reject unreasonable folio/compound page sizes in alloc_contig_range_noprof()
Date: Thu, 28 Aug 2025 00:01:10 +0200
Message-ID: <20250827220141.262669-7-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=dPOAzf+g;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

Let's reject them early, which in turn makes folio_alloc_gigantic() reject
them properly.

To avoid converting from order to nr_pages, let's just add MAX_FOLIO_ORDER
and calculate MAX_FOLIO_NR_PAGES based on that.

Reviewed-by: Zi Yan <ziy@nvidia.com>
Acked-by: SeongJae Park <sj@kernel.org>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/mm.h | 6 ++++--
 mm/page_alloc.c    | 5 ++++-
 2 files changed, 8 insertions(+), 3 deletions(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index 00c8a54127d37..77737cbf2216a 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -2055,11 +2055,13 @@ static inline long folio_nr_pages(const struct folio *folio)
 
 /* Only hugetlbfs can allocate folios larger than MAX_ORDER */
 #ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
-#define MAX_FOLIO_NR_PAGES	(1UL << PUD_ORDER)
+#define MAX_FOLIO_ORDER		PUD_ORDER
 #else
-#define MAX_FOLIO_NR_PAGES	MAX_ORDER_NR_PAGES
+#define MAX_FOLIO_ORDER		MAX_PAGE_ORDER
 #endif
 
+#define MAX_FOLIO_NR_PAGES	(1UL << MAX_FOLIO_ORDER)
+
 /*
  * compound_nr() returns the number of pages in this potentially compound
  * page.  compound_nr() can be called on a tail page, and is defined to
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index baead29b3e67b..426bc404b80cc 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -6833,6 +6833,7 @@ static int __alloc_contig_verify_gfp_mask(gfp_t gfp_mask, gfp_t *gfp_cc_mask)
 int alloc_contig_range_noprof(unsigned long start, unsigned long end,
 			      acr_flags_t alloc_flags, gfp_t gfp_mask)
 {
+	const unsigned int order = ilog2(end - start);
 	unsigned long outer_start, outer_end;
 	int ret = 0;
 
@@ -6850,6 +6851,9 @@ int alloc_contig_range_noprof(unsigned long start, unsigned long end,
 					    PB_ISOLATE_MODE_CMA_ALLOC :
 					    PB_ISOLATE_MODE_OTHER;
 
+	if (WARN_ON_ONCE((gfp_mask & __GFP_COMP) && order > MAX_FOLIO_ORDER))
+		return -EINVAL;
+
 	gfp_mask = current_gfp_context(gfp_mask);
 	if (__alloc_contig_verify_gfp_mask(gfp_mask, (gfp_t *)&cc.gfp_mask))
 		return -EINVAL;
@@ -6947,7 +6951,6 @@ int alloc_contig_range_noprof(unsigned long start, unsigned long end,
 			free_contig_range(end, outer_end - end);
 	} else if (start == outer_start && end == outer_end && is_power_of_2(end - start)) {
 		struct page *head = pfn_to_page(start);
-		int order = ilog2(end - start);
 
 		check_new_pages(head, order);
 		prep_new_page(head, order, gfp_mask, 0);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-7-david%40redhat.com.
