Return-Path: <kasan-dev+bncBC32535MUICBB5XM23CQMGQEK5KARII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 70F26B3E853
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:06:33 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4b3349c2c5dsf13377901cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:06:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739192; cv=pass;
        d=google.com; s=arc-20240605;
        b=ReNZS49NdM13pLrE4EHOKx+Xio7oJ9zeyUQVjbCm+v4duotY9xhmbrCv81+UT2Qt9x
         xJd4NImC6efj9GGAt2EKq8XyIUmfeUFvENcLksOStorr+I7RyVDWx/y0vUeqWFiH8RW8
         pcw0t/wC0tMSNWMrTAxx0TgrQ9MK/khiv9FX0VYESkEAfT/neddm+W6/8DUPZTPMB6s7
         Bc/EzTHx5iGaPgL/vh5fngDCr1D15iTKBSjpvemnzCLwOlXD40PlzKgKFIfIie0lkluV
         I7XYrw4eHqJmIoa0etUxApfAudTCMl59hDRwf4wr2Jweq10gEDycZaQ2nbuWTB9P+TIr
         IoQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=UPuJSswFQFLi7gSU7pTTuXMTen7ukYH8yxaJbCSTdFs=;
        fh=SajlsPcbFq99mJAjKINflOd/stq02evK2+Q3jWTXU/g=;
        b=F7OXvpyuyTKKzItlK+HtxvEiUPpnCG3SxPy5FvX5YmUP5Hl2hbfvgZUrVxFZPEBh/Z
         fyhMICNHSOCbAlmt5KfuhEBOPIADag9vF9xGIXSscO3MgCAjF64qNgMQF+c0o3hPfT0q
         9VObnQ8C53IiQV/9ioPIaVQ0DMucB0YVuQJpQcOP0UqLKFO3dqo3JlYCPPilDflz0JJ1
         i8lypuzMegh5ln2gCclo02Bap2kylkWLs7PCs7qonUy3EylC2vi7DnI3PoV1lYtEkrdj
         crtBOa142D/q6qSaVDS19FX2TsnOwoqew4PNGAqwYaST+D+xYFo3isUd+o8BQBywpApt
         595g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=AyU5PoSI;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739192; x=1757343992; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=UPuJSswFQFLi7gSU7pTTuXMTen7ukYH8yxaJbCSTdFs=;
        b=pECMrd1svJ9LQRXgKzeb5j13mrIjgeP0Mud1/z/K5I4ZHC4EPk+NsXrMYulSEzdXAb
         vgP0DEUvOGUH5WGE+lTMBEfFhJAK5DW8xr/5HzBRRBZjnCPYxaXeAo8PscRHNKMPlvBO
         IDz+PSh58nKstO4sbyifdENXrWDr8wF+ZduHkVUdCaTPghk/RHZ/LRQgblP83eFOA5Wg
         etkelCpz4ozUmtNMKmhcIEt1PZpfj0pw7ID7+Y7H17GjXwKw/Ri99u+sqnl3Q5x8eylL
         /e+cPXYOQEjrJN55yFRazaGJrapcugTebz032c02cnKsW/VDkj9ItW6OLEoZJVak0EcQ
         Ew3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739192; x=1757343992;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UPuJSswFQFLi7gSU7pTTuXMTen7ukYH8yxaJbCSTdFs=;
        b=Jyx1QRstp6ipJ7WyUfeTNBWD5xBGscGOw1U07oorfhw7AJ33gOIfRfSBu2LIZqDtzm
         p0flxTy2zG37ImeqkQ0VM/qtRlQXUU55fD4IyZZoBW+0GgIgG6i15gAx7TU5mSQRFNyP
         Q5Z1UAc3A3PzKbpmhnLOzHU8g6nBOcbniiHhemCIfLU4dGGEO5LKxMwWUvN8uo8cK6Jz
         8MFhVLKPXf2sHU9YrPGvMWzpORxfOnml07BJoHv1lq6AbVpYld06ytzpKGF7X8gQV/GG
         nBKR+xetBUGGgAz5zntPT/HaJNb7oj/d2s/kyfONzCWvFbsCaQckq+ZkpxGnI9O3t0Ro
         EtGQ==
X-Forwarded-Encrypted: i=2; AJvYcCVeKhr2fxe4t3uJVKXtc/nFiXDb4Qi5/LpdZVWByTh+Wo1AM5A9HQzhmK8WdzHwIcB06ILWaA==@lfdr.de
X-Gm-Message-State: AOJu0Yzyl2qI41y8YUWLNd1hJfM+1FnOwPw2bX7/oHA4VspzAyODxMYR
	L+yf5yuKqdTYanDdOtAEVElQp8RTNeghYhqMnGgTpqPZh/OhDn620K2+
X-Google-Smtp-Source: AGHT+IGcmekrrTZtxv8MbhYYiv92L6pMZa5if5xdwq33I7FKjCfUEocyFnhkgI4C4HfPlZHWP/msfQ==
X-Received: by 2002:a05:622a:1107:b0:4b2:d501:d177 with SMTP id d75a77b69052e-4b31d844fa8mr86243871cf.3.1756739190643;
        Mon, 01 Sep 2025 08:06:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfvwuPv3+OHS/zJoXLG677w92qvx2EK+Rx+zpXri5Qmwg==
Received: by 2002:a05:622a:1207:b0:4b0:8b27:4e49 with SMTP id
 d75a77b69052e-4b2fe66330els69853611cf.0.-pod-prod-02-us; Mon, 01 Sep 2025
 08:06:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW/WuymDJPXi0i9dHfrTc0Vm/y/UwBNjTKnuE2S6Or170OiQqPxglVjkBiY63zpnrpdb8zt1vfvHBM=@googlegroups.com
X-Received: by 2002:a05:620a:7103:b0:7e8:38ba:fa5a with SMTP id af79cd13be357-7ff2aa21098mr839379485a.39.1756739188200;
        Mon, 01 Sep 2025 08:06:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739188; cv=none;
        d=google.com; s=arc-20240605;
        b=cOmz0J9BVrP4VHgtzhrwd2ftiyJH2DYLWbl+6XhiHm28UpX+N+Z0eczLkUbYV92H0B
         D7a/Mui2ZDvIcSSm0VDPPnN3b7Z45hWtmLnykidMxgjLhfgwa9cV/uG+H8hm/27ARHm5
         0OQSk4uDfCmxGinQv3zVa/Lupbc21WgJWOyRU/v4zb3GC+w/ytYm44SK4siuHJnqAH54
         7aj2H5ec6wx+gbHe5AqDSmIRN/9+aoftfU/sz8vppX1SoSCxc2RTuAo1UFnOoeVFQdGc
         osDl2084UZND+q/hZcU3ho0HpOPX4qkQytWqpkF0g3eQfGoEbWy+HTMt1jFAJOTno0ld
         UKwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NTgr/pqX3UqVNNKIBPC5IiEd0D/dsfuHo0zqlHJEFcE=;
        fh=cuRM0MbqdhHdvX1pZ7KbQ/6RDS6jpPIk4zOrTmIyCaI=;
        b=ZhHZLk2tYK+0/iQzVG1zRU1n24f9u7/IIE8DvkkF8k2R9XqLqtioti8+rqCf0eIQyX
         96Oo68OYZI1OZMq4PJPU5EXErPXAiZQkgXgCh8wRpdr/5KwO114ZBjWkALplgD3Y+RHE
         WWGL5jbEj/PuOdIX5yaXVTkuBev0DiIgrlhXXde7M8P2OEhYrieRfrPmFpwFIFNPtPpx
         /Fht8/4T5BMtHDEAUeZW2/0il95YwH9Ovjup98z+psUrlLRAWTrBTISNbClepNiRaBK0
         AeK8vy2E3WQopzcsSQc/ITyjhStkkQQ8hCL9HfU7o78nNi7iVKriS/LWRMTeXv0czwVN
         7F6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=AyU5PoSI;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7fc11905071si36368585a.7.2025.09.01.08.06.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:06:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-441-LWOuJP0QNQig9xOBt6uhiw-1; Mon,
 01 Sep 2025 11:06:25 -0400
X-MC-Unique: LWOuJP0QNQig9xOBt6uhiw-1
X-Mimecast-MFC-AGG-ID: LWOuJP0QNQig9xOBt6uhiw_1756739180
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 330D5195608A;
	Mon,  1 Sep 2025 15:06:17 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 344B51800280;
	Mon,  1 Sep 2025 15:06:01 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Zi Yan <ziy@nvidia.com>,
	SeongJae Park <sj@kernel.org>,
	Wei Yang <richard.weiyang@gmail.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
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
Subject: [PATCH v2 06/37] mm/page_alloc: reject unreasonable folio/compound page sizes in alloc_contig_range_noprof()
Date: Mon,  1 Sep 2025 17:03:27 +0200
Message-ID: <20250901150359.867252-7-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=AyU5PoSI;
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

While at it, let's just make the order a "const unsigned order".

Reviewed-by: Zi Yan <ziy@nvidia.com>
Acked-by: SeongJae Park <sj@kernel.org>
Reviewed-by: Wei Yang <richard.weiyang@gmail.com>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/mm.h |  6 ++++--
 mm/page_alloc.c    | 10 +++++++++-
 2 files changed, 13 insertions(+), 3 deletions(-)

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
index 27ea4c7acd158..7e96c69a06ccb 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -6841,6 +6841,7 @@ static int __alloc_contig_verify_gfp_mask(gfp_t gfp_mask, gfp_t *gfp_cc_mask)
 int alloc_contig_range_noprof(unsigned long start, unsigned long end,
 			      acr_flags_t alloc_flags, gfp_t gfp_mask)
 {
+	const unsigned int order = ilog2(end - start);
 	unsigned long outer_start, outer_end;
 	int ret = 0;
 
@@ -6858,6 +6859,14 @@ int alloc_contig_range_noprof(unsigned long start, unsigned long end,
 					    PB_ISOLATE_MODE_CMA_ALLOC :
 					    PB_ISOLATE_MODE_OTHER;
 
+	/*
+	 * In contrast to the buddy, we allow for orders here that exceed
+	 * MAX_PAGE_ORDER, so we must manually make sure that we are not
+	 * exceeding the maximum folio order.
+	 */
+	if (WARN_ON_ONCE((gfp_mask & __GFP_COMP) && order > MAX_FOLIO_ORDER))
+		return -EINVAL;
+
 	gfp_mask = current_gfp_context(gfp_mask);
 	if (__alloc_contig_verify_gfp_mask(gfp_mask, (gfp_t *)&cc.gfp_mask))
 		return -EINVAL;
@@ -6955,7 +6964,6 @@ int alloc_contig_range_noprof(unsigned long start, unsigned long end,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-7-david%40redhat.com.
