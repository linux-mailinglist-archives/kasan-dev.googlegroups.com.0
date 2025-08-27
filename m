Return-Path: <kasan-dev+bncBC32535MUICBBUUCX3CQMGQEDJJXIRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 566E1B38C65
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:06:12 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-24457f59889sf2914605ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:06:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332371; cv=pass;
        d=google.com; s=arc-20240605;
        b=BXy6RbLY1SqYf9zXnl5BFxF3+vVVGooYOOiVzFzVGWL5309Y3AuhpicIEaLUDQnY6R
         KA6C5e8dYwgc8qxRbTD3VY0rd4Te9HaQPIossIzCC2QSmMFcLYYs6gyzCEb/xcCxLBlH
         RraYhgtJtOCXbBXVmLQMoXxEUm/oIGHy8bWGhAKHpjbqKUVEUMlfXoiZjVgS4RYwTUkw
         Pede78w6EQIIR1aa9PNyaI44kMbluUv2y+FLNsuClIVc0G4xYJsfqOV5Z93wZ5fr2fAi
         ps7yEkdCrSXtpX7hhHP7TVgiJGE9alcJazt8SjkPykbRmwdZza8/bw2pO00eCvc/RdDu
         mSoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=b89Rk5aQFg9VtlX/IZ3ekTeXzbD6JhUrWkCh9UPLStw=;
        fh=wvoEKKZvkDY91VXQXbS593q/m6Nh7SCxglyO/f6xho0=;
        b=ebVhSynWlUcr8nnxEjGtCgjAeKKFWhtQYf5kOWAfLCEWzz/4UJitcu8jWq1IfTZBe7
         dHCnqJKNgMZJpCmcMssfuzFvy9P3vzOpCBqVqApVQTquFPE1aLzEuvcgz6jzV/qm6Hqa
         VmNm31TDJP7ve3Ni4M+SxvqHlx+ekzxZ84EfKAZ8wzrib3qausSjPSZZSYGoNVnN/b2s
         alOSpK9bnpZ3jMNis6QCh4cvhrJ09ipTmJRTshK+4tJpgW5DXQxCBQzW48tY/WZw9SM2
         FAVb7lFgS+fqsIL3D2Ym0qbgb+yhXlcCvz2vcS7WvsuuIfFpVbmcPYrbupUKd601mc9P
         Z7UQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SLSX3DJS;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332371; x=1756937171; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=b89Rk5aQFg9VtlX/IZ3ekTeXzbD6JhUrWkCh9UPLStw=;
        b=Lv3fZZZu7+Z0fLsalcmBOOLL/2idTy4LG5S622hTXd8cYe0FP/HI98n5SBsovQs4MZ
         D/9e7jEUw/rKhsU/i9x7By3CxKytU7V0TC0MdVpIUy7PlP4l92hjQe8pSLt8TmUup8JV
         NaOQzd+i7kH4CogcIWkA+hnyj5VdkeVZh0YN+np3RGsxNvly3QLlq+5nAatYlm4+ypLZ
         UYRgUxj+bWYX8eSJdXLMHcwIkgKOqqjeS4FtcBzV4Vs1axLRVdyY+75GiqpCQPIh9vEX
         DxSE3rM1QCbXasyZLUaYI/eYAEPlVVe0Yl6q8G29SjUv7KMtevNSaPL1ObOUVU2jlXXY
         vmVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332371; x=1756937171;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=b89Rk5aQFg9VtlX/IZ3ekTeXzbD6JhUrWkCh9UPLStw=;
        b=QznzDwiMnjifGD8glSKMKQDJ6EHuf3uvTMMa2XNhZVQRLqp8GyncxOFdlXF3kUyyot
         Vih3Kk2E0wI9RCWBJdwHQI9vAyS8vHgx5AKPUlK/i8ry3lY9yHwjxdzqBzULWRzGW2H/
         7Mun9DnLfbfw2/7V977devQXnQINVxtazKSUj5OXuVqQ0DQfHLkW0BVwSHBnFoHMh/ZS
         xDmnEOitkBxUt8toHIM8Q8M2WD3pn9cIj+AOenvnPVdsnqBojUYGNS4FG0fN6WpeKgjc
         dRsNR/uvlthlA/xa5UhEd1zyZida5qgVpA97z86XHzGBmeO8t2SrYu72RcYz7lV6yzgt
         iX2A==
X-Forwarded-Encrypted: i=2; AJvYcCW2/NMgfTtsmhwSccQ54aEMuvMqbcgDDohVS9I7PqqXEfEyaK8XQLB/cLoHBgcYRbznC49Lbw==@lfdr.de
X-Gm-Message-State: AOJu0YyjTnLqo7r8MiA2JCjNsofOQ2QIH+3xRiAoPKrp/vAySlIVJBKj
	RRcqbnVTSAB99K5fYTn/yKBekftv4fVrhF2TsTNkrep3ouGyCpZiapce
X-Google-Smtp-Source: AGHT+IFWUeHtHcUo0yINvx5gggKMUgMRA9/l+Ha/dI8OXvsrHXZxJINjnYO2IzbyG0zO1c0HvsKY6g==
X-Received: by 2002:a17:902:ef46:b0:246:ceda:ebeb with SMTP id d9443c01a7336-246cedb07ecmr147242195ad.33.1756332370729;
        Wed, 27 Aug 2025 15:06:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfoMP6xqYoh5e91QUIT6F8/TjmX/4AnoLq2fQPODPx/nw==
Received: by 2002:a17:902:e810:b0:246:570:cbdd with SMTP id
 d9443c01a7336-248d4de7f52ls1696245ad.2.-pod-prod-02-us; Wed, 27 Aug 2025
 15:06:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/+y46zaqAtE2vnfGbNznYBygK7pZJiqpLgBmnhyaKhhm+EJkGL4Aq0vmFCI8QmOGl4f+y57pkezg=@googlegroups.com
X-Received: by 2002:a17:902:d486:b0:246:b46b:1b09 with SMTP id d9443c01a7336-246b46b2296mr187218665ad.30.1756332369212;
        Wed, 27 Aug 2025 15:06:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332369; cv=none;
        d=google.com; s=arc-20240605;
        b=iynJrOAihw6RI58HmXtgm+eBr/nTO+4G8HmjETsfJAfGD4Howl6r2hS7/WKT5AD6P5
         6RNIL34lbPU+36c2TbjIBOCWpoO7McVc6Um2+OGodHKm12WAYQnnK5OGnG8NiRlv0G5A
         5o0XeaV3JcD/bjYgvZzZTMuyJbzslHW5CMvEryfkMaC11XrPbMBIofkxIdQUQfv2GZS2
         0OwJ0pPXCm2GeacFr2hHV9cOQJH1mC5YRGwS21izX/Mn0dKmEdGzQj4cjixbgGu5LLHp
         frVaRS5v01Imlly6KqC6AkdxpUtmlCRwZGFN8DlVgimpafGWG1FQSr4HExx/NcZ5ZDBW
         qGmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jt1gUZzcr2XqEG7AN90PiEkY48hGbYno8tKmbdcHa9Y=;
        fh=b8pL5mxsrifaEynZEGzAqvQF5L+S8U+H1jEuAVk/IKA=;
        b=SpC/wsXxcw4Ew8DzD+gfz025Zmmi9/jEhZILZ5OGqST5j0QkquOWFN467paoqPpNSV
         WvNUd9+Xh54s9REBOsQlTR/xvlLJPaMUp7L513A0X2Z9qxu28lpfSNKK4k9EBnmX8svq
         m/RRJkTJi9mkKcNXLsm8uu0Xcfema5MuNYCY9TI3PIwhxVpAUycavX2zhvthwepB7Bgm
         MDBXPEL8NFURe0cFOqsZY52Yti593oUXWU7e1ZO39isjBnnFmuNjfbeXbHXeg8Dug1Cy
         LSfernAOmVnjdWemTsuM7oaVd5+Pbfs1szULo0PuqW9Dt1Owq6/HjcTkuqr/9IKIgLK7
         cI5Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SLSX3DJS;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2489ff0aa05si1285675ad.7.2025.08.27.15.06.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:06:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-522-J9sCWjtzNZKv3p8K8yqDNQ-1; Wed,
 27 Aug 2025 18:06:02 -0400
X-MC-Unique: J9sCWjtzNZKv3p8K8yqDNQ-1
X-Mimecast-MFC-AGG-ID: J9sCWjtzNZKv3p8K8yqDNQ_1756332357
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 230CF19560B0;
	Wed, 27 Aug 2025 22:05:57 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 5908830001A1;
	Wed, 27 Aug 2025 22:05:42 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
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
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: [PATCH v1 13/36] mm/hugetlb: cleanup hugetlb_folio_init_tail_vmemmap()
Date: Thu, 28 Aug 2025 00:01:17 +0200
Message-ID: <20250827220141.262669-14-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=SLSX3DJS;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

We can now safely iterate over all pages in a folio, so no need for the
pfn_to_page().

Also, as we already force the refcount in __init_single_page() to 1,
we can just set the refcount to 0 and avoid page_ref_freeze() +
VM_BUG_ON. Likely, in the future, we would just want to tell
__init_single_page() to which value to initialize the refcount.

Further, adjust the comments to highlight that we are dealing with an
open-coded prep_compound_page() variant, and add another comment explaining
why we really need the __init_single_page() only on the tail pages.

Note that the current code was likely problematic, but we never ran into
it: prep_compound_tail() would have been called with an offset that might
exceed a memory section, and prep_compound_tail() would have simply
added that offset to the page pointer -- which would not have done the
right thing on sparsemem without vmemmap.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/hugetlb.c | 20 ++++++++++++--------
 1 file changed, 12 insertions(+), 8 deletions(-)

diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index 4a97e4f14c0dc..1f42186a85ea4 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -3237,17 +3237,18 @@ static void __init hugetlb_folio_init_tail_vmemmap(struct folio *folio,
 {
 	enum zone_type zone = zone_idx(folio_zone(folio));
 	int nid = folio_nid(folio);
+	struct page *page = folio_page(folio, start_page_number);
 	unsigned long head_pfn = folio_pfn(folio);
 	unsigned long pfn, end_pfn = head_pfn + end_page_number;
-	int ret;
-
-	for (pfn = head_pfn + start_page_number; pfn < end_pfn; pfn++) {
-		struct page *page = pfn_to_page(pfn);
 
+	/*
+	 * We mark all tail pages with memblock_reserved_mark_noinit(),
+	 * so these pages are completely uninitialized.
+	 */
+	for (pfn = head_pfn + start_page_number; pfn < end_pfn; page++, pfn++) {
 		__init_single_page(page, pfn, zone, nid);
 		prep_compound_tail((struct page *)folio, pfn - head_pfn);
-		ret = page_ref_freeze(page, 1);
-		VM_BUG_ON(!ret);
+		set_page_count(page, 0);
 	}
 }
 
@@ -3257,12 +3258,15 @@ static void __init hugetlb_folio_init_vmemmap(struct folio *folio,
 {
 	int ret;
 
-	/* Prepare folio head */
+	/*
+	 * This is an open-coded prep_compound_page() whereby we avoid
+	 * walking pages twice by initializing/preparing+freezing them in the
+	 * same go.
+	 */
 	__folio_clear_reserved(folio);
 	__folio_set_head(folio);
 	ret = folio_ref_freeze(folio, 1);
 	VM_BUG_ON(!ret);
-	/* Initialize the necessary tail struct pages */
 	hugetlb_folio_init_tail_vmemmap(folio, 1, nr_pages);
 	prep_compound_head((struct page *)folio, huge_page_order(h));
 }
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-14-david%40redhat.com.
