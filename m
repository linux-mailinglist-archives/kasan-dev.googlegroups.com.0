Return-Path: <kasan-dev+bncBC32535MUICBBXHN23CQMGQEKMYGLCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id CB6FAB3E886
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:08:14 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-30cce9b093bsf5640591fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:08:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739293; cv=pass;
        d=google.com; s=arc-20240605;
        b=fm1DrNBH6dP7pQJrxCiDKEvu3FM3q4q6KvVhOCMOi4pXddw3upXq2bAK3AcLmQsJgw
         JTyF+aNn8ZsUj8h9oP5zcpW6pwbUDrEao19W4JaehxWchgHGOSiadyVjpgaeARIJB9fO
         L/yji3qeHTcgW078hKyq1lec5/B0JUkiHculopAq3WTNs4fxaQwsuVXR/6KUkq6vhD6z
         7WJ2xJi6NFTqQu6r9VQ/E0rWuRJ1RLZo6n+MlZi9Myu0KT0bwNjt9TVQVs2wa9k7gtJu
         ubU8bhHnxDfOL4AiWo1enPo9eVhZHtUj5qnp58/J42ujJIiTUbz+Uqiz+Vmg7LDMacY8
         zpdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=hP1mTJhU8ibWNZw5C4HflWvjZVx+MSy9cENs3PuJM8E=;
        fh=3m9u8EVsJUXNAc5hwH5mVWpU7NMh65zJb+9HJGHVmIc=;
        b=Ujifgh5PqxpCyEAboYl60sfUX2jXkEwVkp2cqZDlUcIjtfN0VGJpwn95t9N9tx+kLW
         5WuQtnumzD3PV8nucAt04SdFm2ZgUzTB5MNb6jniMy9NXNNJwn+vSufUKsKulp1rGGMa
         5aiNmyXvSdxHy8atPUWmc/RiCmE7klL/Cpb/mYPp+yVivaO2Mp15KwOv5i7MS6NcpRqc
         efDMZ6aAto8ic4lR3lfZ7LD3vPjPg3z8UrPCooz1gr/TOjQ3zcWr67kADBrexy0rF6d8
         lELDCA+YeA5h2yB1ZvPmkpFbpihLBETY3zLd6hsxs1H/LvqvvYIOo+dTvFvHncvksmez
         rCbA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Ag2oCQ3P;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739293; x=1757344093; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=hP1mTJhU8ibWNZw5C4HflWvjZVx+MSy9cENs3PuJM8E=;
        b=PFOGBqsJPASb+//mACcKEmWtTP3AB4noeulFTZEAEopwn2VfBipw9glM51tnMdbvKA
         sDS1o76wK+06uq9W4hD+aPyKnmFRKK+hkNZJsdUsCJzR6vMmdkP4aQPIAuKJTro/eeeL
         2k21BUPYRy4N0+xe0updf3Qe0IevGEZKMNAxZIhn18PNOhNEql47FBQKwbaZVyHZUB94
         oZEHmT7S3JROXS/y42tcuz2Pl439I6KPk6TI+YYsDdYRaKxiP6Hi454/pCGwUjmzgvkH
         EieH5nG1Er+ED4omC8kd1/G8mfoGVJ5/Fje3BGcNZo6Evyk/uKEHTokS7c85rnDtqTkt
         ORAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739293; x=1757344093;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hP1mTJhU8ibWNZw5C4HflWvjZVx+MSy9cENs3PuJM8E=;
        b=FuhYUldWdyV0GyOYYK0VZ7gvkXUoNHOE9u1FElL9sS1sgiqdTVn5GlaotXzkGLZNMF
         XxqrhjMHyVXo8wCl15KNar4AM9+1DhYZnlK7VBX/Sn1JTh0RLw8PnebuF1l/WYXcTLTc
         /c3Eyow6giD27uoZ4EhgLD9wWjdUVSM5BPww/GTu82KDKwSNVea8Anpl5qLPm+mA3unI
         FUmZLDyjHV0eAuHoVifEmxTw0nSvJ4OhqiL+nmG3xHEHb8fyteKXnKThdQk6khNqLs7D
         EIVIRFOfH/PQcgMlwDZGAqXS0kEAkE7hRbNYlw/O5bdX3GbRHb/nNh5QXcw+XnBy9cPB
         YDGQ==
X-Forwarded-Encrypted: i=2; AJvYcCVUeCEsXvxqu7S9pPHJAsJILiGSzHn0/3l7VuyRd6HAS6uCqBwZJiX/fdtddgVvAIXrOAlyug==@lfdr.de
X-Gm-Message-State: AOJu0YzvEuPhN6vUfuy9/Ls06YBbGgzqRyk/Ci6KlOR36R1TqEkohh5F
	1QkeuZUegtOmJSA8zhy2tJxUHTT9nC8cPuixIw5Jq6ydYA3o+3GaQ0Ed
X-Google-Smtp-Source: AGHT+IE5r2FbVtNX2qy9iEmERHeLW7CJOPMuxyBuOUIx5hKXxBherMNQ1ihCpCIXkUyMYu14A8eK2w==
X-Received: by 2002:a05:6870:1494:b0:315:c0bc:4bb6 with SMTP id 586e51a60fabf-3196306b5e2mr4764664fac.5.1756739292766;
        Mon, 01 Sep 2025 08:08:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdoC8vbthE9T02y6oLiGo7rT5VzC+IT65R9FZKvoP5+6w==
Received: by 2002:a05:6870:5cc3:b0:319:79af:8148 with SMTP id
 586e51a60fabf-31979b005bels1062375fac.1.-pod-prod-01-us; Mon, 01 Sep 2025
 08:08:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVcYatU8TUiHfpvpLYIjDG/IowqbtTLrEXMn6+TIigQZU/6Ks7vIEtlY3/L0mPkk7Szf1yq4XwSbyI=@googlegroups.com
X-Received: by 2002:a05:6870:219a:b0:315:2b67:2f3b with SMTP id 586e51a60fabf-3196346ff71mr3565419fac.48.1756739290918;
        Mon, 01 Sep 2025 08:08:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739290; cv=none;
        d=google.com; s=arc-20240605;
        b=Q93kOAW2Pi3kM6vfjVV5bOyH11hp5F75JV0WOMYBmkUicyF6sb59J7wjHs5qry5/LU
         6drBOkkYfVShfho0JUXPNvznUoZEOg1ck/wGIS+CLJSfp4BZWEpQXUKICjgA9BfCpno+
         3y1n6udNylR/y8qjnySsLS0Tk9m05IkVXiF+sbuFQH9QDv9sf8XoAvZ2meOd65BOlFXw
         hoZpyt+QboCe4cWVcG+Zlv5Jm9DpFIHlR/e817pdKWvB4JmR0/pqR6ua5K2p/+BUnUrX
         B2vYIlcr5NyCXeo3C7s8nL1A4QfjzNBCGZaBNY/MEEVg/Y2o+1RMXTmnXm9J5OUceyW3
         hBrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ELSebXAokPeuwfrjxvlrywVw1FQ39DJ4AGa2Bi31LpI=;
        fh=jgcnKVOIiO25wlSHIpY52lLj+/aCtpfhg8tQBNYWoLY=;
        b=bKNNt5NeFvk9Jp5InNSrHyKV4YCiNk5yQggCpJl0+oBv6GKil9MP4J5UtNkUynAu7J
         Ta6A8Gnm8W3wW6o6Xp3FJOSqu4xuq2X4/YvaunHo4eEuSeMc11/zAdflj+u1grnXRLqU
         pBEoEyjwqPWoiujL7ZDnuecv/VkG5dGEh6P1dhXJBdg6ZLR71SnmM0WEkx0VQQCXKQZQ
         Q+DPhH8RWhj2sGmj7f6R8ik/XBmg/yQa59BgYRB/eVObkbEHyyzCF1aA4wFf8e2EDgWh
         4lHzMUHXuwSMBJYdJJHcMFmXhlgWa92iPU/LisMHCAi88PaA+gzJWIIKvKUMwhEgo9iv
         IIOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Ag2oCQ3P;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3196d40d2basi217352fac.4.2025.09.01.08.08.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:08:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-479-Hz9nJ24_MAmhMNG_k-jiQA-1; Mon,
 01 Sep 2025 11:08:05 -0400
X-MC-Unique: Hz9nJ24_MAmhMNG_k-jiQA-1
X-Mimecast-MFC-AGG-ID: Hz9nJ24_MAmhMNG_k-jiQA_1756739279
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 1600C195609E;
	Mon,  1 Sep 2025 15:07:59 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id A66A118003FC;
	Mon,  1 Sep 2025 15:07:44 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
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
Subject: [PATCH v2 13/37] mm/hugetlb: cleanup hugetlb_folio_init_tail_vmemmap()
Date: Mon,  1 Sep 2025 17:03:34 +0200
Message-ID: <20250901150359.867252-14-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Ag2oCQ3P;
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

We can now safely iterate over all pages in a folio, so no need for the
pfn_to_page().

Also, as we already force the refcount in __init_single_page() to 1
through init_page_count(), we can just set the refcount to 0 and
avoid page_ref_freeze() + VM_BUG_ON. Likely, in the future, we would just
want to tell __init_single_page() to which value to initialize the
refcount.

Further, adjust the comments to highlight that we are dealing with an
open-coded prep_compound_page() variant, and add another comment explaining
why we really need the __init_single_page() only on the tail pages.

Note that the current code was likely problematic, but we never ran into
it: prep_compound_tail() would have been called with an offset that might
exceed a memory section, and prep_compound_tail() would have simply
added that offset to the page pointer -- which would not have done the
right thing on sparsemem without vmemmap.

Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Acked-by: Liam R. Howlett <Liam.Howlett@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/hugetlb.c | 20 ++++++++++++--------
 1 file changed, 12 insertions(+), 8 deletions(-)

diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index d3542e92a712e..56e6d2af08434 100644
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
+	 * As we marked all tail pages with memblock_reserved_mark_noinit(),
+	 * we must initialize them ourselves here.
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-14-david%40redhat.com.
