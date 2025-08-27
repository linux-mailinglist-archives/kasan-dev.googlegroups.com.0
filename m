Return-Path: <kasan-dev+bncBC32535MUICBBHMFX3CQMGQE7JBHVGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DD86B38D1C
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:11:43 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4b109bccebasf8442611cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:11:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332702; cv=pass;
        d=google.com; s=arc-20240605;
        b=dS9OrNjn3d1873N0xqb43cD89/D8syMOhxjY9YhS4ENz5b5mZZCfgzJVlbVBkpGJ97
         wDRknMIxaQ2fANewdvzaejgQef2Yj2qEsdGH/RSCRy/5/dERqrZXIgwNr2fJe9Ool6NS
         DdyiDkxOdzt7S1768kfUF56GKZc5S+BtQkr/0icT5A3qQromnPRBU8yu5nlITNSfbOL+
         14LWRe3jhMMiaLVYvPgERjQcHn4b0IoBNhy9+24Uw6sdEYyMkmRL2oqVRQzjL5l6N3MR
         M1DGRsfCKLZV6hC+DjNqw+XWnIojSDhj9lVYnRGCV1q7a4tm4/6IC7ofF2bjgyVC3+QO
         qXvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=MgIFp6PbVYvkQrQFfGoTo3kgtII6zszgKb7+Pk0lLWc=;
        fh=1AsSTM9IK9Dx2ePICbcIAsszKWg1Oj37qsxBGiOREY4=;
        b=Fs9pTEzylAXgAzPSZr+dY/cb1j+lur6wlu4y3NROstgWckaVc1Q3JGLMVkRwO9lwDy
         LA7O2RnebVNLbfo+1rUyHJDItxQiekkLNDA+lNZXfaB/QKaJ1l7dc2gj7nr+vh8DwK1Z
         YTmt28KEuG+8wNBpZiBz8YSbPIUZIRr5iuWZ5dxWETes7xtARIBvULCVHtanXVlm35xY
         BukZ39/vpZi/6pEp/9iSlsBE1po8xlRTIZ8/XHaMFecMQfgfD7tHSTw2OnSwv0d4Sssl
         hKPvYXPMBXGvCJm9IEfM3A1bgTbShbPcu+YHYPpvumIg8Gb+kuCSIIhwdZK8uRtLi3/E
         X4OQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hRk7UZ0j;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332702; x=1756937502; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MgIFp6PbVYvkQrQFfGoTo3kgtII6zszgKb7+Pk0lLWc=;
        b=l1/nsyTU1hQgSIYpDoSv5UH42FmIs/RFIf7XcZl6HeIlqXfNYREBn/zHIlGyxZo8tY
         +7RPP8DoR0/CGBnOKvLeOTOvks6eiO9o6gkCi9agdGYr1STJZXfzaqxHfL0GuVx4fgd7
         DCxDi9BNg2fE6PjH9VGdmiAXcOZTJBoz5oquHWnrcT8jaAVTFYoPMivpy5MbuvP3jWyv
         ZmwW/mR3m1Znw8vrXNbOh4vO8PE3QkINYwz+Su6H6k2KstJuHlgmvnzqWgOPi/w18/3i
         JpmdbtsfDyLrTmUJuIVAcTetaTHm2L8wXBKcyDdjKQ0Bx+GPIZbJmErDA79YLm+KnwL3
         GM0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332702; x=1756937502;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MgIFp6PbVYvkQrQFfGoTo3kgtII6zszgKb7+Pk0lLWc=;
        b=qhasg0nVc6QgM8W6bvBn7DKvLzkIzpK0BEkYKJi9FpfR4buKQbwEhv1Vqn7B6ZkrEf
         yFG1M1qZ6WG9KHDyWbY2Rc9vSAK7ugV1YSEJEZbN/WnIhIDTbaQ5GQAJ5nmw2WZMuhnW
         lRMpv8LUEXmPn1GjtRB6oOUsT7u9raY6hWOyykwjwVzJL2O0H3DDgLRRYRfW9U76mPe9
         b7pvQLVRXv3DXjp9pia2lEiZSa7GuZuZ2es0cfpFihufE1lV6A4r8xmKH1uKeD/vf14Z
         BILrvcq1QfV8/nDC29eQtaQSW962/9//JrFUYh7mr/LA3NjDg2FOat9SflnlG3EE+w+0
         69ug==
X-Forwarded-Encrypted: i=2; AJvYcCWUdOsvXj91Erp1dOF1DT4Si+Y2+qhtF+k/FyJdsxooyVKcYylYg8tQr/VWWgogzIdRAHSC8w==@lfdr.de
X-Gm-Message-State: AOJu0Yy8OEgQBq0tSflA8WMVcQCEN00gZFZnxfAz7FmUxVrilmYBHJNp
	bx+oM918AAri5xLGMkjNbY/YAcFCFnN4TSOPJ4aOGCMF0BnRZDDqnmU4
X-Google-Smtp-Source: AGHT+IEtXK5kR0zc5UMdg9UnHhZ/krwVAb/plEdf5jj0IgzEbs5Rj9SE85TX7L01o/S9rlfmT5SrFg==
X-Received: by 2002:ac8:7e8f:0:b0:4b2:9eec:b0ac with SMTP id d75a77b69052e-4b2aaafa340mr265132431cf.44.1756332702094;
        Wed, 27 Aug 2025 15:11:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdiXoA6ABq53vXg+KUvfMPb5VdsuZrln2/ATHLeKa8dgQ==
Received: by 2002:ac8:5895:0:b0:4ab:825d:60e7 with SMTP id d75a77b69052e-4b2fe86dc86ls2368571cf.2.-pod-prod-01-us;
 Wed, 27 Aug 2025 15:11:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVlT4xbUILFbMh8xlDenGbpWSsQZ/2nEqX0deTgwUSpYX4kBNpr3+b8clYWhZtx6udG15PJXD5ioZM=@googlegroups.com
X-Received: by 2002:ac8:7fd5:0:b0:4b0:71cb:5e2 with SMTP id d75a77b69052e-4b2aab1b832mr275650091cf.57.1756332700587;
        Wed, 27 Aug 2025 15:11:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332700; cv=none;
        d=google.com; s=arc-20240605;
        b=Pd2vTuCBU6cCQVVT+CoiN/P5u27uy1t3k5PplQEpM3YN/KZNr1eJWo/bXJoLwJF9+n
         GV11HjUZ7QrPPQEdh0eonH3lpRTn3oUaAO/dDw2ST9+6VZditkffoEVR8YaqIYXx/co0
         wfv8sNTunLqoPdnP6DaveWgpfga8CsIAtyUUYi+DP1amGjmqFO0dMhfxrJhiDv2PfUWV
         rMv/j3sxOkYXcSR2TPtYm0v6t9Ces5v4W9k7ZI/YQ7LVTFfPvG/RV5GVGGoM+wVhNcCH
         z0YFsBI2O+cUieKdcwhOslLJyJAsHZ5j2cNU7wYz1pEYnoUtkrF9Cm1Wg+RA2suVr7M9
         of/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=J4GDJdCQl51NuSKZxl+9iTiOXWhrOYbM3n+02Irtvfk=;
        fh=b8pL5mxsrifaEynZEGzAqvQF5L+S8U+H1jEuAVk/IKA=;
        b=ZMpTmff2mcWuhyaaaMifx9BOz8AFfYB/TOPGtl3EW7uKAdJx34ekioZXpr03Ksrb0o
         buoKi0MaoCPwTYwVstfcvbecVERF5/KZjzy3n+VTQVPm3N/VLOd280ULTBljetnBMToa
         PMGX4s7Rg8PjiFOIx+IWQI9Ohcb3rCXvAqmL8A/2fEbSeaAGaOaff2a4+bK/UGpb/NCV
         aWheJUSvg3PVLl2idIPxqlfE6asvFeywERKnedmPxNkYi/ym4mgKebe/qOx0v78QQtb7
         Q5XcAo1ieIS+x0B1NACEYT1KBjht/Psip9WvIeLAcUMe81OLaJu/2g7b6+iUfp5TkRDX
         XjeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hRk7UZ0j;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b2b8af4d21si4850211cf.0.2025.08.27.15.11.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:11:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-581-9TdTk-QAOCyo3sfI9-0djQ-1; Wed,
 27 Aug 2025 18:11:36 -0400
X-MC-Unique: 9TdTk-QAOCyo3sfI9-0djQ-1
X-Mimecast-MFC-AGG-ID: 9TdTk-QAOCyo3sfI9-0djQ_1756332692
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id F1280180028E;
	Wed, 27 Aug 2025 22:11:31 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 78E0330001A1;
	Wed, 27 Aug 2025 22:11:16 +0000 (UTC)
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
Subject: [PATCH v1 33/36] mm/gup: drop nth_page() usage in unpin_user_page_range_dirty_lock()
Date: Thu, 28 Aug 2025 00:01:37 +0200
Message-ID: <20250827220141.262669-34-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=hRk7UZ0j;
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

There is the concern that unpin_user_page_range_dirty_lock() might do
some weird merging of PFN ranges -- either now or in the future -- such
that PFN range is contiguous but the page range might not be.

Let's sanity-check for that and drop the nth_page() usage.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/gup.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/mm/gup.c b/mm/gup.c
index 89ca0813791ab..c24f6009a7a44 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -237,7 +237,7 @@ void folio_add_pin(struct folio *folio)
 static inline struct folio *gup_folio_range_next(struct page *start,
 		unsigned long npages, unsigned long i, unsigned int *ntails)
 {
-	struct page *next = nth_page(start, i);
+	struct page *next = start + i;
 	struct folio *folio = page_folio(next);
 	unsigned int nr = 1;
 
@@ -342,6 +342,9 @@ EXPORT_SYMBOL(unpin_user_pages_dirty_lock);
  * "gup-pinned page range" refers to a range of pages that has had one of the
  * pin_user_pages() variants called on that page.
  *
+ * The page range must be truly contiguous: the page range corresponds
+ * to a contiguous PFN range and all pages can be iterated naturally.
+ *
  * For the page ranges defined by [page .. page+npages], make that range (or
  * its head pages, if a compound page) dirty, if @make_dirty is true, and if the
  * page range was previously listed as clean.
@@ -359,6 +362,8 @@ void unpin_user_page_range_dirty_lock(struct page *page, unsigned long npages,
 	struct folio *folio;
 	unsigned int nr;
 
+	VM_WARN_ON_ONCE(!page_range_contiguous(page, npages));
+
 	for (i = 0; i < npages; i += nr) {
 		folio = gup_folio_range_next(page, npages, i, &nr);
 		if (make_dirty && !folio_test_dirty(folio)) {
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-34-david%40redhat.com.
