Return-Path: <kasan-dev+bncBC32535MUICBBUEDX3CQMGQEVKT2LHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 17DEDB38CA9
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:08:18 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4b28434045asf11063551cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:08:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332497; cv=pass;
        d=google.com; s=arc-20240605;
        b=YxA5ZOXDqsPD94ldD0n6Hj5Y7PzNqNoz6oC5uJQPfwspiKpF6KNArGzFM8VBqtCdOr
         XKsPdSNhDRT3aJM+xeOIWKUMoGdtIcUbl7LWZ32q0ynAChCd1VuDSBJ5H9djFBGCOXov
         zJJ8OJELpUwGPNnuEYEVpbsprXNdlyzEpFgmN1p/Sl/vCA4hn2Mg4VQFkQetSeexmyYI
         lUtHjFQ4ZvKaKHBdO+rBxNj8gdYIwmIF+IJBseEEBiNUrI5a6SD+KMDHos4MLku+bYGP
         9s/iXOXmjfR3yAmyMJb//9CN3HxcIGVXartIT3HIPcg3GURYe4mOfVMXZa//16xQWE+2
         D2gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ODaDWUWHGVFymoaBPunktcGiXDXN+L52XMHTFf68vaM=;
        fh=R6+IOmV6os/zKIX1TBfn1Ko0ShyeWNB0qZ4PUhB+E/I=;
        b=CM8DG8GFWNbFPMt1sFU3N9PJHH5/z5hz1CSkXjndbyucGrNI/M83AvRmvyjMu+FSTE
         pWyo0qbcbZNgocHifdx5+Pw1q3WQYL6PYJD/JCJ9sOLsHjWr/swDZtwyytopP3yNA0FN
         FBPKFKASk7zryrvVHXCjqxElR2X2gmsu0zj5zbDfuat9BE6segUe+vR3vMHtpPzNUmLa
         vaa4vaYgLOWn9Rtaz85InTHEDD85HBk/7p6rcYizq+fwjYLspoD5TkPKT1o7K6jvpD35
         xRDK22KwGperDDp4UEjusBTkJkzgJtvwxvc4gzvJUhkWLpCDRKHuraJHmQ7ENNJ/8oI3
         9Kdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="YsUvt/pZ";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332497; x=1756937297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ODaDWUWHGVFymoaBPunktcGiXDXN+L52XMHTFf68vaM=;
        b=g3pvQkrCtJII5XGN85wI0TilFFiyjZvZmoPVXrFe2bTCWzum77hWL6kxO7L5cWcw5w
         FD+BgOE7CjVE2g58MKDRAU9d/MGXyS0ln4lw1j9cnrlxNYg6GBLSa81wNlrJ6Gk3W5vH
         skc2k6JqtBzPZgse9Ja4haS7dLgRiHtOgwoQFvaDLOlbR7Ftn/GAtZ89SHBHijctxPh6
         0skVAoe4eQLx5eoO5jtUAlgbxqQS4uxZYs/UX/VINzb9in/4EQErlsiW4A0glNu8IVuz
         drW6MUulydO6OQv/SyyL8IQnjicnT7kWQ0oHP7j8KKrcKL9cZ/T0Fi6xTOBGL5/txOKY
         MXqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332497; x=1756937297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ODaDWUWHGVFymoaBPunktcGiXDXN+L52XMHTFf68vaM=;
        b=u8W/OEq/LTTLShu7llzAfKvFDL/arrItH7fuVISS/KGL9FlAF2VZ9MhiZqwYzw8+U8
         9w3DxFcL61CXHP5LWztYR3rIQolGDcZl+yPjvR3xkOzo58doaM6FktqzczLPjG44MSpe
         cFlfD9Wqk3VH++W4VeoepWiAfVl1ILEEf+DmwhL1PZJmvOUYovPdce+sO3kmnCPH+Wpa
         2nI/7TqKp40R3Y/PIOW30qy08xCAnzsk0URypDDAIf8nQwYI2PBZu6pMgdgeo2ShkOpj
         WucUajkyyZ8XFTnhqllWomNirrIGi4udmMp6WbAOTAmbOdhRlLxWUR2Rujymg3Uyrx7F
         m0lQ==
X-Forwarded-Encrypted: i=2; AJvYcCUdbsnsWuVlQ/3kT8znUSBhIPV2poBNYJK2dvEENlP/uSv59huslceDdw9DyiMmINDNr9VrRw==@lfdr.de
X-Gm-Message-State: AOJu0YwjHzfng+4cOLxpdnolEgMQODvkOInYwcDtp99NL/Qsr3c3ljUI
	wWP6TtUJqRgaqFuwhR4KwTWFgwC0WvoVcAHv5psy5XwazxXAaBdggfJZ
X-Google-Smtp-Source: AGHT+IFtPV5vJcA4d+eOjzxl+msuydvdae+h/PMH4K3pNR19mhAmgZdjB6vGHFzo7znLHGRt+75TLQ==
X-Received: by 2002:ac8:5fc1:0:b0:4b2:fcf4:44c9 with SMTP id d75a77b69052e-4b2fcf44b50mr12646551cf.60.1756332496593;
        Wed, 27 Aug 2025 15:08:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeuTMHrP9MKAkOXnoF5z1P/UAMXJpRhETVX9WbuxC+8+w==
Received: by 2002:a05:622a:1801:b0:4b0:7bac:ac34 with SMTP id
 d75a77b69052e-4b2fe89dcd6ls2149071cf.1.-pod-prod-06-us; Wed, 27 Aug 2025
 15:08:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXC/hKB2xnll9LKP28rIYiiQ8Vzqt1Zc3ckP6RE3VvwwJiEWoXtDX86IrHwkOfn9S5dxOt46X2xf/E=@googlegroups.com
X-Received: by 2002:ac8:7f54:0:b0:4b2:8ac4:f072 with SMTP id d75a77b69052e-4b2aab67f7dmr202737231cf.68.1756332495330;
        Wed, 27 Aug 2025 15:08:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332495; cv=none;
        d=google.com; s=arc-20240605;
        b=I6ZufpvX8aKmDTWJJvP6IVP5/3C+yRlc/zC+E+C3rHoAwxCwnqTg56vlKwlgKLlquD
         fPXHhAUHB9T0orUGHGG930FCU1gYUk8znL9jpLNcFPSt8y9RAYT2f2ILC7bs8Npyl9Cg
         tfBHAKkTaZp+LqYlonov6x8s5LzcRmuL21Day0EwohiMPk2KzqRV4V3tmyMWeCzvVfoP
         g2ZFN2gqnrIf+P5dRV2k+udlHCIhzhxn76wwUC9mGthauAGqns5WWxqX0f0T4PONsPmJ
         sN7h4T5ZwKPa+BReGMHP0F6IOQKHUblCqfZSoxGUUBigfhGX03Qqvm+WlztFlVlSv+YZ
         Msig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oNaSehEob45J6rBCmQiuv1tai/IG2I8b55z4DkHJozQ=;
        fh=XP9LPdqDDxFd3t1I+co323UwcCT9BxTQCsRrPlSi6fM=;
        b=XJBpf/cLMU9FaChTLUPzTUJSNARlf9GFvPvdlRpcEv8/2N99m+BLzd1+gWKPUcUtf2
         HQYeYWZdh4SnSxqkgNurxT9dIETtyxpg+E3lcJJ9i3Tgrzi22fAL5DzlklAC8z/C9nQD
         5hsgIFuCP8oDDfa+dKARVre+VQK4B0Ukh/IhH+oSbw3SNIvM/kSOE4jMp89IQuIJ0YFK
         5Jnhg90qhTpxY3erLjc+K25ITzDwP5BD8GE5ragffleDJrrerv4YvMjHfKvzR9LfdKqA
         851zOYYsX79IvX49z/JY49Y/4HTszRpPW+gBIa+kSsZ8SW/w0NQcyx7XSAkM7dUCCTKl
         1OAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="YsUvt/pZ";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7ebf03c4a9csi59891085a.4.2025.08.27.15.08.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:08:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-376-aT4Dz_AHNuy0h_90DuEaig-1; Wed,
 27 Aug 2025 18:08:13 -0400
X-MC-Unique: aT4Dz_AHNuy0h_90DuEaig-1
X-Mimecast-MFC-AGG-ID: aT4Dz_AHNuy0h_90DuEaig_1756332487
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 2D1AD1800296;
	Wed, 27 Aug 2025 22:08:07 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 478603001453;
	Wed, 27 Aug 2025 22:07:50 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Alexandru Elisei <alexandru.elisei@arm.com>,
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
Subject: [PATCH v1 21/36] mm/cma: refuse handing out non-contiguous page ranges
Date: Thu, 28 Aug 2025 00:01:25 +0200
Message-ID: <20250827220141.262669-22-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="YsUvt/pZ";
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

Let's disallow handing out PFN ranges with non-contiguous pages, so we
can remove the nth-page usage in __cma_alloc(), and so any callers don't
have to worry about that either when wanting to blindly iterate pages.

This is really only a problem in configs with SPARSEMEM but without
SPARSEMEM_VMEMMAP, and only when we would cross memory sections in some
cases.

Will this cause harm? Probably not, because it's mostly 32bit that does
not support SPARSEMEM_VMEMMAP. If this ever becomes a problem we could
look into allocating the memmap for the memory sections spanned by a
single CMA region in one go from memblock.

Reviewed-by: Alexandru Elisei <alexandru.elisei@arm.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/mm.h |  6 ++++++
 mm/cma.c           | 39 ++++++++++++++++++++++++---------------
 mm/util.c          | 33 +++++++++++++++++++++++++++++++++
 3 files changed, 63 insertions(+), 15 deletions(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index f6880e3225c5c..2ca1eb2db63ec 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -209,9 +209,15 @@ extern unsigned long sysctl_user_reserve_kbytes;
 extern unsigned long sysctl_admin_reserve_kbytes;
 
 #if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
+bool page_range_contiguous(const struct page *page, unsigned long nr_pages);
 #define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
 #else
 #define nth_page(page,n) ((page) + (n))
+static inline bool page_range_contiguous(const struct page *page,
+		unsigned long nr_pages)
+{
+	return true;
+}
 #endif
 
 /* to align the pointer to the (next) page boundary */
diff --git a/mm/cma.c b/mm/cma.c
index e56ec64d0567e..813e6dc7b0954 100644
--- a/mm/cma.c
+++ b/mm/cma.c
@@ -780,10 +780,8 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
 				unsigned long count, unsigned int align,
 				struct page **pagep, gfp_t gfp)
 {
-	unsigned long mask, offset;
-	unsigned long pfn = -1;
-	unsigned long start = 0;
 	unsigned long bitmap_maxno, bitmap_no, bitmap_count;
+	unsigned long start, pfn, mask, offset;
 	int ret = -EBUSY;
 	struct page *page = NULL;
 
@@ -795,7 +793,7 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
 	if (bitmap_count > bitmap_maxno)
 		goto out;
 
-	for (;;) {
+	for (start = 0; ; start = bitmap_no + mask + 1) {
 		spin_lock_irq(&cma->lock);
 		/*
 		 * If the request is larger than the available number
@@ -812,6 +810,22 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
 			spin_unlock_irq(&cma->lock);
 			break;
 		}
+
+		pfn = cmr->base_pfn + (bitmap_no << cma->order_per_bit);
+		page = pfn_to_page(pfn);
+
+		/*
+		 * Do not hand out page ranges that are not contiguous, so
+		 * callers can just iterate the pages without having to worry
+		 * about these corner cases.
+		 */
+		if (!page_range_contiguous(page, count)) {
+			spin_unlock_irq(&cma->lock);
+			pr_warn_ratelimited("%s: %s: skipping incompatible area [0x%lx-0x%lx]",
+					    __func__, cma->name, pfn, pfn + count - 1);
+			continue;
+		}
+
 		bitmap_set(cmr->bitmap, bitmap_no, bitmap_count);
 		cma->available_count -= count;
 		/*
@@ -821,29 +835,24 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
 		 */
 		spin_unlock_irq(&cma->lock);
 
-		pfn = cmr->base_pfn + (bitmap_no << cma->order_per_bit);
 		mutex_lock(&cma->alloc_mutex);
 		ret = alloc_contig_range(pfn, pfn + count, ACR_FLAGS_CMA, gfp);
 		mutex_unlock(&cma->alloc_mutex);
-		if (ret == 0) {
-			page = pfn_to_page(pfn);
+		if (!ret)
 			break;
-		}
 
 		cma_clear_bitmap(cma, cmr, pfn, count);
 		if (ret != -EBUSY)
 			break;
 
 		pr_debug("%s(): memory range at pfn 0x%lx %p is busy, retrying\n",
-			 __func__, pfn, pfn_to_page(pfn));
+			 __func__, pfn, page);
 
-		trace_cma_alloc_busy_retry(cma->name, pfn, pfn_to_page(pfn),
-					   count, align);
-		/* try again with a bit different memory target */
-		start = bitmap_no + mask + 1;
+		trace_cma_alloc_busy_retry(cma->name, pfn, page, count, align);
 	}
 out:
-	*pagep = page;
+	if (!ret)
+		*pagep = page;
 	return ret;
 }
 
@@ -882,7 +891,7 @@ static struct page *__cma_alloc(struct cma *cma, unsigned long count,
 	 */
 	if (page) {
 		for (i = 0; i < count; i++)
-			page_kasan_tag_reset(nth_page(page, i));
+			page_kasan_tag_reset(page + i);
 	}
 
 	if (ret && !(gfp & __GFP_NOWARN)) {
diff --git a/mm/util.c b/mm/util.c
index d235b74f7aff7..0bf349b19b652 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -1280,4 +1280,37 @@ unsigned int folio_pte_batch(struct folio *folio, pte_t *ptep, pte_t pte,
 {
 	return folio_pte_batch_flags(folio, NULL, ptep, &pte, max_nr, 0);
 }
+
+#if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
+/**
+ * page_range_contiguous - test whether the page range is contiguous
+ * @page: the start of the page range.
+ * @nr_pages: the number of pages in the range.
+ *
+ * Test whether the page range is contiguous, such that they can be iterated
+ * naively, corresponding to iterating a contiguous PFN range.
+ *
+ * This function should primarily only be used for debug checks, or when
+ * working with page ranges that are not naturally contiguous (e.g., pages
+ * within a folio are).
+ *
+ * Returns true if contiguous, otherwise false.
+ */
+bool page_range_contiguous(const struct page *page, unsigned long nr_pages)
+{
+	const unsigned long start_pfn = page_to_pfn(page);
+	const unsigned long end_pfn = start_pfn + nr_pages;
+	unsigned long pfn;
+
+	/*
+	 * The memmap is allocated per memory section. We need to check
+	 * each involved memory section once.
+	 */
+	for (pfn = ALIGN(start_pfn, PAGES_PER_SECTION);
+	     pfn < end_pfn; pfn += PAGES_PER_SECTION)
+		if (unlikely(page + (pfn - start_pfn) != pfn_to_page(pfn)))
+			return false;
+	return true;
+}
+#endif
 #endif /* CONFIG_MMU */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-22-david%40redhat.com.
