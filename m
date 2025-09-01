Return-Path: <kasan-dev+bncBC32535MUICBBYHO23CQMGQEWOF6KDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CDC8AB3E8BD
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:10:26 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-70fa9206690sf37892396d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:10:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739425; cv=pass;
        d=google.com; s=arc-20240605;
        b=SFskF09FcShl4mADPKRQD7fL6cIxVkKRZqCYzB5IaS1iSgRkgCyJ4+gm2M4v+GhYZF
         djWTnf3hmER0wyEGXfTQDQsxZ+rXcF5O0kiRrWDt4F5Kyef8kc1iXEgIRvTHJimhQrCQ
         9y+XBKFnhHxY5L++nsHnVAh4MRYiWXwJknGoDgkdOAJY/SFk+bnJkHzOJ8SXYnEJ9Hfj
         894tL7cCwY94S6pjQZrapuX+Ek/Tfzj7xzDf1jCO2fFT4wK4McnFM1+x1Xo0P/OZDFr/
         JP4h5sfaZBmtObwsGomWIRfzq5XNmDLQlJHsioT9ov9IzEsi4R0RmZ1zpb4158uMzG9q
         jGzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=MBak8T3Pq9HwbzNXtrCFktjBu0NUOhmt3o4A4I4vkpg=;
        fh=rpeoYV/aNfHx8oTjpf0k/wUuKzIIXRMecRArcO3bWXE=;
        b=IiIxpesJ0oVARRcf+C1AJMvSKWEs1ogR8rOXTz/dC72jjnNB/F93nUdxLfe4YkiVGD
         9dIo9AT14J67OnafdSxvABy/jB3fgY+D9yneTuLPHHcwTQiw+kHGcqUrWk063S3HYZYl
         Qz5p2x6etikf2u3uuGpkv6EpXbKnOWCkh9EhVDfe0iqCvfwX7Y3uR0sixfnvXpKL/HRJ
         M6PCLm7QKRRW0XxhiuC/HjWjd/OlwLnjVbBPlI4lmNePKBNmbuHn2P+ZeHlDdZbSpc49
         aID6qG6sD5LbRO2l0QMP10VAAzeehJBJmNr43JkjkzOn5rLV6ktm7EnCWn+8g+pxtMXy
         SaUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NdeReyDY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739425; x=1757344225; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MBak8T3Pq9HwbzNXtrCFktjBu0NUOhmt3o4A4I4vkpg=;
        b=Vi/U2ZSmvXpTXLe9tfIAXCW4LKMU9i62GsP5zCpEqiiEBl/ccMTp75+aM7orzCTgS+
         cjYaUF+8PB/skJiexf0dZlbkSNlxbiBWK5jJuCktDwF4e5iomrgob0VLypx9s1fCpf18
         VN1kMFK1w3VNBuNhMBZ4byzkSIdHF9Di1aShg0Ahd9qQGL5SlZrh+6/1TYrarvTW8iHR
         dkmCc3+ZpYiBbKtvqwfJqciAqrXGmVHxZtXBM2OJH2ppTigryprfraMGXH4OJ1nTa4q0
         rRr1LoS/RYU7gPMp12lADHWs+nK+0mKjdMTRqBghl0QzOzRphqaCz295CIV7S0l0hUy9
         RSCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739425; x=1757344225;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MBak8T3Pq9HwbzNXtrCFktjBu0NUOhmt3o4A4I4vkpg=;
        b=Q+A5vPGsRsW8IDVwqDp0iIwcLs3+XArhfrrcel4zojZHHDmFcJLUMuqs74kU4Gj1sD
         QxUfE1fQOfaovKUiVDNMneib9ySM15r0F37FCU0dzyt6FHPL4mMgH6SUTuuuN0cJaMaR
         PYp6JQq0PK+/3YOEZYnpSix6w+dhkXrqKOgsJ2Exl24WsuaSL9C/AeSAZoIQ8oEZ8GC5
         NsU3YQisfVQEH1wkOAd1tzYR2fSlen/TOuxTsNJFqf/7ipxQXG7/Vga7Ka/JaPjl2PVf
         F3qDvSUZVfwIvPL2D8IW/lxRPkK1Shv71RfhN70pL45sNasl9XEVwegSXPRULfFnvv0m
         e0jA==
X-Forwarded-Encrypted: i=2; AJvYcCWS6vDQiHiGeABJdxE6PND0NkcIQC56lhU1rJWHf1Qvwm+KFYO7CAluTZtTK1Zete+djR8P1Q==@lfdr.de
X-Gm-Message-State: AOJu0YywhV/C6FXmQ/d1E33tM4gqHzI4klB2KsnmONkgF+81TZIZN1KO
	OEdmmH81Px3EjX+eNClZcvapDYkDjrwoSXCe6cOm+kcRxDu8H4p3yDH6
X-Google-Smtp-Source: AGHT+IEtxQdDeMJjGuobYwBfHFXn6zRe5FqdgF7T/ioMTpg5tHp8jOV+WwILhkYBh7i1MI/NCYNfLg==
X-Received: by 2002:a05:6214:2589:b0:70f:a025:6c5c with SMTP id 6a1803df08f44-70fa97287cemr72409766d6.8.1756739425212;
        Mon, 01 Sep 2025 08:10:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeFKCdY5DV8bgIYvHHMUmfaBN3379euF692OnfF2sU01Q==
Received: by 2002:a05:6214:5018:b0:707:5acb:366c with SMTP id
 6a1803df08f44-70df04ab851ls40933236d6.2.-pod-prod-00-us; Mon, 01 Sep 2025
 08:10:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+cUWCbPMZDXpW76ByuWqp+pL4TkihEikp0MTY3Jl2mVGlrgoDlDOtJVr4GmQsD3jg89nRZfAnXb0=@googlegroups.com
X-Received: by 2002:a05:6214:29ea:b0:707:6cf8:5963 with SMTP id 6a1803df08f44-70fa972c016mr87815056d6.9.1756739423876;
        Mon, 01 Sep 2025 08:10:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739423; cv=none;
        d=google.com; s=arc-20240605;
        b=PDSjAbh3f1YoTRkd1ySCojXjjuKexuyAEUrT6BPvgrP8T/Uznb1Z0RqEqLzkAozCcu
         idIm3jLThGSOUjEbyAvHczByiHoitWDcPv/Q2UO5PDrMS7+j6jJ7EiTf40+SgFRXXwtQ
         yOAkWzu6QRno41ktfEmP0aLEMW75wkZZYlbqmAogHHka3EQyN+eCR4/G6E1HOK3/qxmz
         TkiynsAnXKrw5i91l/iAv8W/isDoq3uryZOap5cQ/rtYBCNgim4rJegqWyRP30Oc3YmM
         zLitt+bWx+lbmNv1aPnUFZn0RAJf0uXexTaQuIs4CfBYDBvsJFVDpUcVszZpjzcjdw4t
         qDfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Qfiq0B+dTjY9T7uZZN1EGvA+QpBiXzU5iR+jbjMvbBM=;
        fh=0ldixfjtj2gc2UqSrjkFw0e+NsZiuxb5Ys2kJ8pwXlI=;
        b=IFl0dXDeLkat8xocCR8cGmLv5oQ7ABBSixulaQCWSzXpau/v0bYFC7UmhakDU7NHok
         r/fsr2suVaMu/bZcz+2lNbWxE7y+2Lm9IJpHfUhxt5zOAHnMZQJI65botfsuhgAnMq7E
         scKAonQI25nmDaTTHsNjQz7n96Vk13Whri5HoL/w6b47AOf8iqrpRYurVS4SdDztxJsE
         9fis1Lc8OBwLvKyNAR1R3X5thN5b3oomuBLJZcczRV4ZzBhgnDcP/6HBVC+F26xlB+V/
         ysfkhGralUReeRc+dsmmRibbXEQTrYvK4DZMDtCK98FRvDtUf3OrWtvjUxKIPz1Z88I5
         JIXw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NdeReyDY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70fb27324d9si2230056d6.5.2025.09.01.08.10.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:10:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-576-C7HqVpXnPaeMVQh_fJcpwQ-1; Mon,
 01 Sep 2025 11:10:19 -0400
X-MC-Unique: C7HqVpXnPaeMVQh_fJcpwQ-1
X-Mimecast-MFC-AGG-ID: C7HqVpXnPaeMVQh_fJcpwQ_1756739414
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id AFFD4195608C;
	Mon,  1 Sep 2025 15:10:13 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 1094E18003FC;
	Mon,  1 Sep 2025 15:09:58 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Alexandru Elisei <alexandru.elisei@arm.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
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
Subject: [PATCH v2 22/37] mm/cma: refuse handing out non-contiguous page ranges
Date: Mon,  1 Sep 2025 17:03:43 +0200
Message-ID: <20250901150359.867252-23-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=NdeReyDY;
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
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/mm.h |  6 ++++++
 mm/cma.c           | 39 ++++++++++++++++++++++++---------------
 mm/util.c          | 35 +++++++++++++++++++++++++++++++++++
 3 files changed, 65 insertions(+), 15 deletions(-)

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
index d235b74f7aff7..fbdb73aaf35fe 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -1280,4 +1280,39 @@ unsigned int folio_pte_batch(struct folio *folio, pte_t *ptep, pte_t pte,
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
+	 * The memmap is allocated per memory section, so no need to check
+	 * within the first section. However, we need to check each other
+	 * spanned memory section once, making sure the first page in a
+	 * section could similarly be reached by just iterating pages.
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-23-david%40redhat.com.
