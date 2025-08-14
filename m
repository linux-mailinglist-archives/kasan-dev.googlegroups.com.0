Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB4XN63CAMGQES7H35TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3395BB261F7
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:14:12 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-30cce9d10e1sf1385514fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:14:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166451; cv=pass;
        d=google.com; s=arc-20240605;
        b=LIN/dZgMSV3iHrYnU7agQdHurZtLpR/eXYPkyWgakUlic2T1vuIPlCBXrQKaYaOGHM
         XOTJ+5BPUqIlS0hrYinAnHfI6H5WlOzXwXuuM+SnVpaKe71bfLrfzksQ8Z1LUKMXtWgj
         7hS2wnHyaRvaxoCrJZJ6E/5qPOgWQ+f+KjhY5E+LHkGzXNbbvnnaikn7vcqVacMnsn9k
         PH4MBxVVl7F8TxjT8uK7zQdGL+GqsXTPimaWEGMKm2hPB5sJ/aTEBghp0MtILj61UGq0
         ODL9qZ+/bSG8ltq9Gkt/TwORtlZ4yyE95OUB6yJaYWHITcKjZkFddzZ3EtAqdDKSUkj+
         uI6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=X4nfkMcRT5mRhWSlM4XRf8kCE3LoihnE6Nhh7GprA3E=;
        fh=Te7rvFlteUI6GP0AfSKfB/WLkiHzuumwEZusBbK/3H4=;
        b=RJT25ELetek5PIQYVIk3zgAEaZk3V06z0FHK6s0Antkk8ZDmFBXs8C7whbKShk9wbx
         1rfJZZ2SGc1Vjr7NCI0WYJ10PtDjrKTxrziyMsn+X5OsirAf1O52PeyI7JbU5gHlMNpm
         q+3kBFxSwZwaWPtXKU3qzifXLx16IwUSBhUwYmgdruQISSDkH6O9vArfjgBchcBbP0WZ
         PhGXkIe5U15o/8VdKSMvolP00XK7H/cK9LTn8iaxAT5yAhKSeDYN3pslu3WOlMRTZTNB
         mpfUUI9CDn2CGtCGvmruJDSGrfwq8QCcPo97CVyl7jkj1jFhYBeDSATy5WhNbCAPFQIr
         s1vg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=l8H3hC3C;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166451; x=1755771251; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=X4nfkMcRT5mRhWSlM4XRf8kCE3LoihnE6Nhh7GprA3E=;
        b=CYR72W6gWSdKG941BItabW4iauUCFWBqPPHPh/eKnprCeLEmfRitPEQTn4mysCqUjI
         uXPUQ+qZdp2hw7iwLk4Ph85J/ds8C/afH5NXrjTiyXWsEf/z6ooORaoqMhzFq8/5whgV
         kTVwtA63vJUuMijVG2jjtKJRT13pTK0Xko0lT5qPzOFE9aPWg87a3vzEa3WauiEuJ2gR
         fIwel5H0u9zkqbmALSGBEyWGC7DLlyrZ9Ij3tEOdSVnhX1PvrK5qGdGL9RGjHbNaSiiV
         ac1eTWREfbuuvJDuKO84gU2MJTy46DD6JDll/E+JsoS5UMI4NOBLuajdIJym88wSAEgY
         Emgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166451; x=1755771251;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=X4nfkMcRT5mRhWSlM4XRf8kCE3LoihnE6Nhh7GprA3E=;
        b=ae2g9VFvEQ4BoXK84OrnHrRe5IE0fl5Fx6EWHYLE07uizCA+YHzgJoRjWJZ46JnsQv
         CujJR9uWX+JAWeLtotemwqL0wwle2lyKw0Gra7e74IdH/pOs5P+JRCvBqfLHHQO7OYmM
         aTuVwkXsF6T1+oCNR/VYUWUriq+KewOelhBn5ntIQYdcSxqvZtFu0iv0prRR2uNtArEU
         RpKjVvmg/pRhcvYRvZErJfboxcES3/2q9vKTGp1cYMbCpPDT/ITDEAOm2vZRk/Sw5j1k
         KQ2KNyWBm0ttGXfOuqfNAdhhSM7AHHSTcY5QM5xzYok9ig7BiVnAU6epRYT8UR7pcphi
         V6Rw==
X-Forwarded-Encrypted: i=2; AJvYcCVTkKzHOTl1vAtbvsxjnWL9jovFloYbRoyNr4ni/Tu8keB5wxCYQ+PR8ZWT4EIQIe5u05ZkuQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz7gmWnS2EGrD7rTKEooveVq+q0rlGJqdeQe+MpAsNEUerTQRfK
	VgS+FCejJSFyQhprIQGB5qqsTGyDymFbkMKfRahFt4lWR0vQ1KTy2Zb5
X-Google-Smtp-Source: AGHT+IHo5SPGGtxqejkCuv0pDhvmhG9rPtXGt6Tn42PuJoomfRFWC7FUcy3pkO2mdk5ivoYV6BQztA==
X-Received: by 2002:a05:6870:1298:b0:2ef:88fa:e0c3 with SMTP id 586e51a60fabf-30cd38a1430mr870565fac.13.1755166450800;
        Thu, 14 Aug 2025 03:14:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdPGFjuaCF2pTHA1kNFDetK4+xdShs0lN9Oswa6mnmQmg==
Received: by 2002:a05:6870:4009:b0:2d5:17b7:9f8c with SMTP id
 586e51a60fabf-30cd5cc4d0cls119347fac.1.-pod-prod-00-us; Thu, 14 Aug 2025
 03:14:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWmk4sUqn42ebvdBIxcT1neOq5tNh/W0xYYKdXrWoei/VHyTyfvm5X8I0KulQmcf6+3zrPYA0T/B38=@googlegroups.com
X-Received: by 2002:a05:6808:4fdf:b0:426:f465:8f63 with SMTP id 5614622812f47-435e0754d77mr1298386b6e.9.1755166448226;
        Thu, 14 Aug 2025 03:14:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166448; cv=none;
        d=google.com; s=arc-20240605;
        b=WwDxv0FPw91TozwLTpOJE9SPI5CbH+O9nX2G9d2Tu8AHSmotUGgXTCkrFIsd2roLcv
         GGaXziyaxezYh6AhTuUMt1hTuV8LD+NTH3yjhGT6rsx7BKtGMD5Opz5JsVmuY27BXkUv
         NvC9E4jK4tE19d0wMnG6GicXazNVxOgVSzqwQa2F7vJM5Wr/UWaSDympK4o+WEvvkib/
         Xm11LfTZ6EFl4wJPtpMg+jgF8xF0FM0zys4ll70jUXcyvUpbUKJOQg/lR+BGKJrOAxCY
         bdOAQXeSBLyBR19uZpEgeAjctlTZG2QsH4Nh8itRnaZL/LIOiGhLt/PI9CPQip6NqV4p
         CAow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kCJU29SWd1OR3k6ZUoBci43zBS+gLO8fdMAUUcFIoOc=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=SheFQLMbDm3QDMkYzg1ykKs1JLHQQ1rcEjc2cT87aQ/qvouiDjsObR/zpFjz9QWR1p
         usvY/1/ajEtqEX7wor9xaDQy2PtL4FfLMnmtcpyfTwQMfZvkEi6qXRCCOewuilCuOFnH
         KbewCwLD93eUuk7LcwcBlttI1YbB1KapA1nfJ5I1LhocgNxk7Bs/UCJr1Ww7d6oI6c3g
         0LViToB2hloiZGp6pPCaB3NccdEksl08Q9fcbKoKQ8+ow+e9qP2D9Oir382nbpJntasf
         JsIVRjiJK4zzILArPS3P5ooV6ia+WT8O7Fao8bj5dirvcaNi+rfhjlqEntlMHeQ/lYnB
         ss6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=l8H3hC3C;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7436f7a3cc7si277678a34.0.2025.08.14.03.14.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:14:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 93F086020A;
	Thu, 14 Aug 2025 10:14:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A0047C4CEF1;
	Thu, 14 Aug 2025 10:14:06 +0000 (UTC)
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leonro@nvidia.com>,
	Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>,
	Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev,
	Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>,
	Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com,
	Keith Busch <kbusch@kernel.org>,
	linux-block@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-nvme@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>,
	rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev,
	Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Subject: [PATCH v2 05/16] iommu/dma: rename iommu_dma_*map_page to iommu_dma_*map_phys
Date: Thu, 14 Aug 2025 13:13:23 +0300
Message-ID: <cd872c32c32bed2cc406ccdde9023b4db155f43c.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755153054.git.leon@kernel.org>
References: <cover.1755153054.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=l8H3hC3C;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Leon Romanovsky <leon@kernel.org>
Reply-To: Leon Romanovsky <leon@kernel.org>
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

From: Leon Romanovsky <leonro@nvidia.com>

Rename the IOMMU DMA mapping functions to better reflect their actual
calling convention. The functions iommu_dma_map_page() and
iommu_dma_unmap_page() are renamed to iommu_dma_map_phys() and
iommu_dma_unmap_phys() respectively, as they already operate on physical
addresses rather than page structures.

The calling convention changes from accepting (struct page *page,
unsigned long offset) to (phys_addr_t phys), which eliminates the need
for page-to-physical address conversion within the functions. This
renaming prepares for the broader DMA API conversion from page-based
to physical address-based mapping throughout the kernel.

All callers are updated to pass physical addresses directly, including
dma_map_page_attrs(), scatterlist mapping functions, and DMA page
allocation helpers. The change simplifies the code by removing the
page_to_phys() + offset calculation that was previously done inside
the IOMMU functions.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/iommu/dma-iommu.c | 14 ++++++--------
 include/linux/iommu-dma.h |  7 +++----
 kernel/dma/mapping.c      |  4 ++--
 kernel/dma/ops_helpers.c  |  6 +++---
 4 files changed, 14 insertions(+), 17 deletions(-)

diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index e1185ba73e23..aea119f32f96 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1195,11 +1195,9 @@ static inline size_t iova_unaligned(struct iova_domain *iovad, phys_addr_t phys,
 	return iova_offset(iovad, phys | size);
 }
 
-dma_addr_t iommu_dma_map_page(struct device *dev, struct page *page,
-	      unsigned long offset, size_t size, enum dma_data_direction dir,
-	      unsigned long attrs)
+dma_addr_t iommu_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
+		enum dma_data_direction dir, unsigned long attrs)
 {
-	phys_addr_t phys = page_to_phys(page) + offset;
 	bool coherent = dev_is_dma_coherent(dev);
 	int prot = dma_info_to_prot(dir, coherent, attrs);
 	struct iommu_domain *domain = iommu_get_dma_domain(dev);
@@ -1227,7 +1225,7 @@ dma_addr_t iommu_dma_map_page(struct device *dev, struct page *page,
 	return iova;
 }
 
-void iommu_dma_unmap_page(struct device *dev, dma_addr_t dma_handle,
+void iommu_dma_unmap_phys(struct device *dev, dma_addr_t dma_handle,
 		size_t size, enum dma_data_direction dir, unsigned long attrs)
 {
 	struct iommu_domain *domain = iommu_get_dma_domain(dev);
@@ -1346,7 +1344,7 @@ static void iommu_dma_unmap_sg_swiotlb(struct device *dev, struct scatterlist *s
 	int i;
 
 	for_each_sg(sg, s, nents, i)
-		iommu_dma_unmap_page(dev, sg_dma_address(s),
+		iommu_dma_unmap_phys(dev, sg_dma_address(s),
 				sg_dma_len(s), dir, attrs);
 }
 
@@ -1359,8 +1357,8 @@ static int iommu_dma_map_sg_swiotlb(struct device *dev, struct scatterlist *sg,
 	sg_dma_mark_swiotlb(sg);
 
 	for_each_sg(sg, s, nents, i) {
-		sg_dma_address(s) = iommu_dma_map_page(dev, sg_page(s),
-				s->offset, s->length, dir, attrs);
+		sg_dma_address(s) = iommu_dma_map_phys(dev, sg_phys(s),
+				s->length, dir, attrs);
 		if (sg_dma_address(s) == DMA_MAPPING_ERROR)
 			goto out_unmap;
 		sg_dma_len(s) = s->length;
diff --git a/include/linux/iommu-dma.h b/include/linux/iommu-dma.h
index 508beaa44c39..485bdffed988 100644
--- a/include/linux/iommu-dma.h
+++ b/include/linux/iommu-dma.h
@@ -21,10 +21,9 @@ static inline bool use_dma_iommu(struct device *dev)
 }
 #endif /* CONFIG_IOMMU_DMA */
 
-dma_addr_t iommu_dma_map_page(struct device *dev, struct page *page,
-		unsigned long offset, size_t size, enum dma_data_direction dir,
-		unsigned long attrs);
-void iommu_dma_unmap_page(struct device *dev, dma_addr_t dma_handle,
+dma_addr_t iommu_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
+		enum dma_data_direction dir, unsigned long attrs);
+void iommu_dma_unmap_phys(struct device *dev, dma_addr_t dma_handle,
 		size_t size, enum dma_data_direction dir, unsigned long attrs);
 int iommu_dma_map_sg(struct device *dev, struct scatterlist *sg, int nents,
 		enum dma_data_direction dir, unsigned long attrs);
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index fe1f0da6dc50..58482536db9b 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -169,7 +169,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 	    arch_dma_map_page_direct(dev, phys + size))
 		addr = dma_direct_map_page(dev, page, offset, size, dir, attrs);
 	else if (use_dma_iommu(dev))
-		addr = iommu_dma_map_page(dev, page, offset, size, dir, attrs);
+		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
 	else
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
 	kmsan_handle_dma(page, offset, size, dir);
@@ -190,7 +190,7 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 	    arch_dma_unmap_page_direct(dev, addr + size))
 		dma_direct_unmap_page(dev, addr, size, dir, attrs);
 	else if (use_dma_iommu(dev))
-		iommu_dma_unmap_page(dev, addr, size, dir, attrs);
+		iommu_dma_unmap_phys(dev, addr, size, dir, attrs);
 	else
 		ops->unmap_page(dev, addr, size, dir, attrs);
 	trace_dma_unmap_phys(dev, addr, size, dir, attrs);
diff --git a/kernel/dma/ops_helpers.c b/kernel/dma/ops_helpers.c
index 9afd569eadb9..6f9d604d9d40 100644
--- a/kernel/dma/ops_helpers.c
+++ b/kernel/dma/ops_helpers.c
@@ -72,8 +72,8 @@ struct page *dma_common_alloc_pages(struct device *dev, size_t size,
 		return NULL;
 
 	if (use_dma_iommu(dev))
-		*dma_handle = iommu_dma_map_page(dev, page, 0, size, dir,
-						 DMA_ATTR_SKIP_CPU_SYNC);
+		*dma_handle = iommu_dma_map_phys(dev, page_to_phys(page), size,
+						 dir, DMA_ATTR_SKIP_CPU_SYNC);
 	else
 		*dma_handle = ops->map_page(dev, page, 0, size, dir,
 					    DMA_ATTR_SKIP_CPU_SYNC);
@@ -92,7 +92,7 @@ void dma_common_free_pages(struct device *dev, size_t size, struct page *page,
 	const struct dma_map_ops *ops = get_dma_ops(dev);
 
 	if (use_dma_iommu(dev))
-		iommu_dma_unmap_page(dev, dma_handle, size, dir,
+		iommu_dma_unmap_phys(dev, dma_handle, size, dir,
 				     DMA_ATTR_SKIP_CPU_SYNC);
 	else if (ops->unmap_page)
 		ops->unmap_page(dev, dma_handle, size, dir,
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cd872c32c32bed2cc406ccdde9023b4db155f43c.1755153054.git.leon%40kernel.org.
