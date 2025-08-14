Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBWWF7DCAMGQEWCJS7VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 27311B26E09
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:54:37 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-76e2e8afd68sf1017497b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:54:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194075; cv=pass;
        d=google.com; s=arc-20240605;
        b=F1fE+KVaIMNDf+EHLIH8CfeNNMnbXrW1/YMhCUyen6y8ktFb8H4By7DHZ6xTVq493t
         ax/pZD5gMwsPpL5UaR5l9hGo/E7FI61DI0gkYSQKAXqwdeehiGLxZ5qv+0f5iMlioWHY
         VF05jctl9sB9lVWCQIofgW02ii5JCvjUxaMgmk760ikb6a12xcCtFp/XE04LubYnmld6
         rGdeuE33REUGUqGYh/9+7hulnD2SmCsLwdN2mTuQEl03UDUrnp6NYAG0YKrLtHilnm8I
         bEXXG2Eyyph0vGBf8HAh7r9+W5BBoW18RkkrpYr7/7chXFn120eakJUjiAF+RrE0Jtb7
         tP7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=tBVo7D+8c8ci7ek0k0impm+R4DbAuO63Z7K1XYwxl+Y=;
        fh=yyTY8IndDvQt8WRw4D/BDfRyeS1KP4tQedDmSCqkUGk=;
        b=MJgkVr1u1/wbGcWd9OOacwMHS7QLH7VlEqa2eGbqkEp02tkG3vxt4nod/k0eEwYSYy
         XAm3qO7Q6cMLcbE1hkqNrqP4DoLD0gWcdZCqobCn7V4/vZdwE3Edbq0atrTuQBuEXjpX
         a0L5vqL8Rki726SWFG2xFryUhPUqIzI29RYAf/TOcNbosjCEMLGY0y/aeJWQUubUMdOJ
         UQTE0pVGXuWFO2blK7SUbTFxV4cYnhYoIDCDonhSTA7qdEd64IHO0CiwKWhVmXG/RF0S
         ik0lEB0EFsigiXMFJ242OaEtBNiBP8PbxxAh098nwheLR5MOqS6Vl5IC0QstXp0VYV5J
         Mvsg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GiDx2YUA;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194075; x=1755798875; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tBVo7D+8c8ci7ek0k0impm+R4DbAuO63Z7K1XYwxl+Y=;
        b=qcsc7GJZKoGioWbrApt21BChUaLYxn9mCDjfaCYdavZ5T01JZj6kMmcarPCez51B6W
         IYKs/mdITv0YS96aTsbkx5DVsvuEzsumzaI/va69KwXrwgJJE+q1nwGT91GO9TTxvLjv
         NTas12SF2qoebCpbYGkfGxe6K0qMWGvCQXaz4OnfEpLkDLP+RtjJ7EyP6oUSlJBxCQ00
         ZRCew52yuRE9UDO6t5c/1xVEM1zAqfmoNuTjhBvYn/STfW02DtcLDnOHL4l7UD/IYAzv
         uJJmdUVfM+nWf2mNmXlazEVZSmWYganGMp2S40Fx/Pe+XK33D4bR43k6DL9RcU8THkbl
         sHGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194075; x=1755798875;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tBVo7D+8c8ci7ek0k0impm+R4DbAuO63Z7K1XYwxl+Y=;
        b=daWPG8lz5LtKJ5Yxtn7pOUbURtXbKyUGDj5v06BywL7FcxbDITYFVAPM/ySr7iX1sH
         OGVlqYsuuasopwU/GMCPZdlrK1fMjmr8imnYOa14WV0iu1EzGZD4f2jOKtgsAX7J4VKo
         iOi3lMbPlMRTOKrA/VKNYPjiJBQgJ7tJqiFiMU9JIuun97j2rlUAKInontR7i62cVcM3
         yb5sWnhN2deXpUvA4VbkMtj/S19BudE9DBo1oFeQfsQc79BmtmII4QKEBg6r0bGZq+Ds
         heSI1FPiKxtCv/1pkAZVPr3z/O0PGjZ4DOH47s5RqWHXMq5KVh03t8JukQLQzz29MfOV
         GZpQ==
X-Forwarded-Encrypted: i=2; AJvYcCViC5JxLuvSato1ADfEO/qVX+dey4YoUJb/P0wxIWyvG2F8Lc1zyZoDu7cxqrk5U/fX4mPMCg==@lfdr.de
X-Gm-Message-State: AOJu0Yw1pxqNckIB689j8Oe+t4oJFi5fVjIg/Q7NU2bZ9Ow/pDz4bytq
	F+lLVZ3qAvbwyT4AWPyNMddbp6ouHt4hLwuwinXmUyrpZXI+i3VG/7QW
X-Google-Smtp-Source: AGHT+IGaM5lM4vetGpdmW+pqv3b8cGiYTRyCAnMbsyURpr3LtuPf20fpYB4/b7HVDW5IhqUlozK8bg==
X-Received: by 2002:a05:6a00:3c84:b0:758:b81:603a with SMTP id d2e1a72fcca58-76e2fbe2a09mr5539529b3a.2.1755194075268;
        Thu, 14 Aug 2025 10:54:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcb8ShEvwyJotrQYvcdS4a1qujjaLmcYRSK+VvSAp+tvQ==
Received: by 2002:a05:6a00:4d16:b0:730:940f:4fa5 with SMTP id
 d2e1a72fcca58-76e2e538969ls1033037b3a.1.-pod-prod-04-us; Thu, 14 Aug 2025
 10:54:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVwYlnQhT9VuTkZ6mYb1UGXqD1wyzZ3fpe+YmBPVWWFMD8viuVtsU8QKmOcDr9gTyCPmcDnqzKWgC0=@googlegroups.com
X-Received: by 2002:a05:6a00:cc7:b0:748:33f3:8da3 with SMTP id d2e1a72fcca58-76e2fd90494mr6416993b3a.19.1755194073205;
        Thu, 14 Aug 2025 10:54:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194073; cv=none;
        d=google.com; s=arc-20240605;
        b=ZDENTnXnzure/83dSNWwP8Xq2QK/G0jArTGqQSr754so02gCrcE1Vj0BlWgal+RC28
         mhG6Nrj97iLenTRLQ6WZr3w3q40Rrkpl+KYZG7k+GlT44eOZGsEck2aZ33FiLfVDTgdc
         G22sjEMFjUEUyHOyy0+19vIVnSInaN5WV1VNZbfeoCPLqlPPZ3cuzab0iFEIRTnCihU4
         r7Yodgz/K3LrTiC45MtN74AbWcWwiZ8IfgarIBPmFWJxDCkf51/UCzadUvEiRBP7KR8V
         6HFBtis6Q069W51HWgGqiuGfFzcgRqpkplno+aL+XaSU2QhbmSyFwD2BgFEHBzWdhiUz
         Bxww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kCJU29SWd1OR3k6ZUoBci43zBS+gLO8fdMAUUcFIoOc=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=hn93LvvueExHADKejpRAPjaR0MkNCSK7hyye3hnYI5X5OCQ72amlHbk3vBWSSDp9we
         6I8S1q0zZKG2s36KxBA+OPFRxWG1A+jB8f/guwYYy0SfmrzPYB4L9v8A+z2RaJeW2xSv
         TpzIi9DVJRggqbLD78SGcj2DPZVZin/tvcUN75nhBNzXYp/e/VV8hkfko5lJR4ppEeJ0
         qOlkT87ArxaJBwmNijBzPjl8jL3JF1x0PdnljOJIsds4/jAmojEWnVDn0WqLLkEARBoV
         e4kdXN/HaQl0PtgclvZIBVD+jMWgjj3Q/qhp6xHAkSm1xcj2/Ivwgz7xae1Sg9prCjkw
         vxoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GiDx2YUA;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76c2d61d1e9si300117b3a.0.2025.08.14.10.54.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:54:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 51186601D8;
	Thu, 14 Aug 2025 17:54:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6E4C7C4CEF4;
	Thu, 14 Aug 2025 17:54:31 +0000 (UTC)
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
Subject: [PATCH v3 05/16] iommu/dma: rename iommu_dma_*map_page to iommu_dma_*map_phys
Date: Thu, 14 Aug 2025 20:53:56 +0300
Message-ID: <66e7cc6854e4e40278b598b38e0c4d49d7fcec91.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GiDx2YUA;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/66e7cc6854e4e40278b598b38e0c4d49d7fcec91.1755193625.git.leon%40kernel.org.
