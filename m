Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBZHO57BAMGQE3FR2XUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 47B9DAE8443
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 15:19:37 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-313d6d671ffsf1625715a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 06:19:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750857573; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZU/d5zlGM5UzgGE22dZW51HAcbMKfNTBsyHSAG3TYXG4g2208do7x1yDPjdCXSOwS5
         w1BtCsIf+jNn2nd8uHc+OrNvv2To6k2upNhZXG7huKbk05RY6oniTY2XAuH8XphoYV4O
         nAy8WzaboT0rjpXCQkB3lxrLqO6NPHT4JLMOaXaUVuHyemI1TzNdoE2kZWZphYwhFhOL
         6b6QwXJwy0uifE7CyTvE28BYKMaKDJJiqvJsnWW0kI04ER0Gfnc4aIJMW0uOh0FG3BJP
         XBWYrwTaTaiEndQV5EFy8AYEHDOgRH/3oBTceEImGbewiyZF8QF0oakzszr0LJrt6J3X
         fhnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=AQzogI1yg8feYfPhw278EU8a+Cu/pl0ut3Dg1CZlFQ4=;
        fh=6uqk/mbrtXO0IzcqyYYoYiZZMbSs6W3fnDXUApIZI6Q=;
        b=hQvMoiO+Qn2TH6UKmvxiczwpoviJCv3HYEHXoqV38Czv8CUycp0d0EHYQUYNIK5RZz
         0aZNV750xkBvHZGsakZlXbmkHK1Qp5l16L9BgzQMmHekJVLyoN093CJFqt6feupGh/7Q
         c+FNK+Hgv2gP5FCPvODwE2Mfrd7DCeR/72OHYSEXayBGVaE/qtnRuqV83PvEn+dMTHLA
         rC5Y0gSWTwyi4ZztrbaXIYhIclnPRLGrojXFyb5wDX6FriibKo1XDz26tL51UCnFY1nb
         30I3zLxDrwaQes4HsdwwC57Jrc4BrrmFU4YRgqkGfHthA715uRNdEy/aRSnDFU1b0cPX
         vrSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NnBSLNRQ;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750857573; x=1751462373; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=AQzogI1yg8feYfPhw278EU8a+Cu/pl0ut3Dg1CZlFQ4=;
        b=Oycwxw6jh0iIuSfQAa1Q1Lu6TVasbYb0bnfU6kFT/JcXwkOYY4poeTm1Rj6csBcucl
         PTRk7ZlWGaZDWgtCmu4xbFEdfGMFInmA8nyYlVV97E6y8Rsp9Hv+DOiChV8FokZSpJTg
         FS5VvN3nFaZpkAcV7ozXiICUaS1gHEyaGjH0Bi0hReCwpwhAKu9RgIdd/WrTelBUmy70
         EVOYZpYhSEVe9twlIwOCU1IRetlB10sPsh0BgPr4K7VgmHuxmiW3qd2thachf3ned9//
         lkCsNt1DQ3WaJttAqc6ZFh0Yo1INbJaAS62lZy50SmZyD0H1WMzoZG5Pak9dMq+fZcFw
         Eofw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750857573; x=1751462373;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AQzogI1yg8feYfPhw278EU8a+Cu/pl0ut3Dg1CZlFQ4=;
        b=JltMiFum42/GTNFieiseFZpHumgN7/t1JMaU1t3phOesImFl/EbD/8v9030LGL9REk
         d/JG2PSbvMuP9PJAIf0ijxxrvDi7w1qmOQ7bddq1AJ76Z73pUyRDPZX/frPB/6EyRy+c
         Wjls4OEelfv/Do5jkhD4Dhac/vGRkzdNDjDnkMTINkrdbSGP1+G7ukRlMuQ6jhfpRv3+
         EU6vIA8HCrXgbeWS0BU1V7exLD8mUbioe3NcOHxX3+O3yt8MAdCX7qksN4c70Tf/fSMR
         /NNgqAKNkhLRLw1L0LnZSr2d5m4jmp8GAyaLlLfQ1Fn9P2nISSmgojS01aoHB1oMsFPV
         zwBQ==
X-Forwarded-Encrypted: i=2; AJvYcCUK1BS/NuVFqR8c1ETP/VTWuzLuS59CXvamH3k+es1gptXpjkutdFbADLtjxaxFH4Jyl3ws0w==@lfdr.de
X-Gm-Message-State: AOJu0YwffxYv9UiQewp9MiuuO/QKb6A3StJ6DI1+9Q2WCU51KUQiyoa1
	rCm9vwA1bCTk94/ZtdIaFiXqQMcHrzQp0O0hKJFhpwk8qSqwoFhQkfzq
X-Google-Smtp-Source: AGHT+IGtd75iwUR6sufw12khhX8Qm+ldkt8jxh0Gic6CWtt3v0Oj8NI4088RrxAbYNPQPCf8O9mbTQ==
X-Received: by 2002:a17:90b:2c85:b0:312:e6f1:c05d with SMTP id 98e67ed59e1d1-315f25e7388mr4928612a91.2.1750857572929;
        Wed, 25 Jun 2025 06:19:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcXHu8sBVes7hRf1yfZZ1K3+ff62jt/A3EQTvR1ujQvZw==
Received: by 2002:a17:90a:1542:b0:311:ba2f:7507 with SMTP id
 98e67ed59e1d1-3158e35a214ls5272092a91.1.-pod-prod-01-us; Wed, 25 Jun 2025
 06:19:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvqf1W2l5VS9E1sNtwLdflzOUsoPdDb+6YzRMcQsmM8NVcqBEbg0piEbWt9dwf4BA0TQf8HSHmm0s=@googlegroups.com
X-Received: by 2002:a17:90b:1cc3:b0:30a:4874:5397 with SMTP id 98e67ed59e1d1-315f261a2c8mr4601745a91.9.1750857571483;
        Wed, 25 Jun 2025 06:19:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750857571; cv=none;
        d=google.com; s=arc-20240605;
        b=JblAztWqnRegIsaINLTZf4xOqTEQG5kgYs9YnA+qEpIWkxiXYlWf9kqVeoHBZX8Vv0
         QUj6E7764z5wm26qsdou7gj5C9p8dU2SOaXGiUdknlrLGf65SJFJVFFduUa+5mDjzG56
         53q+zEoYkEthi/7QrMKX9p0zt2uS0lMPFG6LzNEeUlGDZN0KZIgWd4bfJzWy5Lg1d+2b
         Y67wZmSCCxUUpKONaC/hgyhseOfR4rYl+2qFBHEyWMShTD8/hj6uaXIjwRObMLGtDzSk
         1uO28qL+lhrCefysLYh7OJdLg1a38RyeXymhagPorOK/dRvP60aHKLDuo462hGSJ/IBS
         Gt3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Fuq/EXA4R2mOYUr8QDY0zcJTyX7n7zR8XDaMk9x/6cc=;
        fh=Ue3Mp6STgOoLoEGJ5Njvvyw4rTb/NHl4sWIWt9sNi3o=;
        b=VWcHl+0g8oZm4/6o4rOZR3ekirWSscqfV35uAUShryCJpMmtL8fMVmhX9Gw9ypDgK1
         PK7SIQ6yJEkD8ygjRGxGT8/e8sysEXec9KO3h32kevgkI/dFkxWEhoBtlhCVJnxr/Bnj
         SWzYBmy9+4IdQpa4GssI6jPo/t6lQqlEyC4PwCRb45Qz6eYH4aNMkecHqgX5K35ZRX0g
         ukrBHwlkaC48woENCiCIWDL+SG4t2StMV8XB9FB00/l7EUTd39yG5stMjSvR/TBUjoPY
         Q7aPL91h/B7jbT/sfvx9GfkHV34wL9k+ghTM9PeOeI/HLFy7UxqPqp6PF59HErO8EbBM
         +h3g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NnBSLNRQ;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-315f13d7541si98812a91.1.2025.06.25.06.19.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 06:19:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 28E3F5C5A14;
	Wed, 25 Jun 2025 13:17:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9D15CC4CEF0;
	Wed, 25 Jun 2025 13:19:28 +0000 (UTC)
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leonro@nvidia.com>,
	Christoph Hellwig <hch@lst.de>,
	Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Robin Murphy <robin.murphy@arm.com>,
	Joerg Roedel <joro@8bytes.org>,
	Will Deacon <will@kernel.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	=?UTF-8?q?Eugenio=20P=C3=A9rez?= <eperezma@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?UTF-8?q?J=C3=A9r=C3=B4me=20Glisse?= <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	iommu@lists.linux.dev,
	virtualization@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: [PATCH 3/8] iommu/dma: rename iommu_dma_*map_page to iommu_dma_*map_phys
Date: Wed, 25 Jun 2025 16:19:00 +0300
Message-ID: <ea620f9bc9244e00eb6a9102d435e5cf5d26f436.1750854543.git.leon@kernel.org>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1750854543.git.leon@kernel.org>
References: <cover.1750854543.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NnBSLNRQ;       spf=pass
 (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted
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
index ea2ef53bd4fe..cd4bc22efa96 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1190,11 +1190,9 @@ static inline size_t iova_unaligned(struct iova_domain *iovad, phys_addr_t phys,
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
@@ -1222,7 +1220,7 @@ dma_addr_t iommu_dma_map_page(struct device *dev, struct page *page,
 	return iova;
 }
 
-void iommu_dma_unmap_page(struct device *dev, dma_addr_t dma_handle,
+void iommu_dma_unmap_phys(struct device *dev, dma_addr_t dma_handle,
 		size_t size, enum dma_data_direction dir, unsigned long attrs)
 {
 	struct iommu_domain *domain = iommu_get_dma_domain(dev);
@@ -1341,7 +1339,7 @@ static void iommu_dma_unmap_sg_swiotlb(struct device *dev, struct scatterlist *s
 	int i;
 
 	for_each_sg(sg, s, nents, i)
-		iommu_dma_unmap_page(dev, sg_dma_address(s),
+		iommu_dma_unmap_phys(dev, sg_dma_address(s),
 				sg_dma_len(s), dir, attrs);
 }
 
@@ -1354,8 +1352,8 @@ static int iommu_dma_map_sg_swiotlb(struct device *dev, struct scatterlist *sg,
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
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ea620f9bc9244e00eb6a9102d435e5cf5d26f436.1750854543.git.leon%40kernel.org.
