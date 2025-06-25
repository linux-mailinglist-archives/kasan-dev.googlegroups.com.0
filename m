Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB5PO57BAMGQECXJDJBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id A95A9AE844B
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 15:19:53 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-31220ecc586sf1500215a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 06:19:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750857589; cv=pass;
        d=google.com; s=arc-20240605;
        b=QjuG80HRw1dwb/exumrmG+vcXl0XVRUDUJPL4CgzUnBj14jXRmgLYzcaafcNOIxouQ
         1scj3pKUKS8huY3wL6FdZjGUczpHsvCjy75xMFW7tkdhIrAFYsJS1+naeoQts9ciQ2ao
         A0fDsnJoYP886p9tlIi8i1pQhX0oXZqWY982Dv5nV/paSALURxYG10AxZtgqIyOFvkf+
         bII5ukmDLYIkY1tYT6MuOQLSa+0fYpUUuCwIEldD8KOV21Lqy/sCTHGa4idlmvKJGTr4
         qNDUpVhf1BTuZWD3+TGWc8TmSZrE0aY7xa9UpeMUFP+Qro+lfk91xfvxPKys+Rnov5Ks
         zH1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=MaDMd659mai1uYaSGqKHy1GbLMi/665yEvx1r9WSE4Q=;
        fh=4kBVheEwGzD6U8xX5ZklgcDi2o1FRRBCYt/6CaVX5zo=;
        b=eZgkNkmEEbL5baUar6bPg8wBq/MZXADvTGxrmI178+hRZT8742SVn9zGF1qia3IRBF
         UIos0yRDiHF9x5XPxkyqk26cSjb9vSTzkTe3RJusyMruaI5XE91MiMc1PvybUdxcQxgw
         Lam6LovtxK4Ll/vdxDQyxxNABHwLoWljpUxNe+cq2DSVC2MLOSl5kSkBgocQI83XwkIY
         VZvW2LAGe010mMLPztPVJNdY+it0HHlIFhG4JkpXyU+7cemsDh7WJonT9kfFS1oXHlb7
         W2kLDpULLP7VfAMDNtE1ykeC8UCcPrvgVmjhCCbY2fhRiLF7mCT0bLfcWwVpzenglz5A
         TYfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cnTVV8FS;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750857589; x=1751462389; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MaDMd659mai1uYaSGqKHy1GbLMi/665yEvx1r9WSE4Q=;
        b=tR+NF29xrf00DS//pUR5DaZZRrxZB+9KJb5pAk16D0TuV1wwHDOAOygiR28M0jIL3B
         +fe2/yDc4PbTs22wrbl3qgXd+8Dhd8qsbbrgyPKPvn6J6RWKb1ExAGEWsVsPERkIDDBW
         a0i/8O8VDx9GXsySwIChT/OdliYDGO8rb62w5NzpTUCaReriav7+75h8QoZCcKH2a3Mn
         0WXqTc6vaaQT+6wZ38HjaOUN1usuU29bSuhEoOdWnQ+I2AxIns4QoebfsXzuF3GgTSxk
         EfXa1UbLUGzUzvXKZ8yOyZjoLlGfhkRiqfTGnRU2kuoyHUZA5ff+nf2JAvj8uEq0dIkW
         7T6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750857589; x=1751462389;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MaDMd659mai1uYaSGqKHy1GbLMi/665yEvx1r9WSE4Q=;
        b=xPTXHrgzgKanau40Hjl2MvuCpqq8e0Nl1lpJQVilreBHUbshZcp1yEGWI0ZhCDD1M0
         rfVaR21aE12495Hgfz4FEgZVxzvtt62I4Pb3I1HRqihBu3vxrANaEMpHJ8lKTgzXued/
         a1rjXxRC2cMKkUBOkBNSOazme3u2X7SYIa3zAhdnBS97gc8Y8Ezc9nxe7swTgULB60nL
         ukMXa+3Ht9CVN858+W+p9sBiJt0HSjll8mbyYb4xXSm1HJjIyTifNyr3Q7h8rO+oldSQ
         g8/Lp1MPvqvPF5nLXglZcTuASjHJ5Wi38ciUk2WqxT1dhWMT6+vvHJjVfiYaGxXlDfkP
         2BDg==
X-Forwarded-Encrypted: i=2; AJvYcCVr0bz8UbQ0BYGFlAUyNM/pWxgqH50/Teawy2lxyTkqCX3U/xf5Gssc7VjLX2DCKWi66LpWRg==@lfdr.de
X-Gm-Message-State: AOJu0Ywlo20qutIUm7Ocjk5tvDm+K13BoP4wKrN6eXDmo1w8TW53jbYT
	5VZYee/N+UjDeYWJ3jtucq4L4/TozGpgTU99hWlv4t4+gSzBZLQr32A2
X-Google-Smtp-Source: AGHT+IHm1/LqWuiYu3Yu1jcQkPKbH4GuA2kVxqUggr9TqAH7VFQ7Juqk2EkgqWzORtMP+9cBtd7StQ==
X-Received: by 2002:a17:90b:5303:b0:311:c970:c9bc with SMTP id 98e67ed59e1d1-315f26a24a6mr4497505a91.30.1750857589385;
        Wed, 25 Jun 2025 06:19:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeHbK3wnPpZHENRGDW/BZspzHFduvXVXjRlvYWQ4y8QdA==
Received: by 2002:a17:90a:c2c6:b0:311:b5ad:42d6 with SMTP id
 98e67ed59e1d1-3158df36d6bls5013794a91.0.-pod-prod-02-us; Wed, 25 Jun 2025
 06:19:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCQ5MHO3NqaRexfpls9mchDuqNsBOEOTcEHqyyDWYD0C259sSUdfwSib1JFvmbiUEDFmwjR/K7vnU=@googlegroups.com
X-Received: by 2002:a17:90b:574e:b0:312:39c1:c9cf with SMTP id 98e67ed59e1d1-315f25dc5bamr4655800a91.7.1750857587853;
        Wed, 25 Jun 2025 06:19:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750857587; cv=none;
        d=google.com; s=arc-20240605;
        b=Zj29ZueDBHkKiNQU8YzhsFP0J1vQHXWZfqH0uKWMW2EFhDI8mq+uhpJxSLUX4RBiDO
         78GNyVwcCi1Kct3VLvMjlvkMA31ERHNNugUvlpKV5VVjf40W7FOiVhdXhOpGb13/gJ6X
         sOgsomzUMElq9eu7IG7uwRTLjmAK6OPlR8Jo8VsukAJU2duNfq7Mw4CoGFRxRZ2fAKj1
         DqxchnGd/sWCqWl/OUsKpR8bLioO7EpfOMtxzAOCSL1TbjUBbYgusESz5GiwPFhaPZGA
         VaLQJbOC7WRGdkX4uxxm3+Nu7rgHdEvgxgday5eFQeojMNBeLdnOP2wyTxG2FeqPN5LK
         2LNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BJ1Wn2SVnMm/REOeG/rD6ahVGk6b5fUJAT/ifYboang=;
        fh=Ue3Mp6STgOoLoEGJ5Njvvyw4rTb/NHl4sWIWt9sNi3o=;
        b=EbkILvfnLlme4z0c2uvWc//swoSTFIgYbZARCyqH20ZpeAyZ0LsssRVKks6fOveKRv
         Y/AnYuh+sEjTXkzD6WnENrj8c4aFXV2QS8ysiZu078HmuuW2lxYIPsWxjMfyPdqBzD2W
         Pc2r81hS1xJQCd6Preee8EP3h67INtTzr3mNnRRunx1ZMede2UcwmLpnaAyk1b+ysdfL
         T7dx79havmDv9KoV6KeUJF2FEtkXEECFknNqYoKsclsWZvQETWuAoHfahSIsE0oIFE/R
         ulgeOloxqJh7puFl3OWdynYME6vU+8lcfIBFjp5n3LeAbKhJlKUW/7qjb9pn8ilP0zBK
         T61g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cnTVV8FS;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-315f51e3c8bsi99139a91.0.2025.06.25.06.19.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 06:19:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id E7A366135E;
	Wed, 25 Jun 2025 13:19:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 592E4C4CEEE;
	Wed, 25 Jun 2025 13:19:45 +0000 (UTC)
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
Subject: [PATCH 4/8] dma-mapping: convert dma_direct_*map_page to be phys_addr_t based
Date: Wed, 25 Jun 2025 16:19:01 +0300
Message-ID: <1165abafc7d4bd2eed2cc89480b68111fe6fd13d.1750854543.git.leon@kernel.org>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1750854543.git.leon@kernel.org>
References: <cover.1750854543.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cnTVV8FS;       spf=pass
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

Convert the DMA direct mapping functions to accept physical addresses
directly instead of page+offset parameters. The functions were already
operating on physical addresses internally, so this change eliminates
the redundant page-to-physical conversion at the API boundary.

The functions dma_direct_map_page() and dma_direct_unmap_page() are
renamed to dma_direct_map_phys() and dma_direct_unmap_phys() respectively,
with their calling convention changed from (struct page *page,
unsigned long offset) to (phys_addr_t phys).

Architecture-specific functions arch_dma_map_page_direct() and
arch_dma_unmap_page_direct() are similarly renamed to
arch_dma_map_phys_direct() and arch_dma_unmap_phys_direct().

The is_pci_p2pdma_page() checks are replaced with pfn_valid() checks
using PHYS_PFN(phys). This provides more accurate validation for non-page
backed memory regions without need to have "faked" struct page.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 arch/powerpc/kernel/dma-iommu.c |  4 ++--
 include/linux/dma-map-ops.h     |  8 ++++----
 kernel/dma/direct.c             |  6 +++---
 kernel/dma/direct.h             | 13 ++++++-------
 kernel/dma/mapping.c            |  8 ++++----
 5 files changed, 19 insertions(+), 20 deletions(-)

diff --git a/arch/powerpc/kernel/dma-iommu.c b/arch/powerpc/kernel/dma-iommu.c
index 4d64a5db50f3..0359ab72cd3b 100644
--- a/arch/powerpc/kernel/dma-iommu.c
+++ b/arch/powerpc/kernel/dma-iommu.c
@@ -14,7 +14,7 @@
 #define can_map_direct(dev, addr) \
 	((dev)->bus_dma_limit >= phys_to_dma((dev), (addr)))
 
-bool arch_dma_map_page_direct(struct device *dev, phys_addr_t addr)
+bool arch_dma_map_phys_direct(struct device *dev, phys_addr_t addr)
 {
 	if (likely(!dev->bus_dma_limit))
 		return false;
@@ -24,7 +24,7 @@ bool arch_dma_map_page_direct(struct device *dev, phys_addr_t addr)
 
 #define is_direct_handle(dev, h) ((h) >= (dev)->archdata.dma_offset)
 
-bool arch_dma_unmap_page_direct(struct device *dev, dma_addr_t dma_handle)
+bool arch_dma_unmap_phys_direct(struct device *dev, dma_addr_t dma_handle)
 {
 	if (likely(!dev->bus_dma_limit))
 		return false;
diff --git a/include/linux/dma-map-ops.h b/include/linux/dma-map-ops.h
index f48e5fb88bd5..71f5b3025415 100644
--- a/include/linux/dma-map-ops.h
+++ b/include/linux/dma-map-ops.h
@@ -392,15 +392,15 @@ void *arch_dma_set_uncached(void *addr, size_t size);
 void arch_dma_clear_uncached(void *addr, size_t size);
 
 #ifdef CONFIG_ARCH_HAS_DMA_MAP_DIRECT
-bool arch_dma_map_page_direct(struct device *dev, phys_addr_t addr);
-bool arch_dma_unmap_page_direct(struct device *dev, dma_addr_t dma_handle);
+bool arch_dma_map_phys_direct(struct device *dev, phys_addr_t addr);
+bool arch_dma_unmap_phys_direct(struct device *dev, dma_addr_t dma_handle);
 bool arch_dma_map_sg_direct(struct device *dev, struct scatterlist *sg,
 		int nents);
 bool arch_dma_unmap_sg_direct(struct device *dev, struct scatterlist *sg,
 		int nents);
 #else
-#define arch_dma_map_page_direct(d, a)		(false)
-#define arch_dma_unmap_page_direct(d, a)	(false)
+#define arch_dma_map_phys_direct(d, a)		(false)
+#define arch_dma_unmap_phys_direct(d, a)	(false)
 #define arch_dma_map_sg_direct(d, s, n)		(false)
 #define arch_dma_unmap_sg_direct(d, s, n)	(false)
 #endif
diff --git a/kernel/dma/direct.c b/kernel/dma/direct.c
index 24c359d9c879..fa75e3070073 100644
--- a/kernel/dma/direct.c
+++ b/kernel/dma/direct.c
@@ -453,7 +453,7 @@ void dma_direct_unmap_sg(struct device *dev, struct scatterlist *sgl,
 		if (sg_dma_is_bus_address(sg))
 			sg_dma_unmark_bus_address(sg);
 		else
-			dma_direct_unmap_page(dev, sg->dma_address,
+			dma_direct_unmap_phys(dev, sg->dma_address,
 					      sg_dma_len(sg), dir, attrs);
 	}
 }
@@ -476,8 +476,8 @@ int dma_direct_map_sg(struct device *dev, struct scatterlist *sgl, int nents,
 			 */
 			break;
 		case PCI_P2PDMA_MAP_NONE:
-			sg->dma_address = dma_direct_map_page(dev, sg_page(sg),
-					sg->offset, sg->length, dir, attrs);
+			sg->dma_address = dma_direct_map_phys(dev, sg_phys(sg),
+					sg->length, dir, attrs);
 			if (sg->dma_address == DMA_MAPPING_ERROR) {
 				ret = -EIO;
 				goto out_unmap;
diff --git a/kernel/dma/direct.h b/kernel/dma/direct.h
index d2c0b7e632fc..10c1ba73c482 100644
--- a/kernel/dma/direct.h
+++ b/kernel/dma/direct.h
@@ -80,22 +80,21 @@ static inline void dma_direct_sync_single_for_cpu(struct device *dev,
 		arch_dma_mark_clean(paddr, size);
 }
 
-static inline dma_addr_t dma_direct_map_page(struct device *dev,
-		struct page *page, unsigned long offset, size_t size,
-		enum dma_data_direction dir, unsigned long attrs)
+static inline dma_addr_t dma_direct_map_phys(struct device *dev,
+		phys_addr_t phys, size_t size, enum dma_data_direction dir,
+		unsigned long attrs)
 {
-	phys_addr_t phys = page_to_phys(page) + offset;
 	dma_addr_t dma_addr = phys_to_dma(dev, phys);
 
 	if (is_swiotlb_force_bounce(dev)) {
-		if (is_pci_p2pdma_page(page))
+		if (!pfn_valid(PHYS_PFN(phys)))
 			return DMA_MAPPING_ERROR;
 		return swiotlb_map(dev, phys, size, dir, attrs);
 	}
 
 	if (unlikely(!dma_capable(dev, dma_addr, size, true)) ||
 	    dma_kmalloc_needs_bounce(dev, size, dir)) {
-		if (is_pci_p2pdma_page(page))
+		if (!pfn_valid(PHYS_PFN(phys)))
 			return DMA_MAPPING_ERROR;
 		if (is_swiotlb_active(dev))
 			return swiotlb_map(dev, phys, size, dir, attrs);
@@ -111,7 +110,7 @@ static inline dma_addr_t dma_direct_map_page(struct device *dev,
 	return dma_addr;
 }
 
-static inline void dma_direct_unmap_page(struct device *dev, dma_addr_t addr,
+static inline void dma_direct_unmap_phys(struct device *dev, dma_addr_t addr,
 		size_t size, enum dma_data_direction dir, unsigned long attrs)
 {
 	phys_addr_t phys = dma_to_phys(dev, addr);
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 58482536db9b..80481a873340 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -166,8 +166,8 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		return DMA_MAPPING_ERROR;
 
 	if (dma_map_direct(dev, ops) ||
-	    arch_dma_map_page_direct(dev, phys + size))
-		addr = dma_direct_map_page(dev, page, offset, size, dir, attrs);
+	    arch_dma_map_phys_direct(dev, phys + size))
+		addr = dma_direct_map_phys(dev, phys, size, dir, attrs);
 	else if (use_dma_iommu(dev))
 		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
 	else
@@ -187,8 +187,8 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 
 	BUG_ON(!valid_dma_direction(dir));
 	if (dma_map_direct(dev, ops) ||
-	    arch_dma_unmap_page_direct(dev, addr + size))
-		dma_direct_unmap_page(dev, addr, size, dir, attrs);
+	    arch_dma_unmap_phys_direct(dev, addr + size))
+		dma_direct_unmap_phys(dev, addr, size, dir, attrs);
 	else if (use_dma_iommu(dev))
 		iommu_dma_unmap_phys(dev, addr, size, dir, attrs);
 	else
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1165abafc7d4bd2eed2cc89480b68111fe6fd13d.1750854543.git.leon%40kernel.org.
