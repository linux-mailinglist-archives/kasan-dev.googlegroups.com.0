Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB2PO57BAMGQEFWESGBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 60FC9AE8445
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 15:19:41 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-747cebffd4esf4995873b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 06:19:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750857577; cv=pass;
        d=google.com; s=arc-20240605;
        b=XmrOnZ2Z0XrtBnCztckBY5kq0pSrTWwbs5M1lmndZ6ncZt2m3z/yO54agIZ4C6vkQo
         DBRD9Jc7BCCp+uFXUWDk33QLai+Ef78ZFHaoVgYBEs7/etqcbtA8/aIr2BEnCxHN0TF+
         cd4sKN00dac5afkr3OqYqcnAx+Kdfays2XHnh4474i0+pmXT/01Ri+1wgmHde1TTCCDw
         EzASPRnOH0k8EBST689x1epPqhlzULAayAmxj2IO8t9Evl7aX4IWty5lQdRKAO7T4TdR
         j+qy1rgZZfEDup2QT5a5rDRGtcJUe/gDp3DSvYGnsj9Y9tUm679H0c7NIivDelnFA4t/
         kTfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=SG/EcUcwOQAD6cv/Y+z5/v/5Y1QPtTR1yc+BXIaea6M=;
        fh=QLpFmSFEpeMgrKuwFCx6jZGA2t9Ht9Cbw/+4GOSCeBE=;
        b=D/PBbr6mnaZdg/7cuu/gFh1R4RR4JnRV22u60g8Q9HL+jQ52RAIQqTFRMRF0msJJez
         5J97kXr1kMcxZw8eOkbQ1iHivMuD7oHJHqsZHbZspLcfJj5d53jtnhAYEBA1ezOlSemT
         4hEVTc15J/Fst+QXcLnn7llTAfv4VABwAieuwZG5DWDVdMDdyK/qX9PgxDakq1gD1e4x
         Ve6S7wYi+HurMgELFlRtB7ajwE43hFEmn/0+IHv4Y6YsIkvyF3x9/ZHI2K9nC6eRO5Hw
         pmY6vKkk3wAYoPLaml4mhcZm1YkOVXGVPy46FftRqrCOEQAE+xmgzdjemfLbZxnCN4Dg
         DonQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DKvWYDHn;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750857577; x=1751462377; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SG/EcUcwOQAD6cv/Y+z5/v/5Y1QPtTR1yc+BXIaea6M=;
        b=LQXD5eFFhPg7sog7B6zMyFZyUuVQsqoiwckxkFgu/TLINEkhEYGNcYdaOgVvN+TDsq
         K9euaRyb3Gm0Eb7+tsE9rt3o2FoH4Qr/CYflvlQ5MmjHEtBlCRF6rOfg3ar1X3+9WWQR
         8TH0V7+jqOkuE2sd/7iXT43ADXWG8jZ7Fh4ljP3l6xQRa6d12ZZPkegZYPwSE+xLZ00D
         nHCPdBgnlKUYrghf/8QwLIFA8NrZ2Fd20Cpjt1XYAdxiEhnGRtaJEnxaPahe9uKDtdm/
         jCncHNpq6kq96NfN6/CjZeRcb8Oo+jQ213yTjovTLPBVQ4grsM8dO1aL5L1MIFPUh4hR
         QJnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750857577; x=1751462377;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SG/EcUcwOQAD6cv/Y+z5/v/5Y1QPtTR1yc+BXIaea6M=;
        b=C7SsNdyvXIeuP1N8ZbfkZNTPo34Q2ztfhKpUc1wTvOFx9dQF0WLxBVi/D8gdb1Vb5D
         cgqPvUiQeVC+Hrk2XKgDPwI8cBU42Plel5JEu7qAKuDv8gwFnUgHVcDtp9FplItmoHvA
         NVRGVX6rQIrMRIL6HxAfalUbpkRhjxNW+lIbbNY3PvJT8OEY6VJSgfixWBT9wtBg9KhL
         WOscU/En3oPK/Kin9JmiSyQvu98GAO8z2p/aZ8w5dfQFiEeIB+LftlP5NqdtwgQSJXeW
         H6AeMRn0vycpxOn+aah1LgMzoz2tFTNinKueXnP9VWMDIl4HOQi1RL332bi28WnOoWFn
         uJhQ==
X-Forwarded-Encrypted: i=2; AJvYcCUMwxY6FRXIFpzgzvhVv1cOuOZjOjv8x7l2AWdDF2dyxE6BxkFxoEx/U5jAOar3rS8FO9smfQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx2Xy+FWk51igHisVW/fkH9GrUauIgov7XtDGq25UFMTuJGl9uO
	rOhAaNgXQ778mM6dIqJJcsQA4NHEyGMPtqQqBV+4YDfjU/aVFf0CVhnO
X-Google-Smtp-Source: AGHT+IFJq6Ea28aRMBozZivvF4POfZgLipWyhA2+VhUiS6CpGpQxOE3QHmh5x9RNCa/j7tqLhnxQwg==
X-Received: by 2002:a05:6a00:228d:b0:740:aa31:fe66 with SMTP id d2e1a72fcca58-74ad4408651mr5064362b3a.4.1750857577403;
        Wed, 25 Jun 2025 06:19:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc1JP8q3srg5PIeQhB+7N4xM/E/I95m0CuyvezP13EtwQ==
Received: by 2002:a05:6a00:1898:b0:736:a937:a0d8 with SMTP id
 d2e1a72fcca58-748f9121e4els5647896b3a.1.-pod-prod-07-us; Wed, 25 Jun 2025
 06:19:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWMTL61oUtU28KeK93YTM8kHowj6EYFaPl1hME76Mr4VuB31QeieZFQ4TCLiFkNbTt+aaM0HNL2lP8=@googlegroups.com
X-Received: by 2002:a05:6a20:9c8b:b0:21f:d0f6:13ba with SMTP id adf61e73a8af0-2207f1e5a5dmr5072982637.1.1750857575523;
        Wed, 25 Jun 2025 06:19:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750857575; cv=none;
        d=google.com; s=arc-20240605;
        b=PUdv/C8NBnf0ze93Ocx45wf76kXRYKnchLrVWcDOvkhBs+XrHREKoxPAEw60I+k7pF
         e7OND/rW2CTwW1/CjKWCDBuTVv4HDeMat2xnXXTckA3oMheucsnd4QAlF5SOGVBKt6Bq
         b+CjZy8SFUKNuUKCvnH8U2yCrvMp487nsaKrO4CnwDEo5bSpCYkIAlvAnFSizHlWz6bn
         S78QBTSGORA4XpGzxTcS5zL7GhmhnXpA6yuuncZgZAZuJHhUuVdff763JR2bCdm0NN84
         F4IwdDEhRvTd65TK7g1h1uyP5OC/kXavF/WDjoPieLJUZa5mPrurjlRJK2ph6yBj1178
         bNgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bgxMrc8fF7Z5NJiku3nKrAQz6RTWRZrSyMf5Xj8pQMs=;
        fh=Ue3Mp6STgOoLoEGJ5Njvvyw4rTb/NHl4sWIWt9sNi3o=;
        b=h/pmMn+hUpVMNV5KtRUP5tDs20rlPQrtGSr0RgqTS/labN+K1s08rOLHE/4/WIMWDC
         08HXwV9O1yolRVGungvZYuPTWvqheLLz3crBSOZTX2peJ0GZKLePQ3AxjvoLN/MbQJAE
         ryN3ofmHxqnH4QsnGBHtQumlK0AOaAFUsk+RGKSBh0T+/gQgfE3o9EFQjO34Ovbxgg8z
         X/uaNdHwL5MCpfZy8tDfmH9CXGr7UDBSBmQnlSOAYPPkuLjG602zsmk8ZsRleemRlclJ
         D0LfDGUDv6huYDPr0+r8CyigDlfA9HGLnK8MdZxNv+ypQxqiiWAdEw4UgLuMaXYswS6Y
         jG9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DKvWYDHn;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b31f2755952si708293a12.3.2025.06.25.06.19.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 06:19:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 91187A52616;
	Wed, 25 Jun 2025 13:19:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 962DEC4CEF4;
	Wed, 25 Jun 2025 13:19:33 +0000 (UTC)
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
Subject: [PATCH 5/8] kmsan: convert kmsan_handle_dma to use physical addresses
Date: Wed, 25 Jun 2025 16:19:02 +0300
Message-ID: <cabe5b75fe1201baa6ecd209546c1f0913fc02ef.1750854543.git.leon@kernel.org>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1750854543.git.leon@kernel.org>
References: <cover.1750854543.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DKvWYDHn;       spf=pass
 (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

Convert the KMSAN DMA handling function from page-based to physical
address-based interface.

The refactoring renames kmsan_handle_dma() parameters from accepting
(struct page *page, size_t offset, size_t size) to (phys_addr_t phys,
size_t size). A PFN_VALID check is added to prevent KMSAN operations
on non-page memory, preventing from non struct page backed address,

As part of this change, support for highmem addresses is implemented
using kmap_local_page() to handle both lowmem and highmem regions
properly. All callers throughout the codebase are updated to use the
new phys_addr_t based interface.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/virtio/virtio_ring.c |  4 ++--
 include/linux/kmsan.h        | 12 +++++++-----
 kernel/dma/mapping.c         |  2 +-
 mm/kmsan/hooks.c             | 36 +++++++++++++++++++++++++++++-------
 tools/virtio/linux/kmsan.h   |  2 +-
 5 files changed, 40 insertions(+), 16 deletions(-)

diff --git a/drivers/virtio/virtio_ring.c b/drivers/virtio/virtio_ring.c
index b784aab66867..dab49385e3e8 100644
--- a/drivers/virtio/virtio_ring.c
+++ b/drivers/virtio/virtio_ring.c
@@ -378,7 +378,7 @@ static int vring_map_one_sg(const struct vring_virtqueue *vq, struct scatterlist
 		 * is initialized by the hardware. Explicitly check/unpoison it
 		 * depending on the direction.
 		 */
-		kmsan_handle_dma(sg_page(sg), sg->offset, sg->length, direction);
+		kmsan_handle_dma(sg_phys(sg), sg->length, direction);
 		*addr = (dma_addr_t)sg_phys(sg);
 		return 0;
 	}
@@ -3149,7 +3149,7 @@ dma_addr_t virtqueue_dma_map_single_attrs(struct virtqueue *_vq, void *ptr,
 	struct vring_virtqueue *vq = to_vvq(_vq);
 
 	if (!vq->use_dma_api) {
-		kmsan_handle_dma(virt_to_page(ptr), offset_in_page(ptr), size, dir);
+		kmsan_handle_dma(virt_to_phys(ptr), size, dir);
 		return (dma_addr_t)virt_to_phys(ptr);
 	}
 
diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 2b1432cc16d5..6f27b9824ef7 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -182,8 +182,7 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
 
 /**
  * kmsan_handle_dma() - Handle a DMA data transfer.
- * @page:   first page of the buffer.
- * @offset: offset of the buffer within the first page.
+ * @phys:   physical address of the buffer.
  * @size:   buffer size.
  * @dir:    one of possible dma_data_direction values.
  *
@@ -191,8 +190,11 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
  * * checks the buffer, if it is copied to device;
  * * initializes the buffer, if it is copied from device;
  * * does both, if this is a DMA_BIDIRECTIONAL transfer.
+ *
+ * The function handles page lookup internally and supports both lowmem
+ * and highmem addresses.
  */
-void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
+void kmsan_handle_dma(phys_addr_t phys, size_t size,
 		      enum dma_data_direction dir);
 
 /**
@@ -372,8 +374,8 @@ static inline void kmsan_iounmap_page_range(unsigned long start,
 {
 }
 
-static inline void kmsan_handle_dma(struct page *page, size_t offset,
-				    size_t size, enum dma_data_direction dir)
+static inline void kmsan_handle_dma(phys_addr_t phys, size_t size,
+				    enum dma_data_direction dir)
 {
 }
 
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 80481a873340..709405d46b2b 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -172,7 +172,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
 	else
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
-	kmsan_handle_dma(page, offset, size, dir);
+	kmsan_handle_dma(phys, size, dir);
 	trace_dma_map_phys(dev, phys, addr, size, dir, attrs);
 	debug_dma_map_phys(dev, phys, size, dir, addr, attrs);
 
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 97de3d6194f0..eab7912a3bf0 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -336,25 +336,48 @@ static void kmsan_handle_dma_page(const void *addr, size_t size,
 }
 
 /* Helper function to handle DMA data transfers. */
-void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
+void kmsan_handle_dma(phys_addr_t phys, size_t size,
 		      enum dma_data_direction dir)
 {
 	u64 page_offset, to_go, addr;
+	struct page *page;
+	void *kaddr;
 
-	if (PageHighMem(page))
+	if (!pfn_valid(PHYS_PFN(phys)))
 		return;
-	addr = (u64)page_address(page) + offset;
+
+	page = phys_to_page(phys);
+	page_offset = offset_in_page(phys);
+
 	/*
 	 * The kernel may occasionally give us adjacent DMA pages not belonging
 	 * to the same allocation. Process them separately to avoid triggering
 	 * internal KMSAN checks.
 	 */
 	while (size > 0) {
-		page_offset = offset_in_page(addr);
 		to_go = min(PAGE_SIZE - page_offset, (u64)size);
+
+		if (PageHighMem(page))
+			/* Handle highmem pages using kmap */
+			kaddr = kmap_local_page(page);
+		else
+			/* Lowmem pages can be accessed directly */
+			kaddr = page_address(page);
+
+		addr = (u64)kaddr + page_offset;
 		kmsan_handle_dma_page((void *)addr, to_go, dir);
-		addr += to_go;
+
+		if (PageHighMem(page))
+			kunmap_local(page);
+
+		phys += to_go;
 		size -= to_go;
+
+		/* Move to next page if needed */
+		if (size > 0) {
+			page = phys_to_page(phys);
+			page_offset = offset_in_page(phys);
+		}
 	}
 }
 EXPORT_SYMBOL_GPL(kmsan_handle_dma);
@@ -366,8 +389,7 @@ void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
 	int i;
 
 	for_each_sg(sg, item, nents, i)
-		kmsan_handle_dma(sg_page(item), item->offset, item->length,
-				 dir);
+		kmsan_handle_dma(sg_phys(item), item->length, dir);
 }
 
 /* Functions from kmsan-checks.h follow. */
diff --git a/tools/virtio/linux/kmsan.h b/tools/virtio/linux/kmsan.h
index 272b5aa285d5..6cd2e3efd03d 100644
--- a/tools/virtio/linux/kmsan.h
+++ b/tools/virtio/linux/kmsan.h
@@ -4,7 +4,7 @@
 
 #include <linux/gfp.h>
 
-inline void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
+inline void kmsan_handle_dma(phys_addr_t phys, size_t size,
 			     enum dma_data_direction dir)
 {
 }
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cabe5b75fe1201baa6ecd209546c1f0913fc02ef.1750854543.git.leon%40kernel.org.
