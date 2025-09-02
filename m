Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBAUI3TCQMGQEEIY5KJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 03615B407A1
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:49:41 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-329ee69e7desf598939a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:49:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824579; cv=pass;
        d=google.com; s=arc-20240605;
        b=H5Z8O9NhlUEU8RiEkULPfFphIiPQsmBaM0LBwBVDfvcRt6nJLI/TEqFZX8T4Ie5wY4
         g19U1w4srE7LBA+aauWSyFvjx6PImtxswiKB0HDqIK14JLGuhpXsVJ96BceuCKQJ4ykn
         s6Tycq7272Gr9wgWIcZU2TDz5TkByA727TYn1jv1a96+eXe01uaanwzuuYHkF6T3mfb7
         belnnQbU6O4ZelOlz3g8po9UfIXQu9yBt4D0FtwhYX8UFn3+4qNuyo2tK+wQuMm+6e4R
         wMnUrKNMbAcG2FLWYTQ92zeLuTiMy7hODhtoCxRmwiZhXWFH11RHQz88XF/JqvfxUeuw
         GdkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=BR1zKyyksHdA7u5E3aJU0NdC83j/EIda/L2OMH81WRE=;
        fh=OGBBnQmCafSTcWHredEjrgIduWAdEqiZx1mKYcBB2Cc=;
        b=iChCnklzGpSwfi/Ai1op4dcY8kNktNLcY8H0wkj3GW6xd4RzJqx5RYMjR+k5e7E4xv
         +IL2E+YRxq0V5wrLsCCnkVVtWCUPzrjjaWssUH+zwS/8Wa4t+6IfCXpzgww7/BkzoGoh
         0+TlOl9XOrQL4QGpLEd+6zIlwmH52fUEIe7nMusvzUpFISb/I0uLiHAKQUUxgDpzNb3+
         LTjArYRsQ2uRjeDK58lvYsEkOaJxbxl6C4NnPR6ibopRac+xjKb77JgdT7Df+6gSowmb
         7+jV0xWCj6fG5aAO+WHKsIaJkLwhPwQAxZ8aqDbg+A6G16S3G/bH/tcfJmbIMJBl2l1I
         GzIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CCnOPMO8;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824579; x=1757429379; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=BR1zKyyksHdA7u5E3aJU0NdC83j/EIda/L2OMH81WRE=;
        b=YwQnVQfvr43ztx1F8PaHHSPhDLgi134NVsa4bnb4GUM1qTqtle5OM0CR3UkkLUXyr7
         fhxcBkW8Hm86x5KkWSY9KF5cptQUQJIecMkNxl3Tq8CgjPbOIkXRyJiwEGiLR+ORCtHk
         t7FSHnF6c8CgZNGrc9Wmh1ExNJdM7t/01H1FTYBvTEFVDskJoDP909hH9mjQb79xaBtS
         0MW5C9WPaY2Wtyt4Zg7SFyyO05KBNxLE/4NrkbkUOo2Z+J3PFMw94rY6Nmzm1wlJVR2E
         5FxPuvmk0vrIHUy3BJ5OYmfqmWyPxxG1Gy6vQkY5X7hJaMEx+PzRdsVZ9h7MgBk1a6g4
         hj6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824579; x=1757429379;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BR1zKyyksHdA7u5E3aJU0NdC83j/EIda/L2OMH81WRE=;
        b=UFWkj9ZRDAm2n/qEc6DU8JKCehz6Z1xO/kw8kBAcFfaov6p65iFPTP6LsFwgTxARth
         yRgomSETrl6Ga4F2hswMbhyNJRb7nltf/NJtnS9YRNDwLB/qIIrJ1jKnE/Femw9GpEW2
         GvuQVGfLQ6iHiDVdiyb8UJ06xneaoeLxdebheWWC36icAoQauQjSZ9mkmIxrc2QqMgQl
         K8THP1j1zj3vuuKdS1sH+aj0YRXwLkPa8KW/Z6dp7fvq7i1GvmchLiXqbnsvG5a9zBiE
         oBtt1kBXk1owdd+WENPpNRiOThT/NYeAThZb9LSzm7BgNtCGTTUjaG5X5PMK/unRbxbW
         aS8Q==
X-Forwarded-Encrypted: i=2; AJvYcCX/ZwKUO7HK34MEXKgZwxJWOR2YxMBhPDzDQCVXQvXJu8vaFXWJa9DDsy+kyd6HUmoWbzudzw==@lfdr.de
X-Gm-Message-State: AOJu0YydC23YN4eI5QvekfcjRsez0Y36+S7XsxzAFkU5ZHpzXRt+2168
	4LNbv30tNpmr/5nScr1OD4jJx4jXRkJwpvZVnF/aJKbFsGkPDkkh8ls2
X-Google-Smtp-Source: AGHT+IEgF4TXlGKo60UWtwsYigVNPH6rJT93puwBX/tfObhSVHdSBuaAA22zou/XbqlzDoSyjz8H/Q==
X-Received: by 2002:a17:90b:384c:b0:329:e708:c88e with SMTP id 98e67ed59e1d1-329e708c9fdmr3028169a91.20.1756824579233;
        Tue, 02 Sep 2025 07:49:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZev7SUZSZ/3ryJ2HPh4yDkQO6EXO4z2E58WuiWXxdgJYw==
Received: by 2002:a17:90b:5518:b0:324:e853:c58 with SMTP id
 98e67ed59e1d1-327aacb17b5ls4418851a91.2.-pod-prod-09-us; Tue, 02 Sep 2025
 07:49:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWdD5qkmhosOkOCHSB3JRtUiZwHKX5VYbI+NZ+dL+3JLFDexwFfcFNCiQtfQ+IdjZ/gMPAq+UFAAs8=@googlegroups.com
X-Received: by 2002:a17:90b:4f85:b0:327:add2:4f31 with SMTP id 98e67ed59e1d1-328156e57d2mr16291649a91.33.1756824577456;
        Tue, 02 Sep 2025 07:49:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824577; cv=none;
        d=google.com; s=arc-20240605;
        b=M5CAtxylIbWoxWKEXwWISJvTx5BZUwUakQrHkRfjlAmuXe51MXMglvc81N4m03V2P1
         M05NWpO5gNZQ8u9UqahYW3G2+0IwFN9ysx0Mhs/NpcNQav/YQXimphKeT+6dlG+6xMNI
         kDavIUB6iMvWuL8+ZAXickRcnnNl/uecXtJIyIEqsg552jOI3Gdqnvn3NDRdx3iKsSmQ
         hqerFkKA1YBtOOZp32lgIS/t3m05zpYlIQrq96xzyLr3WzlZC6gPPm/9k/PPjQ+TV9sz
         NBgaEWpLPY/zd5vdMWxqkYNEnfH/f709YEmjfjv1HEKP+svszfgc16Er9TEcX7/PyDqX
         xyhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8Vl1Om3dLVLF61K9r5/nvBAzYD5mRA5wX9zobMvy048=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=I2zMEp5PaFwhdCyzXo5zXoMFcK055+w4BfWwTHi5MSOAUvmHkRnlPEJtWewE9HFopH
         lFc5JbmlOVPq5/ZEmJmWPBBxluHUtnkAgzkxW4D31d3iy9O31gDb5ZLEoakteq7Hvk/a
         d8tjR2NB6shEGcE21wgloqm7Ujfd/YfDZad25e4Q4Y3Lj1PdspwtevoBM36A+Dss8HZR
         6/+mFjzLkF17HZ3bMzDw7xAmCaxzXRbvSQ7TNOrb8zDbRGXk69leNJsLh34A1lVIuMNG
         8qyo/gUdCNEUvqtIAMUN+IlcfRmpND4oOe9iCdGm6dAAP7LUw3mDu4MhuM52T03slvdi
         TBNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CCnOPMO8;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-327415067d9si962143a91.0.2025.09.02.07.49.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:49:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 9473A60222;
	Tue,  2 Sep 2025 14:49:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 98CE2C4CEED;
	Tue,  2 Sep 2025 14:49:35 +0000 (UTC)
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
	David Hildenbrand <david@redhat.com>,
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
Subject: [PATCH v5 08/16] kmsan: convert kmsan_handle_dma to use physical addresses
Date: Tue,  2 Sep 2025 17:48:45 +0300
Message-ID: <9f59c7c5ca21b39cdc90696f270ec6b04c92abf6.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756822782.git.leon@kernel.org>
References: <cover.1756822782.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CCnOPMO8;       spf=pass
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

Convert the KMSAN DMA handling function from page-based to physical
address-based interface.

The refactoring renames kmsan_handle_dma() parameters from accepting
(struct page *page, size_t offset, size_t size) to (phys_addr_t phys,
size_t size). The existing semantics where callers are expected to
provide only kmap memory is continued here.

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/virtio/virtio_ring.c | 4 ++--
 include/linux/kmsan.h        | 9 ++++-----
 kernel/dma/mapping.c         | 3 ++-
 mm/kmsan/hooks.c             | 8 +++++---
 tools/virtio/linux/kmsan.h   | 2 +-
 5 files changed, 14 insertions(+), 12 deletions(-)

diff --git a/drivers/virtio/virtio_ring.c b/drivers/virtio/virtio_ring.c
index f5062061c408..c147145a6593 100644
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
@@ -3157,7 +3157,7 @@ dma_addr_t virtqueue_dma_map_single_attrs(struct virtqueue *_vq, void *ptr,
 	struct vring_virtqueue *vq = to_vvq(_vq);
 
 	if (!vq->use_dma_api) {
-		kmsan_handle_dma(virt_to_page(ptr), offset_in_page(ptr), size, dir);
+		kmsan_handle_dma(virt_to_phys(ptr), size, dir);
 		return (dma_addr_t)virt_to_phys(ptr);
 	}
 
diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 2b1432cc16d5..f2fd221107bb 100644
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
@@ -192,7 +191,7 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
  * * initializes the buffer, if it is copied from device;
  * * does both, if this is a DMA_BIDIRECTIONAL transfer.
  */
-void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
+void kmsan_handle_dma(phys_addr_t phys, size_t size,
 		      enum dma_data_direction dir);
 
 /**
@@ -372,8 +371,8 @@ static inline void kmsan_iounmap_page_range(unsigned long start,
 {
 }
 
-static inline void kmsan_handle_dma(struct page *page, size_t offset,
-				    size_t size, enum dma_data_direction dir)
+static inline void kmsan_handle_dma(phys_addr_t phys, size_t size,
+				    enum dma_data_direction dir)
 {
 }
 
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 80481a873340..891e1fc3e582 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -172,7 +172,8 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
 	else
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
-	kmsan_handle_dma(page, offset, size, dir);
+
+	kmsan_handle_dma(phys, size, dir);
 	trace_dma_map_phys(dev, phys, addr, size, dir, attrs);
 	debug_dma_map_phys(dev, phys, size, dir, addr, attrs);
 
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 97de3d6194f0..ea6d1de19ede 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -336,14 +336,16 @@ static void kmsan_handle_dma_page(const void *addr, size_t size,
 }
 
 /* Helper function to handle DMA data transfers. */
-void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
+void kmsan_handle_dma(phys_addr_t phys, size_t size,
 		      enum dma_data_direction dir)
 {
-	u64 page_offset, to_go, addr;
+	struct page *page = phys_to_page(phys);
+	u64 page_offset, to_go;
+	void *addr;
 
 	if (PageHighMem(page))
 		return;
-	addr = (u64)page_address(page) + offset;
+	addr = page_to_virt(page);
 	/*
 	 * The kernel may occasionally give us adjacent DMA pages not belonging
 	 * to the same allocation. Process them separately to avoid triggering
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
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9f59c7c5ca21b39cdc90696f270ec6b04c92abf6.1756822782.git.leon%40kernel.org.
