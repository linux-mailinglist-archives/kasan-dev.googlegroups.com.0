Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBZWF7DCAMGQET4GYH3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id B4BF0B26E10
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:54:48 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-32326bd712csf1174702a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:54:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194087; cv=pass;
        d=google.com; s=arc-20240605;
        b=YKUiE2y9ygZXkJB7DQGQxtbdho/iF7EDeMAdMtuwaO3ORUKOTyskKyR77WRDTauaUR
         Y1SgOJ+H+Tuj1wBhXNoRVI4znXKMseXNjmZwExcIt/Tqd1J3hLMzd/aSWlqXkoPMzueA
         Yqv0EAEphqOPkcl84KpM6lPz5DbOWKb83pIHXFQ0TFgPM25bll0CIESfAPNsN49ER+i7
         mBmx8QQPdx8BvnPgO4eBhw9DY77Yodo060mRL2/UGHqAxw4V/Hjod9LbB8Re52urNMBh
         8JD45qDmWWQSW2wQc6TPCL/LDqgm4s3UG3I4i5bg6q6qBx6sWhRQ3CrM1HlE+zN7xUQH
         sHHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=B8yDA642JUB1wZWoSoOVOIkOfYbmdhz3N/TXx3PmUGE=;
        fh=oELB6uuS29j4VviUm3tBgXQEXh05jmE1tPNf824rA74=;
        b=ZYagHosPwko62MzXMvPyqyopHGKyXzocJa8l/X5sRZU8Yg3VHheoLbBnShZHfK0KC0
         D2kr20ixFPvCBq4f6EA0JYDHsRKWUq/TfpITtL0cwiXfyssPnHXQR2cjQFAa7SVZirk+
         kg/UGS5XilbqnzAXMZt33QRvMZ6igfn2BT30GzLQTB47rr2b0xq460AueYrQ2O9J8w2Y
         EKmjljXNj2nkSUNqYUxG+d6aUUCT3j5sKhexp9NtRX5PIV8HI9WbZNF0xMxR4ADBce3W
         CoExD2Eb50dnapuyPaKAebQT9mgSrGTvzgMD+S1XD3U5QwadRL5JJwFa1e97lNNoOHMz
         hlKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iIPdKT0a;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194087; x=1755798887; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=B8yDA642JUB1wZWoSoOVOIkOfYbmdhz3N/TXx3PmUGE=;
        b=IPIXWMMO3dUyAd45qL1rcvCCOxD4S9Qld0FuDM2Xt3LRgGPdHsXjqZnWzGWxhFxMit
         Hle0IbCXuo/diR9e51qMk1SxpGiFm8/OZHAtRCbbWnwzjeKfdB5xLPDjZq5Z8tW3yz+x
         dQC05S4ZoamERHYGkBisD4bTtjx2ULavYnNCS3Cjj97ZFKArqL+a/1ASrXPBCXyz7qDP
         BiaCWbK6Hhn/VGJGW99QQC52b0HdMyrbxF0bfhs4jABKeaC3GeoOXJ0+KDw2S1TWJNF7
         1KsXK7sMXhwgUnREJdNR81MEDuvOI87LI0IsbAIakcEERShdoaV2zFB3JUY8h4vBMmK2
         oJLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194087; x=1755798887;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=B8yDA642JUB1wZWoSoOVOIkOfYbmdhz3N/TXx3PmUGE=;
        b=hGbZeScGK+QkkgQBwFDYEwsNLmuaALX5uC+WUCHvZ1jb5J1XQAoIx29eIiuJl0T9lN
         7Zv1E2B7P76lD5NW32W+s21jz276MyqqmW/podkxC69nKsbwgSrsph/ux5BvUBSNZGyu
         8z715tivXvGRfFb2yH8x82lnWeIJV9jjRaaM63hgGGJxM44co1tYoqmJ/Uh/yLc4lCOl
         DK4cWfxXTUIVkF0DeZCwLPuHtJOYp3I0rVzCmPu0MtSocPIKCsfH7U9WJv2sd9ZK5FSq
         FBCzWar/6xDzqvYjmjYhY8/rYsgQT6WhHw0R/njpf7xt5LbXzPdp2ZjeL+F4PUxrQKHG
         xAqA==
X-Forwarded-Encrypted: i=2; AJvYcCXg5cyM5abSfLXxPPV9D0vZpbKF4DEdE/qOS1X0uNOW00U+2gBpSrj8GWIeefX858GG+ym7XQ==@lfdr.de
X-Gm-Message-State: AOJu0YzzhmcmxhMV1A+6OO0PalREi1yDz5cRnU0K2wFZ01z5psLlAJ2f
	6bsS1yv5WuyEIrlq8EoJ05XfXEp0HTsPew3gX9TnMHXNhAAJj8comJKJ
X-Google-Smtp-Source: AGHT+IErgX2RHVr4LQOmvxHSoFM7KzPQKibh8H0IHgpw6fGSjU0KgwkrnbM1h63mZNcXgNq8NxnPgg==
X-Received: by 2002:a17:90b:1d8a:b0:321:c81b:29cd with SMTP id 98e67ed59e1d1-3232b018ba6mr4425933a91.1.1755194087027;
        Thu, 14 Aug 2025 10:54:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfujnWtq1nfXRvzHiFJOfJ51C3CqAYDRJEvFkqaIB6iwg==
Received: by 2002:a17:90a:dc08:b0:313:9f92:9c2e with SMTP id
 98e67ed59e1d1-32326e47da1ls1194454a91.2.-pod-prod-01-us; Thu, 14 Aug 2025
 10:54:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWPNeIGwHWs0OErhyzhkbxJl9kiAMYei2s8L4Is8LxM46YC+1I4GBvQKLTRa/gWqjQ42rqBUEX3vqM=@googlegroups.com
X-Received: by 2002:a17:90b:17cd:b0:321:7528:ab43 with SMTP id 98e67ed59e1d1-3232b3d19d9mr5484268a91.24.1755194084795;
        Thu, 14 Aug 2025 10:54:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194084; cv=none;
        d=google.com; s=arc-20240605;
        b=VwrzTBmf9jayWkv99Vb+WkmEMpGoli1Oy5Qhe8jbpH8dFJtb2Ira24czpqAX7iJqLC
         t1ibUBKysuycwpDxh2l/PNur5Na3ZTG4cKAHcSYNPeTVDvMqbONK4ojDkyui5J6DT/xg
         YJgomghh3QFqfPO5I0HAylemy/EN8s5vf0xbyCCZuqgfYKP8XIJu4j78e+fb2qbRjATs
         1MlkyT3CW4/npINfftd67MkGr6Ph4sTpcHcjcP2x5GTocCwN3X2xfbh9uxZHg++Vy6Si
         y85ski2g02/xdAftUh72F7DzBV6vO5qQ8eOvFeBghTnX4swfF5QkrB658We5hxa+Io6W
         n0Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pzRaznYWcPEPErIBBlcoY/4/ZIrl67NZIXZ6kqZ6GFg=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=MRkZCpDcaz4vNqbvEFw3LKN1mi4I7C3ueoScWjsrukSWbt+mAdZDqbmP49vod/lhce
         ZQDXFBj3HedJEcUyKoBcysZLmp0yiVMKdwnEqkgNUjsciY8pSk46quTYM2EAIOw4StID
         MecKqJOPXUjvfl9Ou4NQjWSFmlAyNYq+vKbFddNlQDA4JSAyZOyE18WB6H46i1P9ccvZ
         zlFNNOYqbDnPMbj72EnOAIk5B7+db6cFjy8XrB5Zw8wASjek2mYXzZOsWqjMYkxaWu2n
         VuM19rXge9KJtyonyok63Nf8pzsCcQ3TMaV3J+48D+Ihy3HqgK/WEKvRheC69yD30Jil
         0BlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iIPdKT0a;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3232ae11abdsi79003a91.0.2025.08.14.10.54.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:54:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id DD020A573EF;
	Thu, 14 Aug 2025 17:54:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D180CC4CEEF;
	Thu, 14 Aug 2025 17:54:42 +0000 (UTC)
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
Subject: [PATCH v3 08/16] kmsan: convert kmsan_handle_dma to use physical addresses
Date: Thu, 14 Aug 2025 20:53:59 +0300
Message-ID: <38de1c5ffb567c5705826f14742fcaf54522c083.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iIPdKT0a;       spf=pass
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
size_t size). The existing semantics where callers are expected to
provide only kmap memory is continued here.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/virtio/virtio_ring.c | 4 ++--
 include/linux/kmsan.h        | 9 ++++-----
 kernel/dma/mapping.c         | 3 ++-
 mm/kmsan/hooks.c             | 7 ++++---
 tools/virtio/linux/kmsan.h   | 2 +-
 5 files changed, 13 insertions(+), 12 deletions(-)

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
index 97de3d6194f0..a080400290e7 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -336,14 +336,15 @@ static void kmsan_handle_dma_page(const void *addr, size_t size,
 }
 
 /* Helper function to handle DMA data transfers. */
-void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
-		      enum dma_data_direction dir)
+void kmsan_handle_dma(phys_addr_t phys, size_t size,
+		      enum dma_data_direction dir, unsigned int attrs)
 {
+	struct page *page = phys_to_page(phys);
 	u64 page_offset, to_go, addr;
 
 	if (PageHighMem(page))
 		return;
-	addr = (u64)page_address(page) + offset;
+	addr = (u64)page_address(page) + offset_in_page(phys);
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/38de1c5ffb567c5705826f14742fcaf54522c083.1755193625.git.leon%40kernel.org.
