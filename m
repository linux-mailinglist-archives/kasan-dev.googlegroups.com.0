Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBF6WYLCAMGQEMGFO5MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DA4AB1A1BE
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:44:09 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-23fe984fe57sf45539345ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:44:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311447; cv=pass;
        d=google.com; s=arc-20240605;
        b=NAvWBKJPqlQE18AG3C+17+v97ujcpdAzcTJSJsU6YbPmk4YvyETDUDbKBoP56KoOcc
         uVX0oEJCSa4qHaI7bkchAI745qKhr+eOqEZIDsy6OLaLdEeZBTpCtcI3dEDUUh+KTqzp
         2T4ZQOsYRcTBKtcsoQgz+b5M1v1PHcy4PM2NYIk5bPauQRYeYW1YLptE9sqoGHkrSanf
         8zr25IwGeeo2hFL2SNfTJBXYIQ9APvGo++eZJkMC2rz4QfiVqKLRdz1yOTd7zvdLaaH/
         6GuBVwav42X4MGjAYb8MEHFijvp56mR0s6xggwq14tPJYVxg+GFLWkS6dnUHbY1+UW1V
         eD7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Sk+Wa/amln0lEJ7HnuSFRG2xkhSTe6XfxG+QYe9EquY=;
        fh=yxOeIA1CCf6YgbiyOU7lgjhy1ArS9h6cJyMmC0RXWho=;
        b=HACowF9wJ4gobPy+nTVJ+GrV7XG9QBHjQ9iYHcuAGZ9nxSn8soMyXAdspRFLyea4i/
         6x4iqMXve8+SUPT2KYuXawFAX5loWmPxR6tWkIOF7xMQF5aVKXsy0UF6kj1SLzgaetcQ
         TFLeDeCIAIDxu2krUmpJYgkwlHOVxTH805jlwJ22jw8s04lQb+N8oy+fCqwgUtBs9CuB
         wZdtazSw8lqCtIfXIpnYBE6Oq96qoxvSrfagy/r2FoGjGGNxHvQUK9sgBtfUjPs0B//8
         aTdU+1xjf/GdJYk5E99f1dPP/fsWS5qcjfYHJsX24Q9HfNWb+kGPykE4nAAZIbSWXzP6
         UUJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GansV4O3;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311447; x=1754916247; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Sk+Wa/amln0lEJ7HnuSFRG2xkhSTe6XfxG+QYe9EquY=;
        b=PvIYKtAEaLvuYg7e9XE8qE/ngcHyQT5gRk+lSmCvLxwen5VXE04HszS7bEKU6Sf6xO
         /WESDoblHFF6D8iBAgxAq4rY4wOmEuAfKGQUVSv6shjegEoq1/IK+B4rWA0xRR1nH8/1
         oOKNScXkx4XmOWp+lKzAaWpwCzBnF+ZAF+aHBhaeIJ8ACOd/21ZTRpm1AvhVXDQFcIKL
         wjNbnL+s6rAN3zNjW2cWIHLBeeYxJjGWoj96GX+7S8irRCT3LCeGegSfSQ9ut60uzkzK
         qxHM9sF32/mX6fDK6bGFBsQgc9qSwaOWrGkJZQHWv3HqIG+dBsLFnLz52wTwRmskIy1O
         CT4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311447; x=1754916247;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Sk+Wa/amln0lEJ7HnuSFRG2xkhSTe6XfxG+QYe9EquY=;
        b=Z9RHDL8pbXBpmr7NCGhzYsV9HTZKm+pVhwUy9TlggDgxw3s/j5fv/UM6w2RTybeigI
         gnlPCpE0dT6J9wohtAa57tdAp2e6ZdzfZ1bPodYl6sMnprHruZ+BNecNqqP1CKOzqUjY
         VWhnxj5slQCTKI8mZvd7B+P6KG1hZWBX7LtPaQwAIviH9XWOQltOkch8wqUl6Mwmv6jP
         7KkalpCtFhjSJysR/2xa44jv2H9w6aYuA+uxaET+w/Pv5C6sZ4FGun+61RMe91PFMBLQ
         KHOu4kSQqGIyDIH5Zznpg7No0kibftLbg9PJiSA3ytGs8luTte4HaOy6YGNPJ/YKq1X1
         wB9g==
X-Forwarded-Encrypted: i=2; AJvYcCUJIf8aj0OmwFbDGhpOg8QIRfTJG+5xGxbwmRBsWRSp0TtZNcuoVP4LZypvETZuwlRJT4jRPg==@lfdr.de
X-Gm-Message-State: AOJu0YxkEvIcTQA3EaMY9WeNxtSyxvdP8mPltSBzKQW9ZrAieYCXomGm
	4VEoP0/PXszRydiYao6FTAv13MUDdlVWPUgEWTiXO3dkn0bFe+wB+2Ma
X-Google-Smtp-Source: AGHT+IEAzYOb0lgtVfuV0M/QUvjVRRRe0q6N/0ogkwE+flRiPvCeVF7wxqaZMBLGKcBO6ZB/EekztQ==
X-Received: by 2002:a17:903:245:b0:224:23be:c569 with SMTP id d9443c01a7336-24246f6b79bmr136302975ad.22.1754311447524;
        Mon, 04 Aug 2025 05:44:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcrfwi7nxYlICQTKw6LgraGUQ6x9maAnElnm8DPoDjUwg==
Received: by 2002:a17:903:23c1:b0:242:434e:6d22 with SMTP id
 d9443c01a7336-242434e6e73ls18093595ad.1.-pod-prod-08-us; Mon, 04 Aug 2025
 05:44:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUUKiQ5QCtTrw7j0Jd/PjkGwoQxP29Yv+HYqdRDY1U5glschacCqjIInPbmbgQk5J+zc7CN56eENAo=@googlegroups.com
X-Received: by 2002:a17:903:32c1:b0:240:8369:9b9d with SMTP id d9443c01a7336-24246f2d5cfmr131157595ad.9.1754311446160;
        Mon, 04 Aug 2025 05:44:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311446; cv=none;
        d=google.com; s=arc-20240605;
        b=QXXEsC4z94xCqt3HGBUfMfB7E9z71OMM1MM83ZR89/BqqC3SgVmBzRuCQnYpz4nNrC
         hIdIIOOE88J3ueRT7+hSJJUe+0ToIo8QI4H58mg7aKQk5vfticZye6DiYQMqjeM2+AmD
         Cquj1/vCQyW2jw0Cm7TMirfDTlF4FBKwdM6C9X6cyMV8slHizY4mx9pz+XU8elfTY29G
         TTsnt79/32ARFXOFNlCiiP8DtYsgco76Z40DrD0cnkhnn9ZB0xvjuOEhHRY0+vSZ0ZBc
         /TIPGtlyzjE4J3Is9doDN/iepGn/hS/u2aMLaVMF3pUrkGHY0rAYVH2UfP33bUOVF87m
         f0Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oozqhYH5WzlQxnRQi/0UiwCCQoDhNmN7489UY899NOI=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=Uf1Pk+EcL9rSp2vH/DkxkP6iL2pxKkkyJYFOzu9P/UCTpFwcPZ650PzSLRT+cSeVaT
         apE30yA4IcL3hgUvZmRqgK7VzIHOEe6mbQupXQ13hGN0CAqBsZQN3+J107xkSYP+SegD
         vKXMKJdVv9JivLC3bZVA4VmmLCzEsSUvkT6Hv2ljpvcV4aAju191/BA4kZyEmAECSnrY
         QkmsEwMuahoIWQ6h8z32DK8/Ay+xzIEQFp6z5tvdbz/x87GPVsr94adUfPTCEvNUjBC8
         Ud2f4MaB0xoHZJyEMjU6hIG8miigM4sOSaF/+SGVzNQPQ0XT2UCD/6v0A6+F2mYOtLqL
         7P/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GansV4O3;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241d1f93e96si4406535ad.3.2025.08.04.05.44.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:44:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 53524A55807;
	Mon,  4 Aug 2025 12:44:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 53748C4CEE7;
	Mon,  4 Aug 2025 12:44:03 +0000 (UTC)
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
Subject: [PATCH v1 11/16] dma-mapping: export new dma_*map_phys() interface
Date: Mon,  4 Aug 2025 15:42:45 +0300
Message-ID: <b96c639433d3b614288be4b305ecba3a9fb2c00f.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
References: <cover.1754292567.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GansV4O3;       spf=pass
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

Introduce new DMA mapping functions dma_map_phys() and dma_unmap_phys()
that operate directly on physical addresses instead of page+offset
parameters. This provides a more efficient interface for drivers that
already have physical addresses available.

The new functions are implemented as the primary mapping layer, with
the existing dma_map_page_attrs() and dma_unmap_page_attrs() functions
converted to simple wrappers around the phys-based implementations.

The old page-based API is preserved in mapping.c to ensure that existing
code won't be affected by changing EXPORT_SYMBOL to EXPORT_SYMBOL_GPL
variant for dma_*map_phys().

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/iommu/dma-iommu.c   | 14 --------
 include/linux/dma-direct.h  |  2 --
 include/linux/dma-mapping.h | 13 +++++++
 include/linux/iommu-dma.h   |  4 ---
 include/trace/events/dma.h  |  2 --
 kernel/dma/debug.c          | 43 -----------------------
 kernel/dma/debug.h          | 21 ------------
 kernel/dma/direct.c         | 16 ---------
 kernel/dma/mapping.c        | 68 ++++++++++++++++++++-----------------
 9 files changed, 49 insertions(+), 134 deletions(-)

diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
index 0a19ce50938b3..69f85209be7ab 100644
--- a/drivers/iommu/dma-iommu.c
+++ b/drivers/iommu/dma-iommu.c
@@ -1556,20 +1556,6 @@ void iommu_dma_unmap_sg(struct device *dev, struct scatterlist *sg, int nents,
 		__iommu_dma_unmap(dev, start, end - start);
 }
 
-dma_addr_t iommu_dma_map_resource(struct device *dev, phys_addr_t phys,
-		size_t size, enum dma_data_direction dir, unsigned long attrs)
-{
-	return __iommu_dma_map(dev, phys, size,
-			dma_info_to_prot(dir, false, attrs) | IOMMU_MMIO,
-			dma_get_mask(dev));
-}
-
-void iommu_dma_unmap_resource(struct device *dev, dma_addr_t handle,
-		size_t size, enum dma_data_direction dir, unsigned long attrs)
-{
-	__iommu_dma_unmap(dev, handle, size);
-}
-
 static void __iommu_dma_free(struct device *dev, size_t size, void *cpu_addr)
 {
 	size_t alloc_size = PAGE_ALIGN(size);
diff --git a/include/linux/dma-direct.h b/include/linux/dma-direct.h
index f3bc0bcd70980..c249912456f96 100644
--- a/include/linux/dma-direct.h
+++ b/include/linux/dma-direct.h
@@ -149,7 +149,5 @@ void dma_direct_free_pages(struct device *dev, size_t size,
 		struct page *page, dma_addr_t dma_addr,
 		enum dma_data_direction dir);
 int dma_direct_supported(struct device *dev, u64 mask);
-dma_addr_t dma_direct_map_resource(struct device *dev, phys_addr_t paddr,
-		size_t size, enum dma_data_direction dir, unsigned long attrs);
 
 #endif /* _LINUX_DMA_DIRECT_H */
diff --git a/include/linux/dma-mapping.h b/include/linux/dma-mapping.h
index afc89835c7457..2aa43a6bed92b 100644
--- a/include/linux/dma-mapping.h
+++ b/include/linux/dma-mapping.h
@@ -132,6 +132,10 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		unsigned long attrs);
 void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 		enum dma_data_direction dir, unsigned long attrs);
+dma_addr_t dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
+		enum dma_data_direction dir, unsigned long attrs);
+void dma_unmap_phys(struct device *dev, dma_addr_t addr, size_t size,
+		enum dma_data_direction dir, unsigned long attrs);
 unsigned int dma_map_sg_attrs(struct device *dev, struct scatterlist *sg,
 		int nents, enum dma_data_direction dir, unsigned long attrs);
 void dma_unmap_sg_attrs(struct device *dev, struct scatterlist *sg,
@@ -186,6 +190,15 @@ static inline void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr,
 		size_t size, enum dma_data_direction dir, unsigned long attrs)
 {
 }
+static inline dma_addr_t dma_map_phys(struct device *dev, phys_addr_t phys,
+		size_t size, enum dma_data_direction dir, unsigned long attrs)
+{
+	return DMA_MAPPING_ERROR;
+}
+static inline void dma_unmap_phys(struct device *dev, dma_addr_t addr,
+		size_t size, enum dma_data_direction dir, unsigned long attrs)
+{
+}
 static inline unsigned int dma_map_sg_attrs(struct device *dev,
 		struct scatterlist *sg, int nents, enum dma_data_direction dir,
 		unsigned long attrs)
diff --git a/include/linux/iommu-dma.h b/include/linux/iommu-dma.h
index 485bdffed9888..a92b3ff9b9343 100644
--- a/include/linux/iommu-dma.h
+++ b/include/linux/iommu-dma.h
@@ -42,10 +42,6 @@ size_t iommu_dma_opt_mapping_size(void);
 size_t iommu_dma_max_mapping_size(struct device *dev);
 void iommu_dma_free(struct device *dev, size_t size, void *cpu_addr,
 		dma_addr_t handle, unsigned long attrs);
-dma_addr_t iommu_dma_map_resource(struct device *dev, phys_addr_t phys,
-		size_t size, enum dma_data_direction dir, unsigned long attrs);
-void iommu_dma_unmap_resource(struct device *dev, dma_addr_t handle,
-		size_t size, enum dma_data_direction dir, unsigned long attrs);
 struct sg_table *iommu_dma_alloc_noncontiguous(struct device *dev, size_t size,
 		enum dma_data_direction dir, gfp_t gfp, unsigned long attrs);
 void iommu_dma_free_noncontiguous(struct device *dev, size_t size,
diff --git a/include/trace/events/dma.h b/include/trace/events/dma.h
index 84416c7d6bfaa..5da59fd8121db 100644
--- a/include/trace/events/dma.h
+++ b/include/trace/events/dma.h
@@ -73,7 +73,6 @@ DEFINE_EVENT(dma_map, name, \
 	TP_ARGS(dev, phys_addr, dma_addr, size, dir, attrs))
 
 DEFINE_MAP_EVENT(dma_map_phys);
-DEFINE_MAP_EVENT(dma_map_resource);
 
 DECLARE_EVENT_CLASS(dma_unmap,
 	TP_PROTO(struct device *dev, dma_addr_t addr, size_t size,
@@ -111,7 +110,6 @@ DEFINE_EVENT(dma_unmap, name, \
 	TP_ARGS(dev, addr, size, dir, attrs))
 
 DEFINE_UNMAP_EVENT(dma_unmap_phys);
-DEFINE_UNMAP_EVENT(dma_unmap_resource);
 
 DECLARE_EVENT_CLASS(dma_alloc_class,
 	TP_PROTO(struct device *dev, void *virt_addr, dma_addr_t dma_addr,
diff --git a/kernel/dma/debug.c b/kernel/dma/debug.c
index da6734e3a4ce9..06e31fd216e38 100644
--- a/kernel/dma/debug.c
+++ b/kernel/dma/debug.c
@@ -38,7 +38,6 @@ enum {
 	dma_debug_single,
 	dma_debug_sg,
 	dma_debug_coherent,
-	dma_debug_resource,
 	dma_debug_phy,
 };
 
@@ -141,7 +140,6 @@ static const char *type2name[] = {
 	[dma_debug_single] = "single",
 	[dma_debug_sg] = "scatter-gather",
 	[dma_debug_coherent] = "coherent",
-	[dma_debug_resource] = "resource",
 	[dma_debug_phy] = "phy",
 };
 
@@ -1448,47 +1446,6 @@ void debug_dma_free_coherent(struct device *dev, size_t size,
 	check_unmap(&ref);
 }
 
-void debug_dma_map_resource(struct device *dev, phys_addr_t addr, size_t size,
-			    int direction, dma_addr_t dma_addr,
-			    unsigned long attrs)
-{
-	struct dma_debug_entry *entry;
-
-	if (unlikely(dma_debug_disabled()))
-		return;
-
-	entry = dma_entry_alloc();
-	if (!entry)
-		return;
-
-	entry->type		= dma_debug_resource;
-	entry->dev		= dev;
-	entry->paddr		= addr;
-	entry->size		= size;
-	entry->dev_addr		= dma_addr;
-	entry->direction	= direction;
-	entry->map_err_type	= MAP_ERR_NOT_CHECKED;
-
-	add_dma_entry(entry, attrs);
-}
-
-void debug_dma_unmap_resource(struct device *dev, dma_addr_t dma_addr,
-			      size_t size, int direction)
-{
-	struct dma_debug_entry ref = {
-		.type           = dma_debug_resource,
-		.dev            = dev,
-		.dev_addr       = dma_addr,
-		.size           = size,
-		.direction      = direction,
-	};
-
-	if (unlikely(dma_debug_disabled()))
-		return;
-
-	check_unmap(&ref);
-}
-
 void debug_dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma_handle,
 				   size_t size, int direction)
 {
diff --git a/kernel/dma/debug.h b/kernel/dma/debug.h
index 76adb42bffd5f..424b8f912aded 100644
--- a/kernel/dma/debug.h
+++ b/kernel/dma/debug.h
@@ -30,14 +30,6 @@ extern void debug_dma_alloc_coherent(struct device *dev, size_t size,
 extern void debug_dma_free_coherent(struct device *dev, size_t size,
 				    void *virt, dma_addr_t addr);
 
-extern void debug_dma_map_resource(struct device *dev, phys_addr_t addr,
-				   size_t size, int direction,
-				   dma_addr_t dma_addr,
-				   unsigned long attrs);
-
-extern void debug_dma_unmap_resource(struct device *dev, dma_addr_t dma_addr,
-				     size_t size, int direction);
-
 extern void debug_dma_sync_single_for_cpu(struct device *dev,
 					  dma_addr_t dma_handle, size_t size,
 					  int direction);
@@ -88,19 +80,6 @@ static inline void debug_dma_free_coherent(struct device *dev, size_t size,
 {
 }
 
-static inline void debug_dma_map_resource(struct device *dev, phys_addr_t addr,
-					  size_t size, int direction,
-					  dma_addr_t dma_addr,
-					  unsigned long attrs)
-{
-}
-
-static inline void debug_dma_unmap_resource(struct device *dev,
-					    dma_addr_t dma_addr, size_t size,
-					    int direction)
-{
-}
-
 static inline void debug_dma_sync_single_for_cpu(struct device *dev,
 						 dma_addr_t dma_handle,
 						 size_t size, int direction)
diff --git a/kernel/dma/direct.c b/kernel/dma/direct.c
index fa75e30700730..1062caac47e7b 100644
--- a/kernel/dma/direct.c
+++ b/kernel/dma/direct.c
@@ -502,22 +502,6 @@ int dma_direct_map_sg(struct device *dev, struct scatterlist *sgl, int nents,
 	return ret;
 }
 
-dma_addr_t dma_direct_map_resource(struct device *dev, phys_addr_t paddr,
-		size_t size, enum dma_data_direction dir, unsigned long attrs)
-{
-	dma_addr_t dma_addr = paddr;
-
-	if (unlikely(!dma_capable(dev, dma_addr, size, false))) {
-		dev_err_once(dev,
-			     "DMA addr %pad+%zu overflow (mask %llx, bus limit %llx).\n",
-			     &dma_addr, size, *dev->dma_mask, dev->bus_dma_limit);
-		WARN_ON_ONCE(1);
-		return DMA_MAPPING_ERROR;
-	}
-
-	return dma_addr;
-}
-
 int dma_direct_get_sgtable(struct device *dev, struct sg_table *sgt,
 		void *cpu_addr, dma_addr_t dma_addr, size_t size,
 		unsigned long attrs)
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index f5f051737e556..b747794448130 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -152,12 +152,10 @@ static inline bool dma_map_direct(struct device *dev,
 	return dma_go_direct(dev, *dev->dma_mask, ops);
 }
 
-dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
-		size_t offset, size_t size, enum dma_data_direction dir,
-		unsigned long attrs)
+dma_addr_t dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
+		enum dma_data_direction dir, unsigned long attrs)
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
-	phys_addr_t phys = page_to_phys(page) + offset;
 	bool is_mmio = attrs & DMA_ATTR_MMIO;
 	dma_addr_t addr;
 
@@ -177,6 +175,9 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 
 		addr = ops->map_resource(dev, phys, size, dir, attrs);
 	} else {
+		struct page *page = phys_to_page(phys);
+		size_t offset = offset_in_page(phys);
+
 		/*
 		 * All platforms which implement .map_page() don't support
 		 * non-struct page backed addresses.
@@ -190,9 +191,25 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 
 	return addr;
 }
+EXPORT_SYMBOL_GPL(dma_map_phys);
+
+dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
+		size_t offset, size_t size, enum dma_data_direction dir,
+		unsigned long attrs)
+{
+	phys_addr_t phys = page_to_phys(page) + offset;
+
+	if (unlikely(attrs & DMA_ATTR_MMIO))
+		return DMA_MAPPING_ERROR;
+
+	if (IS_ENABLED(CONFIG_DMA_API_DEBUG))
+		WARN_ON_ONCE(!pfn_valid(PHYS_PFN(phys)));
+
+	return dma_map_phys(dev, phys, size, dir, attrs);
+}
 EXPORT_SYMBOL(dma_map_page_attrs);
 
-void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
+void dma_unmap_phys(struct device *dev, dma_addr_t addr, size_t size,
 		enum dma_data_direction dir, unsigned long attrs)
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
@@ -212,6 +229,16 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 	trace_dma_unmap_phys(dev, addr, size, dir, attrs);
 	debug_dma_unmap_phys(dev, addr, size, dir);
 }
+EXPORT_SYMBOL_GPL(dma_unmap_phys);
+
+void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
+		 enum dma_data_direction dir, unsigned long attrs)
+{
+	if (unlikely(attrs & DMA_ATTR_MMIO))
+		return;
+
+	dma_unmap_phys(dev, addr, size, dir, attrs);
+}
 EXPORT_SYMBOL(dma_unmap_page_attrs);
 
 static int __dma_map_sg_attrs(struct device *dev, struct scatterlist *sg,
@@ -337,41 +364,18 @@ EXPORT_SYMBOL(dma_unmap_sg_attrs);
 dma_addr_t dma_map_resource(struct device *dev, phys_addr_t phys_addr,
 		size_t size, enum dma_data_direction dir, unsigned long attrs)
 {
-	const struct dma_map_ops *ops = get_dma_ops(dev);
-	dma_addr_t addr = DMA_MAPPING_ERROR;
-
-	BUG_ON(!valid_dma_direction(dir));
-
-	if (WARN_ON_ONCE(!dev->dma_mask))
+	if (IS_ENABLED(CONFIG_DMA_API_DEBUG) &&
+	    WARN_ON_ONCE(pfn_valid(PHYS_PFN(phys_addr))))
 		return DMA_MAPPING_ERROR;
 
-	if (dma_map_direct(dev, ops))
-		addr = dma_direct_map_resource(dev, phys_addr, size, dir, attrs);
-	else if (use_dma_iommu(dev))
-		addr = iommu_dma_map_resource(dev, phys_addr, size, dir, attrs);
-	else if (ops->map_resource)
-		addr = ops->map_resource(dev, phys_addr, size, dir, attrs);
-
-	trace_dma_map_resource(dev, phys_addr, addr, size, dir, attrs);
-	debug_dma_map_resource(dev, phys_addr, size, dir, addr, attrs);
-	return addr;
+	return dma_map_phys(dev, phys_addr, size, dir, attrs | DMA_ATTR_MMIO);
 }
 EXPORT_SYMBOL(dma_map_resource);
 
 void dma_unmap_resource(struct device *dev, dma_addr_t addr, size_t size,
 		enum dma_data_direction dir, unsigned long attrs)
 {
-	const struct dma_map_ops *ops = get_dma_ops(dev);
-
-	BUG_ON(!valid_dma_direction(dir));
-	if (dma_map_direct(dev, ops))
-		; /* nothing to do: uncached and no swiotlb */
-	else if (use_dma_iommu(dev))
-		iommu_dma_unmap_resource(dev, addr, size, dir, attrs);
-	else if (ops->unmap_resource)
-		ops->unmap_resource(dev, addr, size, dir, attrs);
-	trace_dma_unmap_resource(dev, addr, size, dir, attrs);
-	debug_dma_unmap_resource(dev, addr, size, dir);
+	dma_unmap_phys(dev, addr, size, dir, attrs | DMA_ATTR_MMIO);
 }
 EXPORT_SYMBOL(dma_unmap_resource);
 
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b96c639433d3b614288be4b305ecba3a9fb2c00f.1754292567.git.leon%40kernel.org.
