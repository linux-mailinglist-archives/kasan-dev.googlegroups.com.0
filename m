Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBX7N63CAMGQEDIV5KDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id A4A87B261EF
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:13:53 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-88432cb7985sf188062539f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:13:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166432; cv=pass;
        d=google.com; s=arc-20240605;
        b=Sh3IRESgX2cK+Lt2o66EAwkhdqlgx5oHxMJ0pWNcB8KAzRXrsHmfjd5TQxNYkzr6K/
         3WE6Ypqp8TuFBKerGGE8snTm0+op7IUPEYEVGWAFz2nyZUJqSMMfPx8mGKiZFNyv/mLj
         1oTilgNS9B/JD1oUA0H+a5XStpbS6uCCYfzrIdSPxNf8fS5Qy+sA8tD4Z2i8bRX3odn/
         LvJwBYzvL1J4UyEE1UC17z5ire93DnnmkaX0UfNgGnnRJ6vE5fKYvh8WydxRgVUasGKa
         4XvbpUN3uVsM3Sya5Qf6pnkVXuCaQ7f51c991gHujH5GfUbyf/D+1lQ6ZO0B4w14twHi
         RWAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=LqAzEy/kRlyqBwRwtZaNXVG6i8SSDfbZnYWCLodR4IE=;
        fh=/BFK5/7bz1OnBwq+16yPqYij1OVL/KKVBROdyvLm0VI=;
        b=V7KACzNBzR5TJNRa4nCcqI5/vHNI+ymACICEfiuGy0+ESBI9Tbj/UhKOfmtBFHBwug
         E6+SNqzSAJKg9m4gzy57kAt9w8bNNrLzYaH93PbSqqBktmeQw12TwfKfWRKiY7FlDyao
         gEPA0LUKcVhcUF+6nUJ1RD1k32sa9wIZ0oYvRKz2gOLKhc7vMu9NGncbXbgsaoc6N5OM
         tvgUGUkVWQO167iURs1VM83qM79JY2yYHOrVkwIHJxJp1p397uOQ+g1lm2dk4U5GF+3m
         Lsx+8ohqe2G6jyuu9dy9iFQmVwl8o9AfpCPlIv57MRPkPb9hzC0yt63PkB6HEu6g9yc+
         GdaA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GbJfmdOg;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166432; x=1755771232; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LqAzEy/kRlyqBwRwtZaNXVG6i8SSDfbZnYWCLodR4IE=;
        b=E6ufrWLE4fyKI9dh+j8nyYp+JbsOPtNKXfR899Ybe0iHe/ixaOW3aAWgnUgSyaLp48
         7n9abQMhf45q2gxDa47Wg8UqV/viuR7lJ00sS6P8poI2OAYYABDzeM+Z3GG0tmN4kys6
         waRaNU8vQWKivIsUBUYXefsuhFfISGE451r7CLhMED8cnWezjkRW3LYPTYGrDx9Uhxo8
         aUhwxlj3oWdtKZek/uCe2Td/NGnHtgqGfDaa7mNQZ5xeMm0B5aQGnTBMuJ7zmItqrDPS
         x2k5zQzMdOFuHRzA2ThBhwdvBgxVJqnJN9l8M7MIjyfyrRa66NL80eEdTR3YHlOm69kn
         giuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166432; x=1755771232;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LqAzEy/kRlyqBwRwtZaNXVG6i8SSDfbZnYWCLodR4IE=;
        b=GPijV4+BiyBsj1CAMliwQ/S8H6pi6QeRX51+2uT2PFa7QLShJF6SbnATEKi9d//5Vf
         IVFIMeYGcExTx3UQ7+CqmgnciNiMygdCnotCks7PLsY7dfShIPx8oDnPuYe/hcDe9Ohx
         cRZrMBhsStPcqw3QwLTUPvgCf/gGWMVOv8hlfJrvBqqeln7n/dpZMTGpPqQ1ye+IxWVo
         pl1UqlPd7NhToyiOaigLVzPwbuh6RasUePrAQB58gc+7Y25bE+1Rn1Mdh9JIdch0R+bl
         +EN7ycTI6jPLLMUUbcrdmvZ2qIAxWlFYYjBfAQglQGgPNqbkRUtRqVtjQtPKULT7bvfG
         lm7w==
X-Forwarded-Encrypted: i=2; AJvYcCXpbmIEB4OZTNqXRbAyVyOHmWia9tkWDBHaqP+fX5DK5i/WOanCbSlfFwr97MaJTpRvFo86Hw==@lfdr.de
X-Gm-Message-State: AOJu0YyyYzJit4Wf46Fo1X0b8yUyF+N1GfzofIxuz2uNt1MKjW9XXxQH
	IJwzGwL+BbaYuDLbWGa0fza3hAR81PD43RVA940hT1Lr2T8IZ3gEc40m
X-Google-Smtp-Source: AGHT+IGl+31PEuqpKTsynJiMidHvsu6QnC5rdEaA6Ng7uefl63mzNCbLURHvml9UNuwvbAOAPGL1CA==
X-Received: by 2002:a05:6e02:216a:b0:3e5:4447:5eaa with SMTP id e9e14a558f8ab-3e57076e5ddmr46332255ab.1.1755166431978;
        Thu, 14 Aug 2025 03:13:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcZA/xkoWnlDwIb5silHC30XrnniU88IZVkIIGNzrzrhA==
Received: by 2002:a05:6e02:1a0a:b0:3df:1573:75d5 with SMTP id
 e9e14a558f8ab-3e56fb53fecls8513075ab.2.-pod-prod-02-us; Thu, 14 Aug 2025
 03:13:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVnvHUlfa8z5D7SvVHz0bHYQ+FEq5s+eb9JbKFmN4zZAjp4AtFGuPJFevIaC8n+gzPJ+/qTqeauijY=@googlegroups.com
X-Received: by 2002:a05:6e02:380e:b0:3e3:ef79:5a8c with SMTP id e9e14a558f8ab-3e57087a74cmr42419355ab.14.1755166431031;
        Thu, 14 Aug 2025 03:13:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166431; cv=none;
        d=google.com; s=arc-20240605;
        b=fm1RYxilZEQ1Es3BdvaG5sdM9hG+Qa4S6/KRGVf10MijPDFtM/ArO6YnDsZuUmhu5w
         Eb3KUpZsOYdddFNR4zsZUHybcJjItP0lbkbzCmlyre3uAAc1FnYwJyzrG3TmhkQpjdac
         +rIiluzYjyIUGXWtJiGZk/PV6KTX543f9e34SzC8CuPzHbFebqWluT/VQF8fMZqq3zVu
         RgOj8i/Fb0R76mmZab+0UEJM5Kds/P1b1RBJiFnziFlp5Igb9ecyeqx31+27AaG8tvWk
         r8srmivMBAWfRKCJoQ9WuDV5ccwvIzqrVxwR/R9ob4XONNk0KhT/j22nWr12ceuVfqMD
         79Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=QPYc3H/ma9xbsf5ZJdhCt7HUcPhgteyPOGxxaB+GH/M=;
        fh=iu7vSg1EzzlrRbrwbQPzfF0RoV1Uw6GXAom/pnqIJaQ=;
        b=TsrDYLz4GEjGpO4YU3gV3oQADZvYpGvGcFkaKkFOliaLJTsJt8+O4E5lDrAml1wCCl
         ccCzhELHXR8h6Xusq1NQ/UK/buS4d+PXFx8VnGSBrOyR+imQ+sB+gWL5vn9czZj7nnmY
         GGafV69lwqUFnp5TmFxHszu5gw/uL1s1XXiVMkwQ5aMu0FHnnJ5luzAvEOS44q9yxsqn
         kOypiZ7aiMLTyog4z47cYuTPIP0Dw04N70+5pK8HIjwzFE9KrjGDQDOmpLSj41MyJzzR
         zQ/QkjAAhZQb20vpXx0M2xQi5GjTDz/z2NZcDvgHevk7MkP5VKgTDqZ3jkXJaSzTMbjj
         imiw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GbJfmdOg;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e5689b200asi1706035ab.5.2025.08.14.03.13.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:13:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 1F5C36020A;
	Thu, 14 Aug 2025 10:13:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 15191C4CEED;
	Thu, 14 Aug 2025 10:13:49 +0000 (UTC)
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Jason Gunthorpe <jgg@nvidia.com>,
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
Subject: [PATCH v2 00/16] dma-mapping: migrate to physical address-based API
Date: Thu, 14 Aug 2025 13:13:18 +0300
Message-ID: <cover.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GbJfmdOg;       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass
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

Changelog:
v2:
 * Used commit messages and cover letter from Jason
 * Moved setting IOMMU_MMIO flag to dma_info_to_prot function
 * Micro-optimized the code
 * Rebased code on v6.17-rc1
v1: https://lore.kernel.org/all/cover.1754292567.git.leon@kernel.org
 * Added new DMA_ATTR_MMIO attribute to indicate
   PCI_P2PDMA_MAP_THRU_HOST_BRIDGE path.
 * Rewrote dma_map_* functions to use thus new attribute
v0: https://lore.kernel.org/all/cover.1750854543.git.leon@kernel.org/
------------------------------------------------------------------------

This series refactors the DMA mapping to use physical addresses
as the primary interface instead of page+offset parameters. This
change aligns the DMA API with the underlying hardware reality where
DMA operations work with physical addresses, not page structures.

The series maintains export symbol backward compatibility by keeping
the old page-based API as wrapper functions around the new physical
address-based implementations.

This series refactors the DMA mapping API to provide a phys_addr_t
based, and struct-page free, external API that can handle all the
mapping cases we want in modern systems:

 - struct page based cachable DRAM
 - struct page MEMORY_DEVICE_PCI_P2PDMA PCI peer to peer non-cachable
   MMIO
 - struct page-less PCI peer to peer non-cachable MMIO
 - struct page-less "resource" MMIO

Overall this gets much closer to Matthew's long term wish for
struct-pageless IO to cachable DRAM. The remaining primary work would
be in the mm side to allow kmap_local_pfn()/phys_to_virt() to work on
phys_addr_t without a struct page.

The general design is to remove struct page usage entirely from the
DMA API inner layers. For flows that need to have a KVA for the
physical address they can use kmap_local_pfn() or phys_to_virt(). This
isolates the struct page requirements to MM code only. Long term all
removals of struct page usage are supporting Matthew's memdesc
project which seeks to substantially transform how struct page works.

Instead make the DMA API internals work on phys_addr_t. Internally
there are still dedicated 'page' and 'resource' flows, except they are
now distinguished by a new DMA_ATTR_MMIO instead of by callchain. Both
flows use the same phys_addr_t.

When DMA_ATTR_MMIO is specified things work similar to the existing
'resource' flow. kmap_local_pfn(), phys_to_virt(), phys_to_page(),
pfn_valid(), etc are never called on the phys_addr_t. This requires
rejecting any configuration that would need swiotlb. CPU cache
flushing is not required, and avoided, as ATTR_MMIO also indicates the
address have no cachable mappings. This effectively removes any
DMA API side requirement to have struct page when DMA_ATTR_MMIO is
used.

In the !DMA_ATTR_MMIO mode things work similarly to the 'page' flow,
except on the common path of no cache flush, no swiotlb it never
touches a struct page. When cache flushing or swiotlb copying
kmap_local_pfn()/phys_to_virt() are used to get a KVA for CPU
usage. This was already the case on the unmap side, now the map side
is symmetric.

Callers are adjusted to set DMA_ATTR_MMIO. Existing 'resource' users
must set it. The existing struct page based MEMORY_DEVICE_PCI_P2PDMA
path must also set it. This corrects some existing bugs where iommu
mappings for P2P MMIO were improperly marked IOMMU_CACHE.

Since ATTR_MMIO is made to work with all the existing DMA map entry
points, particularly dma_iova_link(), this finally allows a way to use
the new DMA API to map PCI P2P MMIO without creating struct page. The
VFIO DMABUF series demonstrates how this works. This is intended to
replace the incorrect driver use of dma_map_resource() on PCI BAR
addresses.

This series does the core code and modern flows. A followup series
will give the same treatment to the legacy dma_ops implementation.

Thanks

Leon Romanovsky (16):
  dma-mapping: introduce new DMA attribute to indicate MMIO memory
  iommu/dma: implement DMA_ATTR_MMIO for dma_iova_link().
  dma-debug: refactor to use physical addresses for page mapping
  dma-mapping: rename trace_dma_*map_page to trace_dma_*map_phys
  iommu/dma: rename iommu_dma_*map_page to iommu_dma_*map_phys
  iommu/dma: extend iommu_dma_*map_phys API to handle MMIO memory
  dma-mapping: convert dma_direct_*map_page to be phys_addr_t based
  kmsan: convert kmsan_handle_dma to use physical addresses
  dma-mapping: handle MMIO flow in dma_map|unmap_page
  xen: swiotlb: Open code map_resource callback
  dma-mapping: export new dma_*map_phys() interface
  mm/hmm: migrate to physical address-based DMA mapping API
  mm/hmm: properly take MMIO path
  block-dma: migrate to dma_map_phys instead of map_page
  block-dma: properly take MMIO path
  nvme-pci: unmap MMIO pages with appropriate interface

 Documentation/core-api/dma-api.rst        |   4 +-
 Documentation/core-api/dma-attributes.rst |  18 ++++
 arch/powerpc/kernel/dma-iommu.c           |   4 +-
 block/blk-mq-dma.c                        |  15 ++-
 drivers/iommu/dma-iommu.c                 |  61 ++++++------
 drivers/nvme/host/pci.c                   |  18 +++-
 drivers/virtio/virtio_ring.c              |   4 +-
 drivers/xen/swiotlb-xen.c                 |  21 +++-
 include/linux/blk-mq-dma.h                |   6 +-
 include/linux/blk_types.h                 |   2 +
 include/linux/dma-direct.h                |   2 -
 include/linux/dma-map-ops.h               |   8 +-
 include/linux/dma-mapping.h               |  33 ++++++
 include/linux/iommu-dma.h                 |  11 +-
 include/linux/kmsan.h                     |  12 ++-
 include/trace/events/dma.h                |   9 +-
 kernel/dma/debug.c                        |  71 ++++---------
 kernel/dma/debug.h                        |  37 ++-----
 kernel/dma/direct.c                       |  22 +---
 kernel/dma/direct.h                       |  52 ++++++----
 kernel/dma/mapping.c                      | 116 +++++++++++++---------
 kernel/dma/ops_helpers.c                  |   6 +-
 mm/hmm.c                                  |  19 ++--
 mm/kmsan/hooks.c                          |  36 +++++--
 rust/kernel/dma.rs                        |   3 +
 tools/virtio/linux/kmsan.h                |   2 +-
 26 files changed, 333 insertions(+), 259 deletions(-)

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1755153054.git.leon%40kernel.org.
