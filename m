Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBSWF7DCAMGQELAGRNBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id C2C33B26DFE
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:54:19 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-70a88d99c1csf24946286d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:54:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194058; cv=pass;
        d=google.com; s=arc-20240605;
        b=dfCrXAsE0RoGp2vtFyq9KgOq/Iyf896c9Cml1v5ZudgPWfFNTYIgb/uF8v4SH5mmGY
         M0dJJDBLaxEc01usiE4oAthlAcAtLUqiXGufr0uCGwuQ7MQE3bS5TG+KjdD1Ppy295Zu
         bypa/ngEDcomuJdMj9Ht+rHeBwxTdqY81FrxtzZxcqK4/QU1PYfvkH4vlwdbOO/+iHQQ
         V0pBIP9QdcyBgUgXdA7h+cqnApA9uHtMh4lsaInexUQ6y8o+jfdufmeIGp3fqqj5ktfa
         ZW9ZSSM5TushR7+MgIILcJitf5rumwHZPXus5xlZ/Q39cmUDZIcz79biPFWp56Mmr37i
         uAKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=iWyf673zDsiv2aro1D7JUtjGFqItLQHMRDL9ccS4kok=;
        fh=oH/z2GDAxkqGBzu9OWHkvYNQIO93ComFfJBu1oQWUhI=;
        b=gBL3zUaNeg9pqrNnRWs9cT8bigQ6A0fDZtrSstkzE3ROnFgaj5iOSlrox2UuBIJMI9
         gQEI1Zi5D5dGpQEY6cxVK+aKpdjNid1mXQSPOYYO51LEPxbnlYZQZnXvY+3ItzKlB+OV
         SdKfeL60E5UQEt5+p7Kdgpj1vv7im8Xam1WwWYFgzy7DMWZ0PkaNYqFZsEdyi4Xi+Zpv
         Lo7cDrcnpbbsO3VRFdO4WFlipSM/8vd0vlqMgokW7I03XxD8zSMetvx1+cec03PGsrEC
         otQ5UDnX5+huJ2wycEwyi8bbcfaMGmRlM8y5OEnpzXx3I/yg3kHCq2VwFVavfVy72aKh
         Vg6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OcmeWeuk;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194058; x=1755798858; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iWyf673zDsiv2aro1D7JUtjGFqItLQHMRDL9ccS4kok=;
        b=k2BgHKe5wDFx+C/OtezSauE5MTqbvh6+X/yn8G/36vLImT5Gr+g4YeiaoxzEDBPOC6
         0Hp9Z/91V209/0R2mHfynAOpk4GuDD9UlSl+kOV9rVD7+XskW5ui2h87JYxuRJVH6DaQ
         /4lWErNuOv8g4zTKudUOkUXhtQihbV9EwA3ShtkyGnhA6nvirOOS+/v2Cc46ECmzPCAJ
         5VaaEWgvhb+Q0mQnPoMZsNm3VwiRpuos9wY63kqqJig1rk7rUU0Liu7Eg41P15EfkVfB
         156HFZOeqd9Avoh4jp+M19soS2JkEdGDk9u+FobuoMZbE6KGKvfVRb1swbXdqLAttAm2
         LL1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194058; x=1755798858;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iWyf673zDsiv2aro1D7JUtjGFqItLQHMRDL9ccS4kok=;
        b=P6+SfhqiHhcs4GSKJXxScAJqqmaa5DPyFaMbO3+aQ6wDOAeIqgR/XzUcmNLoK2pQaY
         EkNRUw83e/oQXFpa8xNBerKNowsRAK3ruABOE6MnIfLWTWBR9C8lsqYRIyRmQi/uN9B8
         FauE9NClW8qD3lSYLuGM1Sg+ixqGRYzptXx5TTY1X/0KpMu7KuMPGKKFJ8LCWiHODf7h
         qyui1rPcPaSx/S31MsR1fz4W8Ysx/VEpN1ofvS+j+BgGW7FchgZa7mP/m/nxkhztHZTh
         /d9CujqoGvM5gtxdBmZJWyvZHEnDDYkIWgq821QTHSjEbC7I4Bz1Qz7W3rlU1HWbZbrB
         iSyQ==
X-Forwarded-Encrypted: i=2; AJvYcCWaTXr4uNx4xGhvzT4VO0Z9VIdfryuI/F29c45EMWXmM6zMC4sLJ2JOzbhYdjF7sSZuFhcecg==@lfdr.de
X-Gm-Message-State: AOJu0YxXnuP6KDlbFFBxLmYwvyQLeLDCYlblaia0XVf12kOlZyfk9/UT
	zUR4XxW7fAu1LT23Ef8DnYxVA4fIAarfTkZBP9yIKkhBOR9o3YwiphBR
X-Google-Smtp-Source: AGHT+IEvzZCycqcpdq57Qva9JtcG5+OV/9QJoPyqruDT4ZTI26KrGHi8qzPr5PTdz2V7gbgtC2+NuQ==
X-Received: by 2002:a05:6214:1c8c:b0:707:71d9:d6e2 with SMTP id 6a1803df08f44-70b984b9190mr41699506d6.38.1755194058425;
        Thu, 14 Aug 2025 10:54:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeD0Gmdsa2ullBzQ18ZmjXHqleLBHuV9gBVjGDaq48stg==
Received: by 2002:a05:6214:cc7:b0:6fa:fb65:95dc with SMTP id
 6a1803df08f44-70aafed50dbls15239646d6.1.-pod-prod-01-us; Thu, 14 Aug 2025
 10:54:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX0z/EdMu1H9wYjbRtQoNlh78Qdwkmk3skOgTxk9GtwJqa6s88L2cnaaazTxw+eKOJ4qFPtY9T6lF0=@googlegroups.com
X-Received: by 2002:a05:6122:1816:b0:539:5d6e:71fc with SMTP id 71dfb90a1353d-53b18f951acmr1610522e0c.5.1755194057239;
        Thu, 14 Aug 2025 10:54:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194057; cv=none;
        d=google.com; s=arc-20240605;
        b=XT+KTzfouGPAZLkXTzBmCkXxQRE/0Ida3+/YvU0186BdGQ3z23qUPDdeyQ6oTJiPix
         4hESZcet7d/1eOknKV2fBUkUgMPYR6lwyX5Sqfp3IAgATpm8wMdOcs77DBo3rskcx4KP
         PpZj2FbJemWHzbbWSVJGvJEM+Ovg27WrJbQ5Ic+Sm8tL7XT9kR8mFr6nGIWdwXtO0CUL
         HiY09oWHRBGj7p46Nxn1uvNu/v1qt02GP8Q+DvvBOAQufkGlQkmyxf2Vhvaunt3mW5n/
         5Ty/4BBGXQM0OZxPI12nlWvUNS5ydGjMkzF9JFFbZGQdem6TSHsV7MunqytajRY/tO8F
         FslA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=hygAWsv6Yve4N+8ShnO81RkdjrmkzVxj8VTWU3zpjB0=;
        fh=iu7vSg1EzzlrRbrwbQPzfF0RoV1Uw6GXAom/pnqIJaQ=;
        b=cZtWW7jf2SuHzTvGF4BdWtADbJTN+fRwkMPHmwXOyJVMOotKMP6xGl2QGg/cIY1azb
         S+aEm+mpPpndX6tDTq5xUh6GlnhyA8FvWXZT5t/vRn/XGfCzkjwRkHbsVpIQcnNUKsE5
         rVS7jhYUj+DwNOfRQnX6D0oFl6TUcTxTdJspT/sKImOXLODcND4LW8EqhdA14vGyY81D
         3Hh3yoGtMPmyQqsWOd96RSnY1NPM3tU+WeDufIz95d1d/Ak7D0yD2vWJbiSsHLIP3SwN
         kuzBB6fdIszm6OZiZCu8jW4LZMTM277K5cALrm4drCIoY1GqtgJyZstsCo5p3yTHh3Aq
         wjtA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OcmeWeuk;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-539b01ae82bsi716764e0c.2.2025.08.14.10.54.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:54:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 92993601D8;
	Thu, 14 Aug 2025 17:54:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2DF51C4CEED;
	Thu, 14 Aug 2025 17:54:15 +0000 (UTC)
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
Subject: [PATCH v3 00/16] dma-mapping: migrate to physical address-based API
Date: Thu, 14 Aug 2025 20:53:51 +0300
Message-ID: <cover.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OcmeWeuk;       spf=pass
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
v3:
 * Fixed typo in "cacheable" word
 * Simplified kmsan patch a lot to be simple argument refactoring
v2: https://lore.kernel.org/all/cover.1755153054.git.leon@kernel.org
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
 drivers/iommu/dma-iommu.c                 |  61 +++++------
 drivers/nvme/host/pci.c                   |  18 +++-
 drivers/virtio/virtio_ring.c              |   4 +-
 drivers/xen/swiotlb-xen.c                 |  21 +++-
 include/linux/blk-mq-dma.h                |   6 +-
 include/linux/blk_types.h                 |   2 +
 include/linux/dma-direct.h                |   2 -
 include/linux/dma-map-ops.h               |   8 +-
 include/linux/dma-mapping.h               |  33 ++++++
 include/linux/iommu-dma.h                 |  11 +-
 include/linux/kmsan.h                     |   9 +-
 include/trace/events/dma.h                |   9 +-
 kernel/dma/debug.c                        |  71 ++++---------
 kernel/dma/debug.h                        |  37 ++-----
 kernel/dma/direct.c                       |  22 +---
 kernel/dma/direct.h                       |  52 ++++++----
 kernel/dma/mapping.c                      | 117 +++++++++++++---------
 kernel/dma/ops_helpers.c                  |   6 +-
 mm/hmm.c                                  |  19 ++--
 mm/kmsan/hooks.c                          |   7 +-
 rust/kernel/dma.rs                        |   3 +
 tools/virtio/linux/kmsan.h                |   2 +-
 26 files changed, 306 insertions(+), 255 deletions(-)

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1755193625.git.leon%40kernel.org.
