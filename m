Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB4WWQDDAMGQEJQG2IDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id E29D0B4FCC1
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 15:28:20 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4b32d323297sf133695411cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 06:28:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757424499; cv=pass;
        d=google.com; s=arc-20240605;
        b=eL9z0931G97NufuA4cwKYb5Jzndy69aJQoymlkjqAwv+i/qZJF0UhgIKT/nn28FmiF
         8po3EgwqH2KoP4W9ODSGBYjpDNQOQAaKk3D7XSBI3bvBIA6CGxLaOXez3qpSnxqmxU8i
         h0RmxX9rPIIwLGwoQBZjlI2yF8l8b5Z3x8nPp3/FC9EheM5PfYLhAWnxxUstnvdg7plk
         SlV0MKMGw2CsG83Amv2+J7AuwPm12+rW1S0UWdGShWQmCxFnD72UZAwerLFg2i3DB8xQ
         o9lQ43MPmvDu0pwSySPVjnMeMhp0RMXaq4sM/DSlwpvK4lsTOMprz055kz2zJVTYQ/1o
         bgvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=x7zlqXTxqLTpMO6e67LIwvhmLdNM3bKwGEjnL35davk=;
        fh=ygoOncQMBPFutvlQxtjA/VrygYeRGKDfj9vF2uYUQao=;
        b=aZsfmewxUUYjJBgHpsMRBrnkn746zu+PO5Aj5ChseY48BlZVh1DC8ItX6ecJwuoC1e
         MmE/8sGrIx42QuBbiojkw6bSCPcsE2HdcSrGuIfSQJB6fgZUDkc2ITVr9MtLeOjhP7wM
         WFbAs/Jz3YathEUAaO/IN6Tjw170DrlzHYQG4Nz0A1DEpDl4Sf0r8GGLm4fyrFXxP4/I
         h7VYXIUehvbz3KZNB6JPivADVLi+2VSclPuTDumHEEWJIXidE14dcY84dEzfHgoBQcPP
         mcgVSDBHiHs9mECEGcE5N0oEBD1D1wOQbFfmFWYZyQYq2rmihlXH15O8DMT4dfS9l8Os
         4Zjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fdb2HzRe;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757424499; x=1758029299; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=x7zlqXTxqLTpMO6e67LIwvhmLdNM3bKwGEjnL35davk=;
        b=OZsAv+/9vkft7oZOzvQSzhw2y8gvdsVquda55LznLlcTJaqwl4Irn+Vm1oJzJ647s/
         tcjEF6nVB6Kn7wvMk6c0I+TBPYfG3cdVn2CsXj8EriMIk44gK6oiWr/J4xSomwZBO18e
         43T6hpU1uuQFrOcEiX8fB0rSSMKRfAcLcZtynetO7vinDUNTgjNBr+DqJCfGZLRZE66I
         BYRXf5p5JRTJo43V8YBsa/q7a72wU6boKAkI0xtWucAE8mKHfZYfPvaxzEXLMlEzPZ03
         37TlgtOWbo3fUjIdu2vwT8iD5PF/Geu/JBJCcRnYOM2u0WK7haznOaMrjXzFUHrQBrLc
         gwkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757424499; x=1758029299;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=x7zlqXTxqLTpMO6e67LIwvhmLdNM3bKwGEjnL35davk=;
        b=glqYf18USJuIaV+Tchjk5cdpN5lg1jBox3QPLc2jkwNbTqrLl1Yc2Am/QaLwGDbm+F
         u+N+rHoa/7FdVf7KLS4/mLry76p7EAImJNoyODQKIYp1PSG3JrG5jB+4KgHxRSYIoKFe
         GxfcB5H9V5Ba/6Gs25WuXIGdtuPk6IaFhIFNvrJ77nbbpESUfUVRAB/qH2+Enn2PTB6H
         38Rbqri/v5RmPEq+MRy/fa2anS7mBdKKs1xyKDGEOWBOPVcjxW2YX3ye74TkdRKPS50b
         22L7Q8s9wjcNI4BbmSec77Fw/DfDCK3v8NzE+QHDQffffhCryTOyq7vLv/5Ou/Vn9MuJ
         EB5Q==
X-Forwarded-Encrypted: i=2; AJvYcCXNVPigsjEFWdg7Rri58Dv1iAo4GUBDQSpc/FvRup1ssw2zn7zu5+JfLooGm7Gn1N6Alipf0w==@lfdr.de
X-Gm-Message-State: AOJu0Ywdju4s+FZSqV3u2RL8SjequcHgWaXsqJSlds3O4tly8czE/MKd
	tP0cNsqFzotqRFQEAkNsvQKnHRtvvsyMCCG5tqjQ4YFQiHc1KiDKQN8C
X-Google-Smtp-Source: AGHT+IE8OvGJBFSMuc8oBfLbsD1vc3Lb8Z8JSGfmJx0HexBQ1IrrnmogDtoMWgTbOJ2cy/JJDhkY0g==
X-Received: by 2002:a05:622a:1:b0:4b5:eb7b:277c with SMTP id d75a77b69052e-4b5f8385fdfmr106139881cf.1.1757424498304;
        Tue, 09 Sep 2025 06:28:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdDYTsjXHr9Pi4FCQya5TnOplqjHdlHBTGBN70nwU+R0g==
Received: by 2002:a05:622a:1893:b0:4b5:dc6e:c1df with SMTP id
 d75a77b69052e-4b5eaa1a582ls91817271cf.2.-pod-prod-07-us; Tue, 09 Sep 2025
 06:28:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUHdpsWI5lWF/5kprlio8xuiBvm/pF9wq3Cqhlb3SFDFcR8oG3zlDDqXENIiy4vxLB/C1fxKGl5DB0=@googlegroups.com
X-Received: by 2002:a05:620a:2552:b0:7ff:9fdd:c342 with SMTP id af79cd13be357-813c2ef9fe0mr1116489685a.56.1757424496837;
        Tue, 09 Sep 2025 06:28:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757424496; cv=none;
        d=google.com; s=arc-20240605;
        b=MKxQwuWh69LvIHuvwBO458fwmlnuwbd2akdxc+u5bWUV1BsagCIP6Z1JGvd7D38Hgo
         F+T+aVTJEoWXoeU/ooiy76TxsDe4qj5SUuXqE1Z9KbHekc78Kn7/Pw/uOq5O8Wg/LMLz
         7scG62WIFa/avfJMircuWdju9qXSvxSyQ9F7f5iHl+l9FdoscjT+zuldlUDqEpkrPFqs
         U7wj//FcaxYrj4DB6EmY33VJ1neKnH+ntp/YAoYKWZ129YJz/l0oWYQ6buK2UJCLFNaz
         eawNqtzQV4yMwnW8Bks5iAvlnzdtePcf0gb1izpbNsSaNz1hfMdmOG6VYzH2kLMuy9xE
         MYww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=jF2Z86mm30me7y7MFS3s7L7Ykf5ztwV2i6zaG00nN3E=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=HxDDpfdsV7tKXiAKfQtQCo2+RnjpWX8CRWGme1exdsZsGS87CsomvoJPpp+yulMx9f
         Me8DKaaPzwGQQkg0RCX62EvCWLBSOUU/Jku6a38QjEPPbB/iJtAKV+c2lbxHeV31Ruie
         avfsMH9zBLripOPQ8iJke3Y5JeSeGWZ5d4juWunbJv2WcBld1p+rXl60EcvPCl38WCED
         pgrFok5np9pHImHqwFjEepgFlApCE06NRxTSevJJ4Vn9fRIlosT89noAIUa9phhNQKUI
         JQQitaEBw194qLTHnfCBCR/M9rRRwJyJwqISgvTqyyVokETuLSykzInNsuNHZAxsYnCo
         h4Xg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fdb2HzRe;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-81b5c31e722si8317585a.6.2025.09.09.06.28.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 06:28:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id CBC5340951;
	Tue,  9 Sep 2025 13:28:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 06301C4CEF4;
	Tue,  9 Sep 2025 13:28:15 +0000 (UTC)
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
Subject: [PATCH v6 00/16] dma-mapping: migrate to physical address-based API
Date: Tue,  9 Sep 2025 16:27:28 +0300
Message-ID: <cover.1757423202.git.leonro@nvidia.com>
X-Mailer: git-send-email 2.51.0
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fdb2HzRe;       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
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

From: Leon Romanovsky <leonro@nvidia.com>

Changelog:
v6:
 * Based on "dma-debug: don't enforce dma mapping check on noncoherent
   allocations" patch.
 * Removed some unused variables from kmsan conversion.
 * Fixed missed ! in dma check.
v5: https://lore.kernel.org/all/cover.1756822782.git.leon@kernel.org
 * Added Jason's and Keith's Reviewed-by tags
 * Fixed DMA_ATTR_MMIO check in dma_direct_map_phys
 * Jason's cleanup suggestions
v4: https://lore.kernel.org/all/cover.1755624249.git.leon@kernel.org/
 * Fixed kbuild error with mismatch in kmsan function declaration due to
   rebase error.
v3: https://lore.kernel.org/all/cover.1755193625.git.leon@kernel.org
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

 - struct page based cacheable DRAM
 - struct page MEMORY_DEVICE_PCI_P2PDMA PCI peer to peer non-cacheable
   MMIO
 - struct page-less PCI peer to peer non-cacheable MMIO
 - struct page-less "resource" MMIO

Overall this gets much closer to Matthew's long term wish for
struct-pageless IO to cacheable DRAM. The remaining primary work would
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
address have no cacheable mappings. This effectively removes any
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
  iommu/dma: implement DMA_ATTR_MMIO for iommu_dma_(un)map_phys()
  dma-mapping: convert dma_direct_*map_page to be phys_addr_t based
  kmsan: convert kmsan_handle_dma to use physical addresses
  dma-mapping: implement DMA_ATTR_MMIO for dma_(un)map_page_attrs()
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
 include/linux/dma-mapping.h               |  33 +++++++
 include/linux/iommu-dma.h                 |  11 +--
 include/linux/kmsan.h                     |   9 +-
 include/linux/page-flags.h                |   1 +
 include/trace/events/dma.h                |   9 +-
 kernel/dma/debug.c                        |  82 ++++------------
 kernel/dma/debug.h                        |  37 ++-----
 kernel/dma/direct.c                       |  22 +----
 kernel/dma/direct.h                       |  57 +++++++----
 kernel/dma/mapping.c                      | 112 +++++++++++++---------
 kernel/dma/ops_helpers.c                  |   6 +-
 mm/hmm.c                                  |  19 ++--
 mm/kmsan/hooks.c                          |  10 +-
 rust/kernel/dma.rs                        |   3 +
 tools/virtio/linux/kmsan.h                |   2 +-
 27 files changed, 312 insertions(+), 264 deletions(-)

-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1757423202.git.leonro%40nvidia.com.
