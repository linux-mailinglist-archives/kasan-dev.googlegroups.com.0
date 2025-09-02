Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBY4H3TCQMGQEGBMF4BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D097B4078A
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:49:09 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e96f7d36f4fsf6058765276.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:49:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824548; cv=pass;
        d=google.com; s=arc-20240605;
        b=CZ13u4Omg9WmJKCVii0FPoE78DQJQmZto/06vwMY9uSZHkK4TsSI32wfpzdxtih+vo
         YGzJ41b2t/8NwnTkyFqip+b+WK9n402rClIEDr7gxawJZuzFwjh0FqphoTorph28Dy2L
         VE3NcFMqJ9pQvmNS+YaaVWyW6iAWqT32apbo9uuaSUySkBLdLUK3B7XiHCqzAkUOJCLt
         PA3x0Xr3qwhQOCic0L6HdWy/3HaxkYsDtcsRgX1to81dIskjBz/nN4dZ07dIUC4cKXlJ
         ajW+DUxU2nprDxmOKTM7Ljsh8FIETm9lxEMVYUI2q9+scLtsfNl0rnhGd9CosLunh0av
         AFvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=wnDbRfxhC8kUn1slDOyp1wCAdhHdX8hloDYKp+kgrcs=;
        fh=oCPX/Wg0mCNGathGfTzAHNjq3mNAA9OMGX3xblLisJw=;
        b=RZ9ngpGwxHJ5s7DAvb1b+WbaR/S/ORze2ANNYWCwC3C2ETKd186l3o0lzMKDlP45lX
         6uR0BZtThAc/02ZQ41w1wD7NOMRVLcm2vxPNd0wiXbiCysOe185o5jc2tIH6be/+OObY
         Vu9VU3kGO2khVkB8GFkdg0znHPrjy8xVCopbg9rwlV+QqVbxyz0QfHRdosL30fRv9Pn0
         BhRqJsEb906l23wnLdvsReUnslaa0Q4bB4JN1tsMZFNEVnsfdj4Na2lPhPkNhVIDrnJz
         bxWKObfyyExaO/sUv1QELO+3m4jjnLJFtC435VpQDV7tGrWtevXgYGTwwoAEbeKk6IOK
         pX1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="T4z/viMp";
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824548; x=1757429348; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wnDbRfxhC8kUn1slDOyp1wCAdhHdX8hloDYKp+kgrcs=;
        b=TDLm2bjVdtL2EHVRmpCWm5683Fzj8MHWYy/RzHN/UV6FlwUPWxzdzUpPyl2xKvoQVF
         WYBr/vaUaxie2exeqIAm6yas5ja3KIa/9zZljTmqsDLZg36cEX0caaqbYI9uNpZuBfPI
         o6uFhMA+CF/VE1ofhcIHdmg7//FQcKa4ptGHMy3swA5+uvbHM+v6ImhtNBUSGKZUhLZZ
         N2k01yqDzuBKOGBDO07tx7/Yj2fDOWUQgQgmNw4tUTqtyRo+ffaHv9SBEF4sk9/pEAmv
         3BSbfoqyNZ5GZ6Hq7oWRCNDomcqvugNJpnjhb5cMvk/x/SX8C2Hh+bsHwkuE/FHXRIGO
         u7hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824548; x=1757429348;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wnDbRfxhC8kUn1slDOyp1wCAdhHdX8hloDYKp+kgrcs=;
        b=hvWcYWqS4CxUTU6AcmW+kn6X4wQtAxgSS0RnF5+RIdTDUFNmzmgblCQ/WUC7TvqK3X
         +vOH99zGp62hGstH+8fj6M7CbQe68WBBOHgAt/6+XfIsFpa9J9WBDAzxejzXUHZ3FVI5
         ANY926fWTvnxFYjDOcUzlJJBPu9al1HMjJFNeedvzK2VviMAM1kDxptbLDE1H+up4rcW
         Cg+3C70VZuLPskOhToI/9vJGtUFQ6OG8Mq8xmIeSK5kMiQUsCPpA5sOVA9a4m65jfKH5
         H1GicgajLeYrQ8px0tTsqUIDvhACel+Dz7dJFC+CdieFpg8wyxDoJp9dc5vRRE024FMR
         paTw==
X-Forwarded-Encrypted: i=2; AJvYcCV0hn01TTzK4id/3xFZax19XTVQiiaCHBbVlZlK+w6+nJS6m63ux2Ror1X0USdxbYSQ5cuZDw==@lfdr.de
X-Gm-Message-State: AOJu0YxHARgM3CQ+iHwGZaIzfqlAIyLhcLGI19I6jmhaLmRmVDG1up39
	iBv20f+RzqA932hNkymza2opPzsciApBTh/UMpYL/NcuovtgH8m066Kn
X-Google-Smtp-Source: AGHT+IGvjlt4NNT3Idr+CppN8CfzJEoXO3YikX9NEfo1qt9eZ8GqlM9i91LytGetufynzd+VmxWyRg==
X-Received: by 2002:a05:6902:110a:b0:e98:517a:d06b with SMTP id 3f1490d57ef6-e98a5759551mr10937706276.8.1756824547832;
        Tue, 02 Sep 2025 07:49:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZerdQd8PrREmhrst9Uceb0bovg3V0SHIiGmdsHumPISdQ==
Received: by 2002:a25:7e42:0:b0:e96:dc1b:7905 with SMTP id 3f1490d57ef6-e9700e90ac0ls4956502276.1.-pod-prod-03-us;
 Tue, 02 Sep 2025 07:49:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXW+4mxQoRSgAlh61aiWg15qKkUubnDBMSCtVwmpkcPUzXsE1IZQYRTj+Qw9RvW8RgAU1TyiixYQWk=@googlegroups.com
X-Received: by 2002:a05:6902:2b88:b0:e96:e420:1a1b with SMTP id 3f1490d57ef6-e98a581df41mr13739617276.33.1756824546734;
        Tue, 02 Sep 2025 07:49:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824546; cv=none;
        d=google.com; s=arc-20240605;
        b=lO2m8qZz9aBJH3hu3a6EjJNkQbrI0y10ZbSkjyGwCrOLIHfcPaixdyQ4lzzHlxUezU
         CTkH/iNmb+Gji4vINhr6GlMPWFoNVRn6Du9bHMoXW9a9eoB4zsvMw5dw73cxQmaiirE+
         MOd2NBPNGG9nfVjqUXB5mVUoh8lhp6IAjp3QxGkAeH0qQt8CV1okOz/IkmTv1gLt2p3P
         FOtMvPukh/UUW6gcexfcquMjTm2qP07/43hwis3AyTyY5BxIcZHGWJUbJGsfrBdDi/tv
         GZRfM1CDRFvR4BbbLsJGM18c3Lq/erISYuqe/DxeFm8A9fYY+QWEB2eznUxhf8YE19ca
         pT3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=DjH6W2VoAh0Kv3N0VHTv3PO+Q5Ud4SkBBjk+irt/fhU=;
        fh=0KZfjkVFrBJ1A8P/k5PTY2PAUr+/l0FquzWeYmXM7tg=;
        b=NH88Zs3hIiKbeTbwA/X5DQlPUXVkCiLS9cikP5/cnam/SQC4WiC6RmFucnuF7cu08w
         XhouJ+ujG1hSC1MZHsos8pdDvpyg5SFf3CKTebnK1XnVdeOWjxZl8QymXiSVZXhKldwe
         tDCoAszAgD+xMYR/LKCQQG1ntrH7dMyKR3++SPQsb2NB2n3uXZsthC6L9v3YehF0IVqx
         t0WbIY6pX3e5kc7xtGpbC/BcVROyGwhtQX4iu8nLJF6dWwrbLoaYHtXPq+6RJz4iaRxO
         ccNhAeRlSmi9o9cTBW++LRDb5UtBdr9KGSQdOB3Fy+HLPPXSdZSE4wscXKBWq9SnbXm6
         QqQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="T4z/viMp";
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e9bbf7438bbsi79935276.3.2025.09.02.07.49.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:49:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id DE20A43910;
	Tue,  2 Sep 2025 14:49:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id ACFA9C4CEED;
	Tue,  2 Sep 2025 14:49:04 +0000 (UTC)
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Jason Gunthorpe <jgg@nvidia.com>,
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
Subject: [PATCH v5 00/16] dma-mapping: migrate to physical address-based API
Date: Tue,  2 Sep 2025 17:48:37 +0300
Message-ID: <cover.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="T4z/viMp";       spf=pass
 (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted
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

Marek,

Please pay attention that I'm resending all patches which includes
nvme/blk conversion too. The code is based on clean -rc3, but NVMe
tree got patch in this cycle which removes one of their REQ_* bits,
on which I'm relying.

This is the patch:
https://git.kernel.org/pub/scm/linux/kernel/git/axboe/linux-block.git/commit/?h=for-6.18/block&id=7092639031a1bd5320ab827e8f665350f332b7ce
and this is Keith's attempt to restore it:
https://lore.kernel.org/linux-block/20250829142307.3769873-3-kbusch@meta.com/

So there are two possible options:
1. Apply only first 13 patches and I'll resend nvme/blk patches in next
cycle with the hope that REQ_* bits issue is sorted.
2. Apply whole series and deal with merge conflicts by sending PR to
Jens and ask him to merge this DMA series.

Thanks

------------------------------------------------------------------------
Changelog:
v5:
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
 include/linux/page-flags.h                |   1 +
 include/trace/events/dma.h                |   9 +-
 kernel/dma/debug.c                        |  81 ++++-----------
 kernel/dma/debug.h                        |  37 ++-----
 kernel/dma/direct.c                       |  22 +---
 kernel/dma/direct.h                       |  57 +++++++----
 kernel/dma/mapping.c                      | 117 +++++++++++++---------
 kernel/dma/ops_helpers.c                  |   6 +-
 mm/hmm.c                                  |  19 ++--
 mm/kmsan/hooks.c                          |   8 +-
 rust/kernel/dma.rs                        |   3 +
 tools/virtio/linux/kmsan.h                |   2 +-
 27 files changed, 315 insertions(+), 263 deletions(-)

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1756822782.git.leon%40kernel.org.
