Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBX7MSLCQMGQEQ2TO4VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 63131B2CAC6
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:37:37 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e931c30dc0esf214993276.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:37:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625056; cv=pass;
        d=google.com; s=arc-20240605;
        b=TfuhTdVOfRHC5WNat0Hpqft11VoDyvYFGvhwIwZolTTRAzO70/smPlctlJ2HIIvyk8
         mxv1JnAH746yMwMRSjZP5bgJLv3rX3z0rr+VuvN+j5MiiwrKjx1Mhbb1Ad4rV8mw3jhw
         w1ngNCAGricIM8bjNMDvJIyOI5lel2/8aevnpZ1q0B+uwXmqb92YhzzmXhbkLTjsve9t
         gJDAVq+bEWLdZuObi7IdfdM0JAIt/K5RRWV5XRRqQI39hNUcTSoxb1U0bTYFNTB+Xj7r
         ztk9k+A8OvpRixZF2928zSFvRNvjSNmbrm3Dib2EuAnaC6e9jf3R+QI+6RpurRpXZdiH
         TDCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=PIs64xa32ojZe5skOQ1jaTf0pHWdBSLpctvpfYVD1wE=;
        fh=GoTonKwv6QMAAYX/S+5J5YCxk6C9RsS/zboY5502L44=;
        b=hG8lgDPH/mAIuKmHqPQcea8Oc4aNZW3G1+4ddMNNoJOoNU7zyFAQ+HE0qlf8oH04RR
         2qE4mWYw506DkbLfDBX1bYOtG2GPnsW4dsSeKl3QCady071a9JqReZRvEdenboozlKju
         T0gUom5gemHFpTKnBD+tE2TFMsU19a/KWXfpcmRS+9lHJMA+XrUwpNH0c9v4y+wrvP2S
         7Oj4gXRAZXw493bc6jd63MqUrm8lHLSOZ6Zz6FEsmeqvDV77RGlilREjuqcPMCuq83i2
         JbJYyeAGU+ypY0UtIGs01EnvHtiMQMMDVLDyIaLYkJepnlgRawV8aoaGTYhkPxf5yZcg
         Kchg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nt8pdRow;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625056; x=1756229856; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PIs64xa32ojZe5skOQ1jaTf0pHWdBSLpctvpfYVD1wE=;
        b=sPYfjCdhqs/FbE8sqAqg5RJoSEXtdS96oyW9aUOplVx0nzbQssa0/HgCWCQ82vg5Yz
         iLZaOWclkrx25kExj4o9oSHuvPtf1CSxKwU6NlVVSj5Djvuu4yWWOT4etsR+E+yHZ0Do
         VRPiP6vOyHz1+XQR1/7Mw6VK0uEkgzqQupyAdFlMxNtYi5Abm381G9Ltx5thZHmfdz7H
         cazJIi6A4bb8eBQmWPjWgJvoWKAmwSEZwdWFrvVQ2hCVDb6WM90o7PCNwaKym2IxCZuu
         mmA1IM/YKFc5IryZ+TVhBCBexLyxDOD8Sf56kPn36dW2JgbiemN0ZUFM7O2aa9dfI6/r
         V74Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625056; x=1756229856;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PIs64xa32ojZe5skOQ1jaTf0pHWdBSLpctvpfYVD1wE=;
        b=iDVW7wuvVGnNrwJVo/GqxMLdVkg/kdYDGzd2+b4QoDAwk1DIS2YDbVcJidlCB/A/ge
         Pk3TUf6A6oHMPLP8RCkuFb5IbjJO3s4n/6j2zPQGOPj4bbJ1LN0cSYLLF4t8+c9qLwxM
         HwiK9KA14Q3nQLhwfJzNoT6/pgPwNoXLag06MMKrhJ51e7amV8AWQJfi+VcDMWWIgd1D
         7vv7XIIlDauHzwz1YjgcxQ805IPtdhrjiz83KXsnShQ29g5O++ZiRH7kBgy3CWFQXCA/
         I25YCiryRFfqkK/2lkyUboPn2lzK8lFoQf5oTm/HjM2YVNFLaFaP7HcdlM4pjhJ3sfzX
         Ahmw==
X-Forwarded-Encrypted: i=2; AJvYcCUN4rYFrW1ges0PCkSak84ARSMx3DyyPaL3A5sD+KegZ/5fV5EObhv0V/tU9AbHh/ApMuDbwA==@lfdr.de
X-Gm-Message-State: AOJu0YyYJS80B8mk7eXBWcajx2ziyyTiPIXqn+NtYt2bNHeOgaquAnsY
	Y7TUSkWneB/nxMPRB8ImKGIKp6LjowegNGqBRv8PPkIkX5/ccnqsffyt
X-Google-Smtp-Source: AGHT+IE+qcRY6CUUdGCR5IBtnGicWwoHaxvK2yNmUchSJQpu6KN8YgxiyHzAnCiL+IQzMqJ01XFwmg==
X-Received: by 2002:a05:6902:2405:b0:e93:3b23:af31 with SMTP id 3f1490d57ef6-e94f58b1b01mr240092276.10.1755625055880;
        Tue, 19 Aug 2025 10:37:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfunLxyhGmTz1xLi0FHpxyiZjiHPqcj3Lhgmz52goGXSw==
Received: by 2002:a25:ddc6:0:b0:e93:4930:85e9 with SMTP id 3f1490d57ef6-e94f526a63fls59516276.2.-pod-prod-00-us;
 Tue, 19 Aug 2025 10:37:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVzzfI4T6/rS8lPpxNpz/GbsriFOs4LTM2Xki6vKBtk1dR7ESfTOTtKBVL6HiJepFRHNvsSWAkSjcA=@googlegroups.com
X-Received: by 2002:a05:690c:a00e:b0:71f:9a36:d333 with SMTP id 00721157ae682-71f9e595310mr29948647b3.22.1755625054546;
        Tue, 19 Aug 2025 10:37:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625054; cv=none;
        d=google.com; s=arc-20240605;
        b=NyZypdAdM9RMsO27OSXB8N1Ef1CI7suHzuNatBTs0PdcC6yr/uHt4wRQDF06DZvAHL
         Z8fSkxkz64V9GsWeWP0MQBA0aJR3a7yquxsmf/xcPa/5blcu9r+nSb9Wa2p4I0L6v7fw
         7wZA57RAscRZzCW8BUT796vHfth1oY5h2RagfSL51/csnoCDuZDx8GSOTMrlvMtOlszp
         FQPKbphFLWq6k/Fy60stWOgM/0iPbMJZ7Qplte30Ar+60m2DePz2GRd1cTBFoRU9Cuan
         TzVPmV0yRl95r6qzMVt9+fj6zSXZEsyEyVkbeeQ9r0pdl6tNFmMXuQrnZTjjhHOsVB2p
         FapA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=V7lyGHPVpToHBO4xk7veSlctoonDh3C6qltAZuVkH4M=;
        fh=iu7vSg1EzzlrRbrwbQPzfF0RoV1Uw6GXAom/pnqIJaQ=;
        b=Cq5NEc2bP/av3IQNpfibNwHAXUQ7gRy0WOE+Z0NcsSBQB3wGD0KkYPWOU5y0GONhpB
         PSVTJEWnS64kPwyYJd7/pODso3bwapqIADk8wQ7p+U93JOZUCs2asnN5oxGmP8HtI66C
         Dj5+fWIIBRhvoTSwhgEA2pEF4z/8Hy8Lzg9DSRTc70h6CX14N9zeo+ZGdNhj6Ij1S3uS
         8T513Zo29cIeY9XVSyONnq/uNeHvZxtCrZqw6e9FPE6yHt/Z0B2BXZNEm48a2H9/NLg+
         Sr8dm9MIcch1w1xdcuT+Oo2/o1MWVgXRaJ7L+bxD/pCONt7VMLJ1ABCg1GzhVTI0RU1p
         7F0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nt8pdRow;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71fa513c048si595697b3.0.2025.08.19.10.37.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:37:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 176855C64A7;
	Tue, 19 Aug 2025 17:37:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9C7B6C113D0;
	Tue, 19 Aug 2025 17:37:21 +0000 (UTC)
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
Subject: [PATCH v4 00/16] dma-mapping: migrate to physical address-based API
Date: Tue, 19 Aug 2025 20:36:44 +0300
Message-ID: <cover.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nt8pdRow;       spf=pass
 (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as
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

Changelog:
v4:
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
 mm/kmsan/hooks.c                          |   5 +-
 rust/kernel/dma.rs                        |   3 +
 tools/virtio/linux/kmsan.h                |   2 +-
 26 files changed, 305 insertions(+), 254 deletions(-)

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1755624249.git.leon%40kernel.org.
