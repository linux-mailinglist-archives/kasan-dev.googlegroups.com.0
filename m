Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBMEIYHCQMGQEAXAXVIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 90101B39C0C
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 13:57:37 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e96d57eb1d0sf904630276.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 04:57:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756382256; cv=pass;
        d=google.com; s=arc-20240605;
        b=MMzQHRqCBmBTFZ4jkckLv3vSdiXSkHB1II4AeuBldhHzrhVWLXt6/I+s2ZnY+0rV6e
         4zOighiwrOckFDdLrKbLXq6MVGJF63n1bcFeO5mBsz9JSQN9DlnIevgZXV9vn4Ef5Jze
         mb6TJYKboTRhx2h7r8VlJqxZKp+rKocnvMo5/XB/BKnU2YlmpZT1Roj4PZJirXHIOcPK
         BSBh4QcoPk72GVhtZrWWrEYuJEol/UXfUdFM3tmSTyutDa5/QSUUd5Gun9oEXvO8oEGJ
         HlFOkuVRpTRpbW+cgi7TPR29QjYvACeiBe8AUWWK7ZWC43uU8Z0OQEQ3iTh8p90moLiP
         SdJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=LNlp3cWLSYeroRuLd81bFfUBBokUxJXstTzR32JDmUo=;
        fh=mvtEsP/Uk02und6oHieKUN8hXts0Rb0RMFqezylcXK0=;
        b=aPCKh7EWwovfdaTG7pE+tm04eAjT4JsmrhUE4BQ6ffvYquk57ZlOlSloGAaRCGNFIH
         DhpgtUgIjP2Q7t6eapOOuCRhTr2RPQn8ErcAf9OdUJ/bL8B+7sGz1uRiLZ/Vy/cOg+Bm
         lC5FIcFA1jbAqJJ3sUyTUnA3EMyqkkIw4ay9yi+iOltEKE6azH3F+Hvbm4hLYVoS+Wr4
         sX9b8XptKLJ1v5I1/waTZGEEBbmxXrA93EA50U4DjoBYI8tRE5yhxsPrIcBNwhlxXnD0
         XoPSvvwWBvQnBvVAC2k1a13BpOehmeAj2MevF9ZwFWC/AK+8aIcfA176SnTzPyMw3x/z
         Zegw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OqLtXq0g;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756382256; x=1756987056; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=LNlp3cWLSYeroRuLd81bFfUBBokUxJXstTzR32JDmUo=;
        b=UBQx/A658H9gLhHiUYciwfp1/A4Qf/c4foDy3cuCWOnRlyBFRMKIUjibrq8nUEYr+g
         JaYMYOLeRq92i0UyptQzQDWPpJyjDF1nFgAC7i4ZNwLwHHpt90yarspjXJzOKbZK2jxO
         EtInU2FXTHrvef6QK6UMGnWmk+b1hGhaPQ0Fz84ygRLByXLeTrnIxnYU2Pwv5G5SZD5j
         D4plOVEoLOJonGc9wgt8F0J8cI05osIvuY8AMqlMQsHiutxV+V2r8vufSS2KDN8He/Ec
         qUBehqn5kpkMLCtnR1oa+Fo68goisdPB95wq+aLVr7STSCrVkxjmuMbxnZQq87FsgKpR
         AXCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756382256; x=1756987056;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LNlp3cWLSYeroRuLd81bFfUBBokUxJXstTzR32JDmUo=;
        b=QEEPL/+IdvFKF8A8VEcNydp1iirJAFA1oW/ObPtpK6NnHDHjcm4gno8fKUJkVIGnOI
         gV6McDZElM4M45hlw6pNxIzSelT4JuGrHukiy1HzmKgS0B0tC7cmz2wNzba+k3eGz31m
         THEKTJZDuK4w5uefdtWdG1ZvuMSufsbA73nFc+iXwXdbNO7ol5K9Y49tP9uoBeghyGQn
         roXA3HGNzzilqMckLgN2PksWmpuCPw2f8W5msYRij4L+O0YXQ7GIotdigeoH4iqHxK4X
         UydUvfP9eQVYb9lFr24L8ddHu8bqZKAzzprIYiu5PyrjQD0pyhmYCE6C+dCJ/6niKr1p
         8sRA==
X-Forwarded-Encrypted: i=2; AJvYcCVgl+MLIdAOB8ZbPk5QEUrGVqlN0586yADdNAjRhJ5XzE+lxQ2CwzfzqdPH2HgfoIHpmKGfwA==@lfdr.de
X-Gm-Message-State: AOJu0Ywow5r9CIbmn3k3WPuQdJEA6GhzV5qBa2QsDNFiAnwxzMh2hfBc
	/tiB+4LP1g9s4qKuZmq2pyXqRK31XJ1hmOJAxLGJGhEc+JeQWDqky0Rj
X-Google-Smtp-Source: AGHT+IG/Vsu2eNob7Ds7r/Y7pMZaCzLWQkm4k17MXXss/qCDbpPsBl6slTitVNVkXS6z3DHoC7KKPg==
X-Received: by 2002:a05:6902:2b86:b0:e97:6a:90f3 with SMTP id 3f1490d57ef6-e97006a9902mr3371694276.21.1756382256298;
        Thu, 28 Aug 2025 04:57:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc5Pt1jgf4gVsyc+DaZv4ZXXLSPgSWDZk7AlIx+P/Gf8w==
Received: by 2002:a05:6902:a06:b0:e93:3de3:82c9 with SMTP id
 3f1490d57ef6-e9700a8a980ls827256276.0.-pod-prod-08-us; Thu, 28 Aug 2025
 04:57:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUsXW5eOMvAZwT2qoVyAhUwQhMtA5twFr6q4vJHmPeNzMb74lG5iqoX1CCRLwt0p31z/wCgdQ28CNY=@googlegroups.com
X-Received: by 2002:a05:690c:fc2:b0:71f:ff0c:c95b with SMTP id 00721157ae682-71fff0cf3b0mr213834237b3.14.1756382254997;
        Thu, 28 Aug 2025 04:57:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756382254; cv=none;
        d=google.com; s=arc-20240605;
        b=QdWdkEjssAwEMsvHJyhSxrbq5ivwVP755/f91Dz534BencI51fj/ClyGK10wgnJx6L
         F7bxnIH9nJ/JiHuJA/Y34RNCHkPtBmRt0yjJUA8yfeOO8xZUnam+1a0s8p/DB2Zq8oM0
         dCr54EdYAo9h36KNQAqJKvE0n5hzQ0sGELglP+eH5raWgm7USxkQNr5RyrzWfYbmAxXU
         f4gBeK28uiNqOEI79cUQ4i9PzPTeeaewv4WYJrWuBHw1FD7QA52aOhzgy9fJc3cDkt+t
         FNHto6IeV6VUT8ZkOmgXAPXU0r+v49SscfOxEhw4iDoi61O2bCCl6bZJZDE7egeOGAvm
         /M8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jBKvGDDakYGcFCOIMrtxoT/Y5g/H8pKchV2rdUCvrxw=;
        fh=iu7vSg1EzzlrRbrwbQPzfF0RoV1Uw6GXAom/pnqIJaQ=;
        b=RlDdcmJGLWT7uu9Uc7LuK1Wjak0l/QdroLMB0sc78ShH+U15/6sUpfgeX+I5lXzVpG
         IlEzFIOkEK8+Y6+LDXwexSR/dPF2THGOrti7hoV1fi2voD1Jw0zAi3Y9llJDtHLCNkTw
         1DR35oJaHZBjPO+60ZFHLhTgF95IxqQRFP70E2khCpziAFQyHn7+/xXSwmGAciB6JEiT
         ZO9DQgYLcUcbxvESWPT/0wI7jTD7hr1niidkfwat3XB+J5n+gCgvkCIVJF8AUVRF163/
         CY7gq7pRpH96Etx4EX9gfiGrB2vEBDpxIRYtH5Gq+QtCgAR6iYQgJbmPmV+AHRuuI7WK
         Qzyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OqLtXq0g;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-5f8ae7ef907si488731d50.0.2025.08.28.04.57.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 04:57:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id EABC440888;
	Thu, 28 Aug 2025 11:57:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E94ADC4CEEB;
	Thu, 28 Aug 2025 11:57:32 +0000 (UTC)
Date: Thu, 28 Aug 2025 14:57:29 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
	linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Subject: Re: [PATCH v4 00/16] dma-mapping: migrate to physical address-based
 API
Message-ID: <20250828115729.GA10073@unreal>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OqLtXq0g;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Leon Romanovsky <leon@kernel.org>
Reply-To: Leon Romanovsky <leon@kernel.org>
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

On Tue, Aug 19, 2025 at 08:36:44PM +0300, Leon Romanovsky wrote:
> Changelog:
> v4:
>  * Fixed kbuild error with mismatch in kmsan function declaration due to
>    rebase error.
> v3: https://lore.kernel.org/all/cover.1755193625.git.leon@kernel.org
>  * Fixed typo in "cacheable" word
>  * Simplified kmsan patch a lot to be simple argument refactoring
> v2: https://lore.kernel.org/all/cover.1755153054.git.leon@kernel.org
>  * Used commit messages and cover letter from Jason
>  * Moved setting IOMMU_MMIO flag to dma_info_to_prot function
>  * Micro-optimized the code
>  * Rebased code on v6.17-rc1
> v1: https://lore.kernel.org/all/cover.1754292567.git.leon@kernel.org
>  * Added new DMA_ATTR_MMIO attribute to indicate
>    PCI_P2PDMA_MAP_THRU_HOST_BRIDGE path.
>  * Rewrote dma_map_* functions to use thus new attribute
> v0: https://lore.kernel.org/all/cover.1750854543.git.leon@kernel.org/
> ------------------------------------------------------------------------
> 
> This series refactors the DMA mapping to use physical addresses
> as the primary interface instead of page+offset parameters. This
> change aligns the DMA API with the underlying hardware reality where
> DMA operations work with physical addresses, not page structures.
> 
> The series maintains export symbol backward compatibility by keeping
> the old page-based API as wrapper functions around the new physical
> address-based implementations.
> 
> This series refactors the DMA mapping API to provide a phys_addr_t
> based, and struct-page free, external API that can handle all the
> mapping cases we want in modern systems:
> 
>  - struct page based cachable DRAM
>  - struct page MEMORY_DEVICE_PCI_P2PDMA PCI peer to peer non-cachable
>    MMIO
>  - struct page-less PCI peer to peer non-cachable MMIO
>  - struct page-less "resource" MMIO
> 
> Overall this gets much closer to Matthew's long term wish for
> struct-pageless IO to cachable DRAM. The remaining primary work would
> be in the mm side to allow kmap_local_pfn()/phys_to_virt() to work on
> phys_addr_t without a struct page.
> 
> The general design is to remove struct page usage entirely from the
> DMA API inner layers. For flows that need to have a KVA for the
> physical address they can use kmap_local_pfn() or phys_to_virt(). This
> isolates the struct page requirements to MM code only. Long term all
> removals of struct page usage are supporting Matthew's memdesc
> project which seeks to substantially transform how struct page works.
> 
> Instead make the DMA API internals work on phys_addr_t. Internally
> there are still dedicated 'page' and 'resource' flows, except they are
> now distinguished by a new DMA_ATTR_MMIO instead of by callchain. Both
> flows use the same phys_addr_t.
> 
> When DMA_ATTR_MMIO is specified things work similar to the existing
> 'resource' flow. kmap_local_pfn(), phys_to_virt(), phys_to_page(),
> pfn_valid(), etc are never called on the phys_addr_t. This requires
> rejecting any configuration that would need swiotlb. CPU cache
> flushing is not required, and avoided, as ATTR_MMIO also indicates the
> address have no cachable mappings. This effectively removes any
> DMA API side requirement to have struct page when DMA_ATTR_MMIO is
> used.
> 
> In the !DMA_ATTR_MMIO mode things work similarly to the 'page' flow,
> except on the common path of no cache flush, no swiotlb it never
> touches a struct page. When cache flushing or swiotlb copying
> kmap_local_pfn()/phys_to_virt() are used to get a KVA for CPU
> usage. This was already the case on the unmap side, now the map side
> is symmetric.
> 
> Callers are adjusted to set DMA_ATTR_MMIO. Existing 'resource' users
> must set it. The existing struct page based MEMORY_DEVICE_PCI_P2PDMA
> path must also set it. This corrects some existing bugs where iommu
> mappings for P2P MMIO were improperly marked IOMMU_CACHE.
> 
> Since ATTR_MMIO is made to work with all the existing DMA map entry
> points, particularly dma_iova_link(), this finally allows a way to use
> the new DMA API to map PCI P2P MMIO without creating struct page. The
> VFIO DMABUF series demonstrates how this works. This is intended to
> replace the incorrect driver use of dma_map_resource() on PCI BAR
> addresses.
> 
> This series does the core code and modern flows. A followup series
> will give the same treatment to the legacy dma_ops implementation.
> 
> Thanks
> 
> Leon Romanovsky (16):
>   dma-mapping: introduce new DMA attribute to indicate MMIO memory
>   iommu/dma: implement DMA_ATTR_MMIO for dma_iova_link().
>   dma-debug: refactor to use physical addresses for page mapping
>   dma-mapping: rename trace_dma_*map_page to trace_dma_*map_phys
>   iommu/dma: rename iommu_dma_*map_page to iommu_dma_*map_phys
>   iommu/dma: extend iommu_dma_*map_phys API to handle MMIO memory
>   dma-mapping: convert dma_direct_*map_page to be phys_addr_t based
>   kmsan: convert kmsan_handle_dma to use physical addresses
>   dma-mapping: handle MMIO flow in dma_map|unmap_page
>   xen: swiotlb: Open code map_resource callback
>   dma-mapping: export new dma_*map_phys() interface
>   mm/hmm: migrate to physical address-based DMA mapping API
>   mm/hmm: properly take MMIO path
>   block-dma: migrate to dma_map_phys instead of map_page
>   block-dma: properly take MMIO path
>   nvme-pci: unmap MMIO pages with appropriate interface
> 
>  Documentation/core-api/dma-api.rst        |   4 +-
>  Documentation/core-api/dma-attributes.rst |  18 ++++
>  arch/powerpc/kernel/dma-iommu.c           |   4 +-
>  block/blk-mq-dma.c                        |  15 ++-
>  drivers/iommu/dma-iommu.c                 |  61 +++++------
>  drivers/nvme/host/pci.c                   |  18 +++-
>  drivers/virtio/virtio_ring.c              |   4 +-
>  drivers/xen/swiotlb-xen.c                 |  21 +++-
>  include/linux/blk-mq-dma.h                |   6 +-
>  include/linux/blk_types.h                 |   2 +
>  include/linux/dma-direct.h                |   2 -
>  include/linux/dma-map-ops.h               |   8 +-
>  include/linux/dma-mapping.h               |  33 ++++++
>  include/linux/iommu-dma.h                 |  11 +-
>  include/linux/kmsan.h                     |   9 +-
>  include/trace/events/dma.h                |   9 +-
>  kernel/dma/debug.c                        |  71 ++++---------
>  kernel/dma/debug.h                        |  37 ++-----
>  kernel/dma/direct.c                       |  22 +---
>  kernel/dma/direct.h                       |  52 ++++++----
>  kernel/dma/mapping.c                      | 117 +++++++++++++---------
>  kernel/dma/ops_helpers.c                  |   6 +-
>  mm/hmm.c                                  |  19 ++--
>  mm/kmsan/hooks.c                          |   5 +-
>  rust/kernel/dma.rs                        |   3 +
>  tools/virtio/linux/kmsan.h                |   2 +-
>  26 files changed, 305 insertions(+), 254 deletions(-)

Marek,

So what are the next steps here? This series is pre-requirement for the
VFIO MMIO patches.

Thanks

> 
> -- 
> 2.50.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828115729.GA10073%40unreal.
