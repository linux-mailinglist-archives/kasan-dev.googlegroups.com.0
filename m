Return-Path: <kasan-dev+bncBDLKPY4HVQKBBA7O7DCAMGQE2S2DTIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 93C78B26F9D
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 21:20:38 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id a640c23a62f3a-afcb7ae03ebsf110705766b.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:20:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755199236; cv=pass;
        d=google.com; s=arc-20240605;
        b=d8MeGpK1t1v1Z7upswH4lymvDGr0Lfy0MeXtatJZpPEHLUneFwaoa/9vzTBXpVHK6p
         ATty3sMs4gGj399mNSH0sXi+oIT8WCT2MbdhLxH1HkSH3ZDZZ1OoZAztBSksCKPwuGaR
         aAdygoViHKevNniC1CxS5fsKTEoAYJMhMbaPc3RircRDVTBtC15TYTGpzjHdNcnxpCff
         PRmKjNX7rLlDD+i8Q1a6hUtmo0fsVsrR+6QRZtxc2T0Gq6ezcUeg9JccCFr6yA7LfeMR
         orZQYibzoo1ysyx3Fext8aF7EV1xruz+CXvdcNt+1th1lQZxx61ZG/melzjsCEp1O/uO
         NCaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=V+Rjkpv41/nwv03dRA/Wc+QS1D6EPFOeTcfMRVS2kA4=;
        fh=Iyrkm3dzdbq9Sz+oOF8uoGl99CsqbgWlDcNic3o1uiQ=;
        b=blQHshBM9YCsFi8Ii5dQaZkAY+f8/eqAKm9gphxi7qA/SNyVhXnAREYntvhOTEWFi3
         bJ+Dl3m7i48L3qTamQ0p/PSN2rZwveP1OE14OgQKynp4Be88uSNyeUrX5+ciXeBkUYSb
         4XmrDAZEuV9YwkI06hXzIRbG2Uzb75g74DMzuM+4ZzQ+zc7XUjYq/2G5mg+JnYPMXBAC
         3o1CUiPgl3g6ZO+WvqVUGLrUvO03iSZJZXB7LZVbuBURdlreaCEKWnjjLzkqUed/4vyP
         B5KPppv5RV+ABsk1im6IDREdpbBza5PUyU0go2nbbxVvwVGTtRYu9cf5EYZe5rIuU3Cb
         MbpQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755199236; x=1755804036; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=V+Rjkpv41/nwv03dRA/Wc+QS1D6EPFOeTcfMRVS2kA4=;
        b=BrM1h2Np06jrEarl6zd6SR8r4tauoRNNsECAdsQSn4WUNC0eiALB23LC/bt/EZHmxd
         BTI45yAgg+xCarfHbfbosH6UAnCOJQMBWlryBynezBbl6ohCSDlHCe888UTUQ3W0iCux
         Cio+OQtScQWxwQnja3rP4imvOqXgmcAjFdfyqJnWLho+yNH003CwMw5BENpufE0e4IFa
         +arlZ0xmWFAYv4HNiOLIzyG3GhUVBvixRdmQJloawz5vU/1FkWAR044Rg9FiKJBDzJH/
         Pv6jHi+DBDQcTNPKNRnzkQmks36rrJ7jh59IR4jyqCbStQLECyfCjg+T153c/63sGhCc
         AxOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755199236; x=1755804036;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=V+Rjkpv41/nwv03dRA/Wc+QS1D6EPFOeTcfMRVS2kA4=;
        b=mOaXIKIlcF668habUq24lEWGsxekQ2rL9e5XTBR1lbX9wQyunD0W2g8Ejwee2GdHjG
         GuepYJ6p84N0KJDhVBj+4M8WvdWfBxV9tkOvUdSCu6TGWO/jNdOJLzGpxQCpyCOKCEgm
         V9O+mdyt64EYHCfoMcjmk//LGLS1/OGa4YlcdCXNuK7h0Fu7eFiG9AfSaoqetx8DyWcN
         bmZFBRsfX1OHSeVnLNi44mPX5JvJhKZfZ2VPW+42LpP+ovqjaqAhMn7Trtc1DU2pt1K2
         YczgaVreTliEC8GkaR0tMF1n66fL5vVaZ79HX+6J/8fjPlDo5uNl7yPPvDCPrVMc9uYH
         +RBg==
X-Forwarded-Encrypted: i=2; AJvYcCW29pxgAaCTO16bRJkVqWWYiGRa/YapDRJUFa/A+Y28k3seWCr6Uzt99ZvbIOmuaiSt7M5VjQ==@lfdr.de
X-Gm-Message-State: AOJu0YxlYC06zJ3QmyQ0P2V2LbJFlSIFYmK+H+9HD6oTw+IZLlivfjhE
	5rDO1Bw1U22iJ7Ed73gCH7gyhrCEfihiV+MBP2mraSpDB5CKZge4MJXy
X-Google-Smtp-Source: AGHT+IGNOVla2Toz/gRAABvYVTzW4ZS+XUp4d9QfSEtDa0ntrmwsuNoOzP/71i0SBF92Aga6QBchMQ==
X-Received: by 2002:a17:907:944a:b0:adb:428f:f748 with SMTP id a640c23a62f3a-afcb97d2a19mr407015766b.21.1755199235920;
        Thu, 14 Aug 2025 12:20:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcI1R0qu+uPfCbvD2guDHLvqUL7sdSPkJlqu/bF/iqQBQ==
Received: by 2002:a05:6402:a0d0:b0:60c:44d6:282c with SMTP id
 4fb4d7f45d1cf-6188a3698d6ls1091558a12.1.-pod-prod-04-eu; Thu, 14 Aug 2025
 12:20:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU1Z2x3ZQapDujxyEboI12EQJqDZc5xl/27wHyS2z5DTOFOWrKLORn4qS3AyKGzqXLth+PzSu8MxjA=@googlegroups.com
X-Received: by 2002:a17:907:97c5:b0:af9:7333:3624 with SMTP id a640c23a62f3a-afcb939811dmr458104766b.4.1755199233069;
        Thu, 14 Aug 2025 12:20:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755199233; cv=none;
        d=google.com; s=arc-20240605;
        b=D/9Omz5A0y2bk7hF6u3TRGnAO83Urj6/XJY8xVn5c80ZTBE8HTuG3SxUSp1LnP6HEn
         dNNaiI3EsveIqPXXkRu1b3+u1rzTD40bvYk/NG/s23nkyZwf5ms8MW+6doRhnlfhowxW
         2UmY/YJThEOcrrwgn/CntOE3oBg1wVi+eM6UGpk7uxDfswdYCUTbL4leyYWRl7FvrjoE
         Evj3XIUeP2ca5N2ZOdrWJ4HdvYsD45XZQWHZB/AOLug/ajRhL8xtY5D2+yJ5BI1pVYZb
         JNOtlEGcT3YB02GwJCwvCK6U3aZmnXOWyOPcplUZaLXBkSlOztSpRy4SCceTUnU+82JC
         y4jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=YHyGC2tklvgN0REkQ0ldTWNmLFHcFMgQsr/26aDn6pU=;
        fh=5p2GrrWlefXKc3++Ng75s105snygW/gKAXxF6wOCiTw=;
        b=T25EjRmOYlXyktB/eHLmmqFDHdzzb9WTLoGqhcEvrHB+t4UmJZdKkKAZHpgrP/Hbsn
         RMlHx0yh1OnLXcObzb/pzJ4AL6mGpZoIMAjstoSbRKjjEIyH+3ywdMswhTQTyaEv1agZ
         IATHbf0yIGUJCErh4gCAaQUs7ivwPH+BXkqqUCj1MyVmf0R3d9hYgPa4LLnfL5hPc+iJ
         boKyrocPHM1c0R4ziQd5kid+EG5xnQkqaxfGIMKExQTtaQtouqblWAlBLo84Z8MfHKjt
         31CsHn8NpptRxa1zZFWcW8OVOxI+yG5l49obt9LkbaV+9FfEiAS9QSdqyRJ7vQcRFabT
         lizg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-615a8f29032si1012588a12.1.2025.08.14.12.20.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 12:20:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub4.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4c2vpK65M9z9sSH;
	Thu, 14 Aug 2025 21:05:45 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id ZPu83EvDtL2B; Thu, 14 Aug 2025 21:05:45 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4c2vpK3P9dz9sSC;
	Thu, 14 Aug 2025 21:05:45 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 16AD08B764;
	Thu, 14 Aug 2025 21:05:45 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id v81OkG88qzZ0; Thu, 14 Aug 2025 21:05:44 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 592BF8B763;
	Thu, 14 Aug 2025 21:05:43 +0200 (CEST)
Message-ID: <ccc8eeba-757a-440d-80d3-9158e80c19fe@csgroup.eu>
Date: Thu, 14 Aug 2025 21:05:42 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 00/16] dma-mapping: migrate to physical address-based
 API
To: Leon Romanovsky <leon@kernel.org>,
 Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Jason Gunthorpe <jgg@nvidia.com>,
 Abdiel Janulgue <abdiel.janulgue@gmail.com>,
 Alexander Potapenko <glider@google.com>, Alex Gaynor
 <alex.gaynor@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
 Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
 iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
 Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
 Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
 kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
 linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
 linux-trace-kernel@vger.kernel.org, Madhavan Srinivasan
 <maddy@linux.ibm.com>, Masami Hiramatsu <mhiramat@kernel.org>,
 Michael Ellerman <mpe@ellerman.id.au>, "Michael S. Tsirkin"
 <mst@redhat.com>, Miguel Ojeda <ojeda@kernel.org>,
 Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
 Sagi Grimberg <sagi@grimberg.me>, Stefano Stabellini
 <sstabellini@kernel.org>, Steven Rostedt <rostedt@goodmis.org>,
 virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
 xen-devel@lists.xenproject.org
References: <cover.1755193625.git.leon@kernel.org>
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: fr-FR
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 14/08/2025 =C3=A0 19:53, Leon Romanovsky a =C3=A9crit=C2=A0:
> Changelog:
> v3:
>   * Fixed typo in "cacheable" word
>   * Simplified kmsan patch a lot to be simple argument refactoring

v2 sent today at 12:13, v3 sent today at 19:53 .... for only that ?

Have you read=20
https://docs.kernel.org//process/submitting-patches.html#don-t-get-discoura=
ged-or-impatient=20
?

Thanks
Christophe

> v2: https://lore.kernel.org/all/cover.1755153054.git.leon@kernel.org
>   * Used commit messages and cover letter from Jason
>   * Moved setting IOMMU_MMIO flag to dma_info_to_prot function
>   * Micro-optimized the code
>   * Rebased code on v6.17-rc1
> v1: https://lore.kernel.org/all/cover.1754292567.git.leon@kernel.org
>   * Added new DMA_ATTR_MMIO attribute to indicate
>     PCI_P2PDMA_MAP_THRU_HOST_BRIDGE path.
>   * Rewrote dma_map_* functions to use thus new attribute
> v0: https://lore.kernel.org/all/cover.1750854543.git.leon@kernel.org/
> ------------------------------------------------------------------------
>=20
> This series refactors the DMA mapping to use physical addresses
> as the primary interface instead of page+offset parameters. This
> change aligns the DMA API with the underlying hardware reality where
> DMA operations work with physical addresses, not page structures.
>=20
> The series maintains export symbol backward compatibility by keeping
> the old page-based API as wrapper functions around the new physical
> address-based implementations.
>=20
> This series refactors the DMA mapping API to provide a phys_addr_t
> based, and struct-page free, external API that can handle all the
> mapping cases we want in modern systems:
>=20
>   - struct page based cachable DRAM
>   - struct page MEMORY_DEVICE_PCI_P2PDMA PCI peer to peer non-cachable
>     MMIO
>   - struct page-less PCI peer to peer non-cachable MMIO
>   - struct page-less "resource" MMIO
>=20
> Overall this gets much closer to Matthew's long term wish for
> struct-pageless IO to cachable DRAM. The remaining primary work would
> be in the mm side to allow kmap_local_pfn()/phys_to_virt() to work on
> phys_addr_t without a struct page.
>=20
> The general design is to remove struct page usage entirely from the
> DMA API inner layers. For flows that need to have a KVA for the
> physical address they can use kmap_local_pfn() or phys_to_virt(). This
> isolates the struct page requirements to MM code only. Long term all
> removals of struct page usage are supporting Matthew's memdesc
> project which seeks to substantially transform how struct page works.
>=20
> Instead make the DMA API internals work on phys_addr_t. Internally
> there are still dedicated 'page' and 'resource' flows, except they are
> now distinguished by a new DMA_ATTR_MMIO instead of by callchain. Both
> flows use the same phys_addr_t.
>=20
> When DMA_ATTR_MMIO is specified things work similar to the existing
> 'resource' flow. kmap_local_pfn(), phys_to_virt(), phys_to_page(),
> pfn_valid(), etc are never called on the phys_addr_t. This requires
> rejecting any configuration that would need swiotlb. CPU cache
> flushing is not required, and avoided, as ATTR_MMIO also indicates the
> address have no cachable mappings. This effectively removes any
> DMA API side requirement to have struct page when DMA_ATTR_MMIO is
> used.
>=20
> In the !DMA_ATTR_MMIO mode things work similarly to the 'page' flow,
> except on the common path of no cache flush, no swiotlb it never
> touches a struct page. When cache flushing or swiotlb copying
> kmap_local_pfn()/phys_to_virt() are used to get a KVA for CPU
> usage. This was already the case on the unmap side, now the map side
> is symmetric.
>=20
> Callers are adjusted to set DMA_ATTR_MMIO. Existing 'resource' users
> must set it. The existing struct page based MEMORY_DEVICE_PCI_P2PDMA
> path must also set it. This corrects some existing bugs where iommu
> mappings for P2P MMIO were improperly marked IOMMU_CACHE.
>=20
> Since ATTR_MMIO is made to work with all the existing DMA map entry
> points, particularly dma_iova_link(), this finally allows a way to use
> the new DMA API to map PCI P2P MMIO without creating struct page. The
> VFIO DMABUF series demonstrates how this works. This is intended to
> replace the incorrect driver use of dma_map_resource() on PCI BAR
> addresses.
>=20
> This series does the core code and modern flows. A followup series
> will give the same treatment to the legacy dma_ops implementation.
>=20
> Thanks
>=20
> Leon Romanovsky (16):
>    dma-mapping: introduce new DMA attribute to indicate MMIO memory
>    iommu/dma: implement DMA_ATTR_MMIO for dma_iova_link().
>    dma-debug: refactor to use physical addresses for page mapping
>    dma-mapping: rename trace_dma_*map_page to trace_dma_*map_phys
>    iommu/dma: rename iommu_dma_*map_page to iommu_dma_*map_phys
>    iommu/dma: extend iommu_dma_*map_phys API to handle MMIO memory
>    dma-mapping: convert dma_direct_*map_page to be phys_addr_t based
>    kmsan: convert kmsan_handle_dma to use physical addresses
>    dma-mapping: handle MMIO flow in dma_map|unmap_page
>    xen: swiotlb: Open code map_resource callback
>    dma-mapping: export new dma_*map_phys() interface
>    mm/hmm: migrate to physical address-based DMA mapping API
>    mm/hmm: properly take MMIO path
>    block-dma: migrate to dma_map_phys instead of map_page
>    block-dma: properly take MMIO path
>    nvme-pci: unmap MMIO pages with appropriate interface
>=20
>   Documentation/core-api/dma-api.rst        |   4 +-
>   Documentation/core-api/dma-attributes.rst |  18 ++++
>   arch/powerpc/kernel/dma-iommu.c           |   4 +-
>   block/blk-mq-dma.c                        |  15 ++-
>   drivers/iommu/dma-iommu.c                 |  61 +++++------
>   drivers/nvme/host/pci.c                   |  18 +++-
>   drivers/virtio/virtio_ring.c              |   4 +-
>   drivers/xen/swiotlb-xen.c                 |  21 +++-
>   include/linux/blk-mq-dma.h                |   6 +-
>   include/linux/blk_types.h                 |   2 +
>   include/linux/dma-direct.h                |   2 -
>   include/linux/dma-map-ops.h               |   8 +-
>   include/linux/dma-mapping.h               |  33 ++++++
>   include/linux/iommu-dma.h                 |  11 +-
>   include/linux/kmsan.h                     |   9 +-
>   include/trace/events/dma.h                |   9 +-
>   kernel/dma/debug.c                        |  71 ++++---------
>   kernel/dma/debug.h                        |  37 ++-----
>   kernel/dma/direct.c                       |  22 +---
>   kernel/dma/direct.h                       |  52 ++++++----
>   kernel/dma/mapping.c                      | 117 +++++++++++++---------
>   kernel/dma/ops_helpers.c                  |   6 +-
>   mm/hmm.c                                  |  19 ++--
>   mm/kmsan/hooks.c                          |   7 +-
>   rust/kernel/dma.rs                        |   3 +
>   tools/virtio/linux/kmsan.h                |   2 +-
>   26 files changed, 306 insertions(+), 255 deletions(-)
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c=
cc8eeba-757a-440d-80d3-9158e80c19fe%40csgroup.eu.
