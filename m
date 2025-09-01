Return-Path: <kasan-dev+bncBDG6PF6SSYDRBGFJ3DCQMGQED4VUZDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E2D9B3F0AB
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 23:48:10 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-336be2f22cesf23285851fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 14:48:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756763290; cv=pass;
        d=google.com; s=arc-20240605;
        b=TJckDxoUxHtzhpEyy0ad01xdBNh4L9pty9A3bXRy608nJsheJ8ge9A5OpY+9Nq1ZUT
         mec/3GfgBCaUa7vVn0Ow0j+xlcQ9WKFhNHAO3NIA8A2qYBU0hdrc8EGWtWmYLVDbj7Gt
         aZOfCo6owtfN4OXk0cLJeTrTm+nbpZo4mMDr63pSeOivu7419O2bPNvFO1+pBBcbH6xw
         nXh+haERnYj6ZJFXmEZIYTTURzXUqqekxzBewydc+6UsxXP4TMxCaao01zIyJqLX1ycf
         +03vkx56Vc7qAF3VBUoGzrTPqH7arCQpVUV1j6IXRukVJtXJWMfRP9StlWScLKS6DwUF
         qrZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references
         :content-transfer-encoding:in-reply-to:from:content-language:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-filter:sender
         :dkim-signature;
        bh=JR8gqJlWuJSaJVfXFjSr0lVdStrTwQxlP0tDQ4DrfIo=;
        fh=X8edSGztMBJhmJDbWbY8vhAWqr5bf663wZ4wTgKZBbk=;
        b=T+mNUTt0miq2as1gmYME6mqDuFopuTmt9lpumDukqlaimVmajLp53TjTQf9T/+0UgA
         2uzQKB6khn/8VIlrWWcxD7l20GWaUuLX2kiQV1NmZhU27iG1G2WgsfKnPwKuFmW/5fbO
         NsCOYadLn7Jv5kY+tIaC5XL0O0LfPlWMOmCvC0+J1o9gaOWj5jKnzFFp+ks/V4/wmt2O
         e8/3dzjvsdKVpOhWehZNhZEQQ63GnE61P974+BzalJAL/oXh4Kyia5WmmJP6TgmAuSxm
         IP11ahS+Xtq9SHGUjHzBWSSQXWbq8gaiavYZ+KAY68getoCQX2fnDC0fbhMURQhshVYe
         EX4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=FxjRf7+C;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756763290; x=1757368090; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:content-transfer-encoding:in-reply-to
         :from:content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JR8gqJlWuJSaJVfXFjSr0lVdStrTwQxlP0tDQ4DrfIo=;
        b=GpYhFeZzStxPM8Hzd/ABcYnESdnum2/AEJoBxKbp9XutCbdRG7ueLZ/p3tXa7rGIJ3
         LWK4J42TllCtdDf49Nd7wugBpEqjtZL5mbXntH/GsVv8GruwOsoJmbMVdUlr1Uot0R6l
         ALukEJVufS8sgDX3TQnvCusMBTL09kYIoTd3UgVPso+CV8v0MtrmzfXizfUv7CjGHvfg
         7wHfP6zis/hZrhl37bIIZaatQO2OUa2c0a9Z8uUmNN0rvoKxondoex/0ZBBwFD0Kc7+c
         wGNKzPY7aMJdzbnDK3vL8J2XKesPW4+d/kVwOZfAvkV7z0F4Q/01a8oZcU2Ii5c3A4RP
         xCJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756763290; x=1757368090;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :content-transfer-encoding:in-reply-to:from:content-language:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-filter
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JR8gqJlWuJSaJVfXFjSr0lVdStrTwQxlP0tDQ4DrfIo=;
        b=qNZqjOgpWgrRzt5fc92+b7Q/pJKQbzb3QR75Sag3WnlFSv0/EL5CYvPuIhPGjCBs8m
         2Y7e0ePx34lIhqU2QQZYeuB+g0soIkoNXRKt2vxULNlOhieq+ouochwsNn6pTl5rhFKU
         afUMpo5295W+cj6YxotQGuYP93RBFgfJqWvnr9Imx8PBmh5s9yFY200D40/ZFhdkmMwU
         gvVWaU13tQMlexGVp2NaOUyUJwQUSATmcB8EWSdi8jTJa4+pmKu1TEUMSP1X64s/m3wv
         tLllXtq5o8XHKL+9kYJj9Zy8/KRn3SlrsXmLesf9h4h8K69bX+1RYYB7yOn4IiBv5ANm
         ksjQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX8r60pNwLcCOslbnG4g7q4AwPdcXtjn6dl7sPPyrKa5csetA5UaWrEy2Trr/eoenI2zmxh3w==@lfdr.de
X-Gm-Message-State: AOJu0Yxn7goeiKSwrlhElnPB+928/dZ6jqznMKEeT5UqJC87dwNKfLaJ
	GSFjTi5MCk8gdJKk6wMWFE3JXnIvLDmDrtpvm34bwoeKQctSFDyBfjgr
X-Google-Smtp-Source: AGHT+IGZVYKPNAcwsrZM7VQ6kh3ITrNpI30PkrQhVsKdWYrCmc7OD157KgFL3rGhK7XqrxmnkGfoPw==
X-Received: by 2002:a05:6512:eaa:b0:55f:6f76:418 with SMTP id 2adb3069b0e04-55f70948ae4mr2849015e87.44.1756763289102;
        Mon, 01 Sep 2025 14:48:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdsBVSVUx8uuoEFucbQhp5EQ7UxXvjhnhsgQeX+gDAI3g==
Received: by 2002:a19:4344:0:b0:55a:2758:43e9 with SMTP id 2adb3069b0e04-55f5f072994ls751824e87.1.-pod-prod-03-eu;
 Mon, 01 Sep 2025 14:48:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVYAzIeFxTmkwYvHy394ls+ds1xQ1PQKYsdrqXNMB1MPJ5VEUWSdXp4w99NreQT3+tcGlcvszy++MA=@googlegroups.com
X-Received: by 2002:a05:6512:2c09:b0:55b:92f9:c625 with SMTP id 2adb3069b0e04-55f708b70ccmr2417867e87.20.1756763286195;
        Mon, 01 Sep 2025 14:48:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756763286; cv=none;
        d=google.com; s=arc-20240605;
        b=OFvsfso2mmHIa9Nk8WBMxX93lPA+byDgk+tPgKogKyWuAcXbx5cPg16v3c1ntUyzd9
         eLa20qnD6McuK9T1bQTkTneZNH8UjVS9m9Va9hqL5LBZ7j+ny2W46Zo/JN/hZ9ixk2Ja
         e9b/y2kQVzoQu05orJSXJaQAu4CJEwp25OvIOBwRdpqCYrYORq0zkT+FxaI8470MYyx5
         LSoCHyGxRCrnJXLYsqm/6P0Zszpxn+RXb5x2YyiE9mUxq9VUi1CjEJPERNDoyp3DPV7t
         5oAfKSUG0WuS0pMeBMdrsxoYp+/wi7fveXwko1hlikMiKFJ0OkWhmV8qI3xeeJBaSeCR
         19hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=nDcHitW6y2xbmXlK2jIcbndjdtco2y22djXFkarI+Kk=;
        fh=zgr8QDHL9U+SBYRLt4JPwbPFJLa48RTUEIjk/IwbdaI=;
        b=hQWqe0+oQ9IFqio7roViVg1aqhApQp42zPGCHp7G/bYtWWiSAfNUbzPGoFXJF05L3x
         ux0JySovftucB+sk0gpAt5G0cbVMM319RXlk0r2UP7pnKvpB1QlKF8Wyu+1U46YnsssJ
         lYaUhpnbDz2YtS81QL6RtWVINtzFNQUfnjPyTglIyg0vpXMBJIs33LsMym7PneljOa+k
         sNE5ya3SqVjyS4HRzItw9lLWCusd7jQzYyz+i/9n27xVNfKbUuNiN4k66TqRs8vf6uDd
         4/bMBsOzP7xyJzGIMQ8S8kqONuSeQkOJXaFWzer0OuzyPYmi+nPGlSZPI1mZ41Qu4xHC
         Vnlg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=FxjRf7+C;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.w1.samsung.com (mailout2.w1.samsung.com. [210.118.77.12])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-560826ee633si7217e87.3.2025.09.01.14.48.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 01 Sep 2025 14:48:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) client-ip=210.118.77.12;
Received: from eucas1p1.samsung.com (unknown [182.198.249.206])
	by mailout2.w1.samsung.com (KnoxPortal) with ESMTP id 20250901214803euoutp02d79d0cf4cda6546a5817575ed420314a~hRuYkNP0O2070420704euoutp02b;
	Mon,  1 Sep 2025 21:48:03 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.w1.samsung.com 20250901214803euoutp02d79d0cf4cda6546a5817575ed420314a~hRuYkNP0O2070420704euoutp02b
Received: from eusmtip2.samsung.com (unknown [203.254.199.222]) by
	eucas1p2.samsung.com (KnoxPortal) with ESMTPA id
	20250901214802eucas1p2e3b4b360d054bc640a8654e364047c28~hRuXfQpr52428424284eucas1p2C;
	Mon,  1 Sep 2025 21:48:02 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20250901214759eusmtip26af756ba90f133971e3a66f9c5275b48~hRuUiYUac1463914639eusmtip2j;
	Mon,  1 Sep 2025 21:47:59 +0000 (GMT)
Message-ID: <26bd901a-0812-492d-9736-4a7bb2e6d6b4@samsung.com>
Date: Mon, 1 Sep 2025 23:47:59 +0200
MIME-Version: 1.0
User-Agent: Betterbird (Windows)
Subject: Re: [PATCH v4 00/16] dma-mapping: migrate to physical address-based
 API
To: Leon Romanovsky <leon@kernel.org>
Cc: Jason Gunthorpe <jgg@nvidia.com>, Abdiel Janulgue
	<abdiel.janulgue@gmail.com>, Alexander Potapenko <glider@google.com>, Alex
	Gaynor <alex.gaynor@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>, Jens Axboe
	<axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>, Jonathan Corbet
	<corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
	linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org, Madhavan Srinivasan
	<maddy@linux.ibm.com>, Masami Hiramatsu <mhiramat@kernel.org>, Michael
	Ellerman <mpe@ellerman.id.au>, "Michael S. Tsirkin" <mst@redhat.com>, Miguel
	Ojeda <ojeda@kernel.org>, Robin Murphy <robin.murphy@arm.com>,
	rust-for-linux@vger.kernel.org, Sagi Grimberg <sagi@grimberg.me>, Stefano
	Stabellini <sstabellini@kernel.org>, Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Content-Language: en-US
From: Marek Szyprowski <m.szyprowski@samsung.com>
In-Reply-To: <20250828115729.GA10073@unreal>
Content-Transfer-Encoding: quoted-printable
X-CMS-MailID: 20250901214802eucas1p2e3b4b360d054bc640a8654e364047c28
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20250828115738eucas1p24f3c17326b318c95a5569a2c9651ff92
X-EPHeader: CA
X-CMS-RootMailID: 20250828115738eucas1p24f3c17326b318c95a5569a2c9651ff92
References: <cover.1755624249.git.leon@kernel.org>
	<CGME20250828115738eucas1p24f3c17326b318c95a5569a2c9651ff92@eucas1p2.samsung.com>
	<20250828115729.GA10073@unreal>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=FxjRf7+C;       spf=pass
 (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as
 permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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


On 28.08.2025 13:57, Leon Romanovsky wrote:
> On Tue, Aug 19, 2025 at 08:36:44PM +0300, Leon Romanovsky wrote:
>> Changelog:
>> v4:
>>   * Fixed kbuild error with mismatch in kmsan function declaration due t=
o
>>     rebase error.
>> v3: https://lore.kernel.org/all/cover.1755193625.git.leon@kernel.org
>>   * Fixed typo in "cacheable" word
>>   * Simplified kmsan patch a lot to be simple argument refactoring
>> v2: https://lore.kernel.org/all/cover.1755153054.git.leon@kernel.org
>>   * Used commit messages and cover letter from Jason
>>   * Moved setting IOMMU_MMIO flag to dma_info_to_prot function
>>   * Micro-optimized the code
>>   * Rebased code on v6.17-rc1
>> v1: https://lore.kernel.org/all/cover.1754292567.git.leon@kernel.org
>>   * Added new DMA_ATTR_MMIO attribute to indicate
>>     PCI_P2PDMA_MAP_THRU_HOST_BRIDGE path.
>>   * Rewrote dma_map_* functions to use thus new attribute
>> v0: https://lore.kernel.org/all/cover.1750854543.git.leon@kernel.org/
>> ------------------------------------------------------------------------
>>
>> This series refactors the DMA mapping to use physical addresses
>> as the primary interface instead of page+offset parameters. This
>> change aligns the DMA API with the underlying hardware reality where
>> DMA operations work with physical addresses, not page structures.
>>
>> The series maintains export symbol backward compatibility by keeping
>> the old page-based API as wrapper functions around the new physical
>> address-based implementations.
>>
>> This series refactors the DMA mapping API to provide a phys_addr_t
>> based, and struct-page free, external API that can handle all the
>> mapping cases we want in modern systems:
>>
>>   - struct page based cachable DRAM
>>   - struct page MEMORY_DEVICE_PCI_P2PDMA PCI peer to peer non-cachable
>>     MMIO
>>   - struct page-less PCI peer to peer non-cachable MMIO
>>   - struct page-less "resource" MMIO
>>
>> Overall this gets much closer to Matthew's long term wish for
>> struct-pageless IO to cachable DRAM. The remaining primary work would
>> be in the mm side to allow kmap_local_pfn()/phys_to_virt() to work on
>> phys_addr_t without a struct page.
>>
>> The general design is to remove struct page usage entirely from the
>> DMA API inner layers. For flows that need to have a KVA for the
>> physical address they can use kmap_local_pfn() or phys_to_virt(). This
>> isolates the struct page requirements to MM code only. Long term all
>> removals of struct page usage are supporting Matthew's memdesc
>> project which seeks to substantially transform how struct page works.
>>
>> Instead make the DMA API internals work on phys_addr_t. Internally
>> there are still dedicated 'page' and 'resource' flows, except they are
>> now distinguished by a new DMA_ATTR_MMIO instead of by callchain. Both
>> flows use the same phys_addr_t.
>>
>> When DMA_ATTR_MMIO is specified things work similar to the existing
>> 'resource' flow. kmap_local_pfn(), phys_to_virt(), phys_to_page(),
>> pfn_valid(), etc are never called on the phys_addr_t. This requires
>> rejecting any configuration that would need swiotlb. CPU cache
>> flushing is not required, and avoided, as ATTR_MMIO also indicates the
>> address have no cachable mappings. This effectively removes any
>> DMA API side requirement to have struct page when DMA_ATTR_MMIO is
>> used.
>>
>> In the !DMA_ATTR_MMIO mode things work similarly to the 'page' flow,
>> except on the common path of no cache flush, no swiotlb it never
>> touches a struct page. When cache flushing or swiotlb copying
>> kmap_local_pfn()/phys_to_virt() are used to get a KVA for CPU
>> usage. This was already the case on the unmap side, now the map side
>> is symmetric.
>>
>> Callers are adjusted to set DMA_ATTR_MMIO. Existing 'resource' users
>> must set it. The existing struct page based MEMORY_DEVICE_PCI_P2PDMA
>> path must also set it. This corrects some existing bugs where iommu
>> mappings for P2P MMIO were improperly marked IOMMU_CACHE.
>>
>> Since ATTR_MMIO is made to work with all the existing DMA map entry
>> points, particularly dma_iova_link(), this finally allows a way to use
>> the new DMA API to map PCI P2P MMIO without creating struct page. The
>> VFIO DMABUF series demonstrates how this works. This is intended to
>> replace the incorrect driver use of dma_map_resource() on PCI BAR
>> addresses.
>>
>> This series does the core code and modern flows. A followup series
>> will give the same treatment to the legacy dma_ops implementation.
>>
>> Thanks
>>
>> Leon Romanovsky (16):
>>    dma-mapping: introduce new DMA attribute to indicate MMIO memory
>>    iommu/dma: implement DMA_ATTR_MMIO for dma_iova_link().
>>    dma-debug: refactor to use physical addresses for page mapping
>>    dma-mapping: rename trace_dma_*map_page to trace_dma_*map_phys
>>    iommu/dma: rename iommu_dma_*map_page to iommu_dma_*map_phys
>>    iommu/dma: extend iommu_dma_*map_phys API to handle MMIO memory
>>    dma-mapping: convert dma_direct_*map_page to be phys_addr_t based
>>    kmsan: convert kmsan_handle_dma to use physical addresses
>>    dma-mapping: handle MMIO flow in dma_map|unmap_page
>>    xen: swiotlb: Open code map_resource callback
>>    dma-mapping: export new dma_*map_phys() interface
>>    mm/hmm: migrate to physical address-based DMA mapping API
>>    mm/hmm: properly take MMIO path
>>    block-dma: migrate to dma_map_phys instead of map_page
>>    block-dma: properly take MMIO path
>>    nvme-pci: unmap MMIO pages with appropriate interface
>>
>>   Documentation/core-api/dma-api.rst        |   4 +-
>>   Documentation/core-api/dma-attributes.rst |  18 ++++
>>   arch/powerpc/kernel/dma-iommu.c           |   4 +-
>>   block/blk-mq-dma.c                        |  15 ++-
>>   drivers/iommu/dma-iommu.c                 |  61 +++++------
>>   drivers/nvme/host/pci.c                   |  18 +++-
>>   drivers/virtio/virtio_ring.c              |   4 +-
>>   drivers/xen/swiotlb-xen.c                 |  21 +++-
>>   include/linux/blk-mq-dma.h                |   6 +-
>>   include/linux/blk_types.h                 |   2 +
>>   include/linux/dma-direct.h                |   2 -
>>   include/linux/dma-map-ops.h               |   8 +-
>>   include/linux/dma-mapping.h               |  33 ++++++
>>   include/linux/iommu-dma.h                 |  11 +-
>>   include/linux/kmsan.h                     |   9 +-
>>   include/trace/events/dma.h                |   9 +-
>>   kernel/dma/debug.c                        |  71 ++++---------
>>   kernel/dma/debug.h                        |  37 ++-----
>>   kernel/dma/direct.c                       |  22 +---
>>   kernel/dma/direct.h                       |  52 ++++++----
>>   kernel/dma/mapping.c                      | 117 +++++++++++++---------
>>   kernel/dma/ops_helpers.c                  |   6 +-
>>   mm/hmm.c                                  |  19 ++--
>>   mm/kmsan/hooks.c                          |   5 +-
>>   rust/kernel/dma.rs                        |   3 +
>>   tools/virtio/linux/kmsan.h                |   2 +-
>>   26 files changed, 305 insertions(+), 254 deletions(-)
> Marek,
>
> So what are the next steps here? This series is pre-requirement for the
> VFIO MMIO patches.

I waited a bit with a hope to get a comment from Robin. It looks that=20
there is no other alternative for the phys addr in the struct page=20
removal process.

I would like to=C2=A0give those patches a try in linux-next, but in meantim=
e=20
I tested it on my test farm and found a regression in dma_map_resource()=20
handling. Namely the dma_map_resource() is no longer possible with size=20
not aligned to kmalloc()'ed buffer, as dma_direct_map_phys() calls=20
dma_kmalloc_needs_bounce(), which in turn calls=20
dma_kmalloc_size_aligned(). It looks that the check for !(attrs &=20
DMA_ATTR_MMIO) should be moved one level up in dma_direct_map_phys().=20
Here is the log:

------------[ cut here ]------------
dma-pl330 fe550000.dma-controller: DMA addr 0x00000000fe410024+4=20
overflow (mask ffffffff, bus limit 0).
WARNING: kernel/dma/direct.h:116 at dma_map_phys+0x3a4/0x3ec, CPU#1:=20
speaker-test/405
Modules linked in: ...
CPU: 1 UID: 0 PID: 405 Comm: speaker-test Not tainted=20
6.17.0-rc4-next-20250901+ #10958 PREEMPT
Hardware name: Hardkernel ODROID-M1 (DT)
pstate: 604000c9 (nZCv daIF +PAN -UAO -TCO -DIT -SSBS BTYPE=3D--)
pc : dma_map_phys+0x3a4/0x3ec
lr : dma_map_phys+0x3a4/0x3ec
...
Call trace:
 =C2=A0dma_map_phys+0x3a4/0x3ec (P)
 =C2=A0dma_map_resource+0x14/0x20
 =C2=A0pl330_prep_slave_fifo+0x78/0xd0
 =C2=A0pl330_prep_dma_cyclic+0x70/0x2b0
 =C2=A0snd_dmaengine_pcm_trigger+0xec/0x8bc [snd_pcm_dmaengine]
 =C2=A0dmaengine_pcm_trigger+0x18/0x24 [snd_soc_core]
 =C2=A0snd_soc_pcm_component_trigger+0x164/0x208 [snd_soc_core]
 =C2=A0soc_pcm_trigger+0xe4/0x1ec [snd_soc_core]
 =C2=A0snd_pcm_do_start+0x44/0x70 [snd_pcm]
 =C2=A0snd_pcm_action_single+0x48/0xa4 [snd_pcm]
 =C2=A0snd_pcm_action+0x7c/0x98 [snd_pcm]
 =C2=A0snd_pcm_action_lock_irq+0x48/0xb4 [snd_pcm]
 =C2=A0snd_pcm_common_ioctl+0xf00/0x1f1c [snd_pcm]
 =C2=A0snd_pcm_ioctl+0x30/0x48 [snd_pcm]
 =C2=A0__arm64_sys_ioctl+0xac/0x104
 =C2=A0invoke_syscall+0x48/0x110
 =C2=A0el0_svc_common.constprop.0+0x40/0xe8
 =C2=A0do_el0_svc+0x20/0x2c
 =C2=A0el0_svc+0x4c/0x160
 =C2=A0el0t_64_sync_handler+0xa0/0xe4
 =C2=A0el0t_64_sync+0x198/0x19c
irq event stamp: 6596
hardirqs last=C2=A0 enabled at (6595): [<ffff800081344624>]=20
_raw_spin_unlock_irqrestore+0x74/0x78
hardirqs last disabled at (6596): [<ffff8000813439b0>]=20
_raw_spin_lock_irq+0x78/0x7c
softirqs last=C2=A0 enabled at (6076): [<ffff8000800c2294>]=20
handle_softirqs+0x4c4/0x4dc
softirqs last disabled at (6071): [<ffff800080010690>]=20
__do_softirq+0x14/0x20
---[ end trace 0000000000000000 ]---
rockchip-i2s-tdm fe410000.i2s: ASoC error (-12): at=20
soc_component_trigger() on fe410000.i2s

Best regards
--=20
Marek Szyprowski, PhD
Samsung R&D Institute Poland

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
6bd901a-0812-492d-9736-4a7bb2e6d6b4%40samsung.com.
