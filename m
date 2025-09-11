Return-Path: <kasan-dev+bncBDG6PF6SSYDRB24YRXDAMGQEOFWPKXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B4B6B53EA2
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 00:25:49 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-55f6a515516sf1702438e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 15:25:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757629548; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZjF/WMM2KWvXJYhmX7masGBQtK1dD5J/yKtwu4RwIgxJAi0hlx6nDCE07aimRMueuy
         x5Jq6ZNOtzPUPFilg50C90xb5D7JhyvAzK8HfM7+5WSqpPl7FlL6tSwrjgz4Crz+8ORT
         yC0AjoWLG7rTTybQrU3O3frhM7Viim2KHGkhP++tOTKS4vIfxJ/5C/G3W6lJX/cCDc5u
         KTNS7JIxQQsfhLEM7fx28jhd3AmZ9/ZhJyT+b7xV5CdPf3auM3KPF6Dyd4ALFmn8gMFr
         Y5fvbppHf7zwoS2vFLfjsIptIizu6M16WH8UQp99Ft/zXQMocYFCMdtctuip5X5sABgV
         WwPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:dkim-signature;
        bh=CGM/WXSIxDdZZUILlayEJ07OFPwW0pn6cieKCl8MZGo=;
        fh=h+0buue1p9qhWSbJZoE2H5gbyhAc3v31foyFd2PdBW4=;
        b=WLrNGzZ1/RZZljXM0t3eEHZjYkukgC9N6yi3x4cISsj4NTy9Pn5SMFDHmNTxUF9Hvr
         NZ6XLA7Mr6sBcVIGcyuy9VIEsJB6iht3phTsmxsC4WZOr7d+AmxLLaqf2xxMHvefl+cZ
         4yKIqIbpUG8fKu36z5rm1c9upIIQKASGveAxU8d2QOTODj1CMhjxU0iOXdxzxuFMhX1I
         PPx4qEWH7nbvbo2TJc+2h4S+B0Z9Vpa8anfuHxL6TUYUnM6QqckxtWIPUCb7sIjwqkpf
         b0ltPxqEvFtJSumgGidydA/7r7/lysIkFHvtzNFh4E2qe5QW2UqRRXlSWSJNsGPK37Im
         TLXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=TYzap3cs;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757629548; x=1758234348; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:from:content-language:cc
         :to:subject:user-agent:mime-version:date:message-id:dkim-filter
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CGM/WXSIxDdZZUILlayEJ07OFPwW0pn6cieKCl8MZGo=;
        b=lDVM224W7HyL9+Y3Dj5gf2oiwJxpKp+f+aYqJ48tme9S8WXL7cllvkaUJfCBv72Yf2
         Iq/mxS8XUP3Vn5291G19eaDrxmXEOTBWhFsLUJTl3qk9tc9XqIr9vA4BH7jdSuIV17A6
         okTdL12YyR0FMwROgCg5omkMPaUrgf1u20GyMdVAaY2+sT/Df3jWr2CqroDwwaycuTGZ
         bS1h0bZNrRHwvwavUd9x9VTEXmt1W7w9pL3SSV70df3LNxbK9vHQg+Q3qXSm9q6bOYEO
         Hwq+NFY5SNH0Vj+gRNZCysJucAZBY9S+WZ1ttubCjeGTlPgdJXtkhPs69lNZ8lKA9lU9
         UPAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757629548; x=1758234348;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:from:content-language:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-filter:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CGM/WXSIxDdZZUILlayEJ07OFPwW0pn6cieKCl8MZGo=;
        b=EaeB8VcWTF1xT0FlmrT/euKgbdQJhWhCwTHId5K+8Z4iEHeKlw1inV0f1AL6G8/ZoS
         C3MmorL1tQo85uMGajIPbajJgv1T4z6mIWAXcAOae0j99QUa3ZASQ5eP89Zs9Tjlddbn
         EGfGzvWJtBjECiutnuI0FsvXbgl3B9luh7yk4Mi+ilC5hFdtHGolBtuKoFvM+zi8cXR2
         vjKdMGGSh+YB/2I2AtPREL5Kdlm/JoUwc4pOQpqOEJhbbDw5NluOffTtvQo+GZ9Gvg7B
         kvF1Wo/+p/2UdUUJdCM2s82Qdcb9HA7GpsKCveB3q49Hfw2hXKG9RK0BpzKAYUzXjIPn
         ArLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVkDwB3gTPxlNiHjGXDYeWhr0NwOWNMxRrBdNmsKzo0F0EI9TCnIkFjO6bS83GmBZkTx0nahA==@lfdr.de
X-Gm-Message-State: AOJu0YxI4qUgmF22A812I+zRh4e9+TSHY6GmhIBvf+LKyr5FpC9wVPFQ
	WHbdcGFeTcBDQ+tj56/0I7pzASgj5TUBeU9Hj+7quFQJ6/tVhIZxcBdF
X-Google-Smtp-Source: AGHT+IGtfPqaTmaRCrCxdxqMz+edWu6hFON6u77pToFaaZmTVPyaGqPbsJ5ethcarCnh6V8eiiOKOA==
X-Received: by 2002:a05:6512:b27:b0:560:a641:6499 with SMTP id 2adb3069b0e04-5705d063a09mr329365e87.9.1757629547799;
        Thu, 11 Sep 2025 15:25:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfyA3veFkVFT9EM2iXUIc6Vm8b6UN3GFt18ZgwBp8CT1Q==
Received: by 2002:a05:6512:144d:10b0:55f:4af2:a581 with SMTP id
 2adb3069b0e04-56dd7585ba1ls159373e87.0.-pod-prod-00-eu; Thu, 11 Sep 2025
 15:25:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWPSE1B51SMrq4pWp48CP7lbVkXlECDhqr6v9kwLapkwqjOTEHcQNCXzWyLGaHpf2O+3g8VqnTnL9c=@googlegroups.com
X-Received: by 2002:a05:6512:3fa:b0:55f:6d0c:487b with SMTP id 2adb3069b0e04-56d755e83f7mr1159246e87.3.1757629544801;
        Thu, 11 Sep 2025 15:25:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757629544; cv=none;
        d=google.com; s=arc-20240605;
        b=EtQRWSNYlsSMcFVJYBls0+l7J2msDtS1HSzNSXrlOcuIPcH/XGutU+JmMmNMlWbyyi
         jNAUeS8Bv1BjXvhQpO7YRpFs0cFgmE4ZKXIqo4btgo+qMkNF9C90b6tlpEuNQBzbFM+Q
         dCuAtvU4z1VC4ijnSisCGAmgrqZYjZGmmxBMOU1WyedZcQ81D3LtnIHgwBODOJ1nPfSk
         PwAgMdTZ52OkeUNWlancjMzeI7ZFnJPVQoxQRjKbi7BOPwOpAXuCpt9fCW5hLyPrf8Zr
         j92v61ZzNyCJ+xI6y2Yz6aIlNI7cjt4wp4OCEVDdWvq7eqpilkg/oEkrET6L0saV9S6g
         rDRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=pKZpcAmq/bht8ZKkJqtZPTgOAGANcQvA5kKLVuXifcI=;
        fh=OrMujXTewyvzYmcfWSc12Lkv5kQcm7TAYfZXBi77AsM=;
        b=XP9KZRuXMSPK/rftoAjyjJOn+uAOyJupoRKEqcaN3j9zGctN9We2OD5f5Z3cvZQRbI
         xYeycdVJZPIhqce1UaKt+wIk06zBxoN4VidRtuWOF5TQTeWVHCZ1/sT94EdlO/cW9JSR
         HqG/eBZMr34ogiB/YBAlliudOIzmHXnEdEYpzsR/tVbZTJ4o8FcgdvVWlU95qhIv8QVW
         GpvJBwpfPa5AeXYOqnXKNZp5Lh5sX3hHpn+iGikjC3KrcWem+GuBBaE93IT3MfyRvx9I
         2VBIqJNx5O/x58UnNyrY9956KkY0zvhD2Wuv+fAd8FzgdowjEcnFt4cvjT8tj7O+XIZU
         qulg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=TYzap3cs;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.w1.samsung.com (mailout1.w1.samsung.com. [210.118.77.11])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3512ad6a34esi117231fa.6.2025.09.11.15.25.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Sep 2025 15:25:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) client-ip=210.118.77.11;
Received: from eucas1p2.samsung.com (unknown [182.198.249.207])
	by mailout1.w1.samsung.com (KnoxPortal) with ESMTP id 20250911222543euoutp0181a9340dd64dc67c6339e0a47181ebf4~kWsHnYW5E2610126101euoutp01U;
	Thu, 11 Sep 2025 22:25:43 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.w1.samsung.com 20250911222543euoutp0181a9340dd64dc67c6339e0a47181ebf4~kWsHnYW5E2610126101euoutp01U
Received: from eusmtip1.samsung.com (unknown [203.254.199.221]) by
	eucas1p1.samsung.com (KnoxPortal) with ESMTPA id
	20250911222542eucas1p1fd99b15e46362a0af4417b04fa0c831b~kWsHKwmS41727217272eucas1p1e;
	Thu, 11 Sep 2025 22:25:42 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip1.samsung.com (KnoxPortal) with ESMTPA id
	20250911222538eusmtip17e16b44d9939848958cad6696cc3414c~kWsDGpMzk2282122821eusmtip1T;
	Thu, 11 Sep 2025 22:25:38 +0000 (GMT)
Message-ID: <0db9bce5-40df-4cf5-85ab-f032c67d5c71@samsung.com>
Date: Fri, 12 Sep 2025 00:25:38 +0200
MIME-Version: 1.0
User-Agent: Betterbird (Windows)
Subject: Re: [PATCH v6 00/16] dma-mapping: migrate to physical address-based
 API
To: Leon Romanovsky <leon@kernel.org>
Cc: Leon Romanovsky <leonro@nvidia.com>, Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>, Alexander Potapenko
	<glider@google.com>, Alex Gaynor <alex.gaynor@gmail.com>, Andrew Morton
	<akpm@linux-foundation.org>, Christoph Hellwig <hch@lst.de>, Danilo
	Krummrich <dakr@kernel.org>, David Hildenbrand <david@redhat.com>,
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
In-Reply-To: <cover.1757423202.git.leonro@nvidia.com>
X-CMS-MailID: 20250911222542eucas1p1fd99b15e46362a0af4417b04fa0c831b
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20250909132821eucas1p1051ce9e0270ddbf520e105c913fa8db6
X-EPHeader: CA
X-CMS-RootMailID: 20250909132821eucas1p1051ce9e0270ddbf520e105c913fa8db6
References: <CGME20250909132821eucas1p1051ce9e0270ddbf520e105c913fa8db6@eucas1p1.samsung.com>
	<cover.1757423202.git.leonro@nvidia.com>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=TYzap3cs;       spf=pass
 (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as
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

On 09.09.2025 15:27, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
>
> Changelog:
> v6:
>   * Based on "dma-debug: don't enforce dma mapping check on noncoherent
>     allocations" patch.
>   * Removed some unused variables from kmsan conversion.
>   * Fixed missed ! in dma check.
> v5: https://lore.kernel.org/all/cover.1756822782.git.leon@kernel.org
>   * Added Jason's and Keith's Reviewed-by tags
>   * Fixed DMA_ATTR_MMIO check in dma_direct_map_phys
>   * Jason's cleanup suggestions
> v4: https://lore.kernel.org/all/cover.1755624249.git.leon@kernel.org/
>   * Fixed kbuild error with mismatch in kmsan function declaration due to
>     rebase error.
> v3: https://lore.kernel.org/all/cover.1755193625.git.leon@kernel.org
>   * Fixed typo in "cacheable" word
>   * Simplified kmsan patch a lot to be simple argument refactoring
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
>   - struct page based cacheable DRAM
>   - struct page MEMORY_DEVICE_PCI_P2PDMA PCI peer to peer non-cacheable
>     MMIO
>   - struct page-less PCI peer to peer non-cacheable MMIO
>   - struct page-less "resource" MMIO
>
> Overall this gets much closer to Matthew's long term wish for
> struct-pageless IO to cacheable DRAM. The remaining primary work would
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
> address have no cacheable mappings. This effectively removes any
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

Applied patches 1-13 into dma-mapping-for-next branch. Let's check if it 
works fine in linux-next.

Best regards
-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0db9bce5-40df-4cf5-85ab-f032c67d5c71%40samsung.com.
