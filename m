Return-Path: <kasan-dev+bncBDG6PF6SSYDRBJEO3HCAMGQERLAAYBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4088BB1EE86
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 20:51:29 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-615cfb6b834sf1228809a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Aug 2025 11:51:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754679078; cv=pass;
        d=google.com; s=arc-20240605;
        b=BdDPkMnSam9cI101d9RJvVZwtROKzgdtrAuXY9MsjaJprJl0j4lnxx3PuI5ggth+9V
         iogT7o8vro84KrVnEiLjhHptbjd9OXctNFlukOv3/KfZi68uaOQBlwhXzSTORtmzAOxi
         nt+ucdiAVWgYdy/pqUQaey8hM2lGiCI9UCaakp5PpUhDbuuLrlmkzkS5egYYAYLsAHX/
         zjkUfhL3BJBnKy+DS4wrUG99LHi8QiLwtDd/dDvT5mXf+rtBZNz/4uYTX7jd8HkeOdNz
         gOXbPAo5oR/8Zx25A/BGhJqtHFxCN2YfkDOQvtM6kCwMU2mAADvEEfPWMRet08N1k5jR
         rPig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references
         :content-transfer-encoding:in-reply-to:from:content-language:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-filter:sender
         :dkim-signature;
        bh=akvUqBdw1cbaS0KikfBVczg5NrXJyu9odYRf567JjqQ=;
        fh=2PkGp9mFds9J0Phg7xAJZYadxQ5cviKn0TzgqEPsAK8=;
        b=CJT/kpez7XFMbDFN8fywfs6/VmnAHnE+bcyCcSfC6wkigmxX/Ne2NN9GjqNw+9Sjfr
         nAau3ey8KgXxNSP8gy1lrC9nSGEcP0pgcb/j/0Sf8NhXvnsQroQn9tnrRa0GJmyZmziq
         Xnad43HTQ0cJtfu7zTQrG7X/wKJ793mZbnf9AObh11jD+r0rqv8TzbaMi+m22jQ9jZX9
         tQoLa5NdS4mlIAjnmpJgg0k4zAC0OUnZgFdPnksQrDSst+NLwGq/kMryX5KZpP7TrVty
         4yn9CcK+clZ6GSw2Uavm2nvxzhpeyn3YRYg+dxW7jG9WiSW/J9QppGSwlTxM+cO0Oj/F
         Xkig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=WGyqUFMD;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754679078; x=1755283878; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:content-transfer-encoding:in-reply-to
         :from:content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=akvUqBdw1cbaS0KikfBVczg5NrXJyu9odYRf567JjqQ=;
        b=j5+tpSDzzBO6K7F20hlzzF5c4lJ33viRBqDZmWW7Zy7bx+bY4wlcyEvwOAtu2a5zJM
         RdbxD3PCU8G0Wq+9YxMzv0dENi6x18s7meTKi1Jv2H2aH8Wnp16S2LNRfFDo3sHKF20a
         4R4kqHwtlCgeh1F4SB3LE50cJd8aCfH1U3xQar2UmLVhxfOBWcU4Pl6wah7ekHK5L3q6
         xVKd7INahHtnn0qCLw2KcDduigqsmZbJ2zLVvH+dNloPHWg+zah66Okq8fDozO0R7hsA
         r969HkU8ABaO7PrJZCU8wXP0+rhbXCKwVaQWk/EBH3yhF6Xv+E6ger5v2QzDPtvduRG2
         QM6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754679078; x=1755283878;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :content-transfer-encoding:in-reply-to:from:content-language:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-filter
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=akvUqBdw1cbaS0KikfBVczg5NrXJyu9odYRf567JjqQ=;
        b=G3FhBVallKhxfUv9MpH8mzyuc1VXbbggo9XltxFiN98bjgE//TZ40wrxG1ffyb720S
         uA2wHIvF+HNi//J47IbH56TZvQ9lDlWU28lY+C7TMt5FpGReLTuzag2M+hwFa/O4HGj+
         i1GL8/haz0WGKYCxboZQsdIessEYQ0+8ZGyB8DEe7kA/oK2Xp38WIhqNncnaOaA5tvxQ
         nbI1YHbCfWKbCawYKzgcoqyYttDZ6kVW7w7Aj18gGoMpdsFwV+X5cgsospWx3FT1uoTM
         UfbGC7aG3+6r/p8Glmk5XBXDF3r2tVz4QcXGBANC0crVFPmCEY7OF84jspaiZf8G0k5H
         Y+xQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUPCJYBqs8ccggKINb3VZZPyx5/nyPp3M0pHRjbYj6jTsIbK8i1jQEbcNlzrFnkFvKrPTk7/Q==@lfdr.de
X-Gm-Message-State: AOJu0YwWRWZxnqfC1zwOr19ZtJwj3OWTmPlUAPEG8sflfH5JUd2AhkzG
	qYgSeFjshTIwk+E7eaG4vBraATaYkIDH3vNKopQajOFMAv7NF9r1ysHR
X-Google-Smtp-Source: AGHT+IFzNXHZMWFSsBZAHqUOpbgJIS1pDIh+onYmwW4oWPOIzblpcoUcUTYoxQsOhEmA1O4ezGbGZw==
X-Received: by 2002:a05:6402:8d0:b0:615:223:e8ae with SMTP id 4fb4d7f45d1cf-617b38f4677mr5193806a12.15.1754679077556;
        Fri, 08 Aug 2025 11:51:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe9L7e8CtE/o6qsZ9GFzONKLjFJZ8YzXsh3qZNvMmDzhQ==
Received: by 2002:a05:6402:1d53:b0:607:2358:a304 with SMTP id
 4fb4d7f45d1cf-617b1ce0b1als1240366a12.1.-pod-prod-00-eu; Fri, 08 Aug 2025
 11:51:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZ+zG2uHvFgsERR86HSOrjz0cOFlGc4NF1kB7BdnWzfpUce0fb3gi1rBlbLmi23V5IrfxHjbT95DE=@googlegroups.com
X-Received: by 2002:a05:6402:4602:20b0:60e:3f7c:deb2 with SMTP id 4fb4d7f45d1cf-617e3032888mr2264612a12.12.1754679074793;
        Fri, 08 Aug 2025 11:51:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754679074; cv=none;
        d=google.com; s=arc-20240605;
        b=FOiA9Of84hS8sLgV8qeCUlFsnl8G6tj2fpWFMnM9xxRNnjCTAMMUesoyj8H6eOIeHk
         UXNPn0NTDB8x412P2w2iG4yxK430YGX75yQGn93IfA3qqnT6DU3nU4fZKrwV6t2yz2lR
         NcrJ15tBDpqhO3MDRHP/7GqKTcQTwAeqR3ebnL8aXwNhMZH5q+6Dr49RU/Eb1SXOT9S/
         82HXOXPTKFL0uduaZeTzHG/nOB1xUIgzmzmnLezC98HEFQQZiVp1q8QNUYDMauab0ttx
         cBqSRbEzuSRAB9WTUZrRbBjfjgGLdhyzACEzxFd7RPSZ9VRY68+NHW7A+yE06L1GhWYA
         p9jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=eZMpLLPpWLfEcYOqjTqa6+eB/bqRZJ+BbYqsgnnPbkY=;
        fh=8zUy9eVyy10sI6vo7zt7kRBAFba1pEnRAgAKKwuE6vk=;
        b=E9s7aJaWCPpWvt9fyTkvBRdVDcaskGAVud889lTtQ39fYMc34nPpVLKo1OsHGAPm66
         eHDGNCx8nGhAFk0OCpbiRQg2UqF2Nu5/+H2n7kl/rcu1LA+AwK3xjBh2e5LNL34Lcq0l
         aNY/QTrrClEvACwF3HjCIyKdcSDg7EnXVyzIL26cvhEiuEF7nDtadoA4sB0z7J6/qnxQ
         8vV8vhahCBuj78+XSoTUiN1wnbAP44nJ/NOQ9qE8G/yf8iH4dYXHQPWot/Bai5eex6XU
         Kia4hWynd6SApOdPslBRqJa2W2FfpclNvHcCIPDtkBNBrXiK/R/6C7VGQ+QYGHRNFGAC
         Z+Aw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=WGyqUFMD;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.w1.samsung.com (mailout1.w1.samsung.com. [210.118.77.11])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-615a8f80accsi541696a12.2.2025.08.08.11.51.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 08 Aug 2025 11:51:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) client-ip=210.118.77.11;
Received: from eucas1p2.samsung.com (unknown [182.198.249.207])
	by mailout1.w1.samsung.com (KnoxPortal) with ESMTP id 20250808185114euoutp0162c911292defe8bfee54f2309b1e8171~Z31I7WGpl0720707207euoutp01Y;
	Fri,  8 Aug 2025 18:51:14 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.w1.samsung.com 20250808185114euoutp0162c911292defe8bfee54f2309b1e8171~Z31I7WGpl0720707207euoutp01Y
Received: from eusmtip1.samsung.com (unknown [203.254.199.221]) by
	eucas1p2.samsung.com (KnoxPortal) with ESMTPA id
	20250808185112eucas1p285bfbeb3352a16df0b5c8f262fadbf2f~Z31Hzuzfc1555715557eucas1p2H;
	Fri,  8 Aug 2025 18:51:12 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip1.samsung.com (KnoxPortal) with ESMTPA id
	20250808185109eusmtip1cf791168d581e5b5b824a27d8cdd9069~Z31ElK-rK1126511265eusmtip1F;
	Fri,  8 Aug 2025 18:51:09 +0000 (GMT)
Message-ID: <a154e058-c0e6-4208-9f52-57cec22eaf7d@samsung.com>
Date: Fri, 8 Aug 2025 20:51:08 +0200
MIME-Version: 1.0
User-Agent: Betterbird (Windows)
Subject: Re: [PATCH v1 00/16] dma-mapping: migrate to physical address-based
 API
To: Jason Gunthorpe <jgg@nvidia.com>, Leon Romanovsky <leon@kernel.org>
Cc: Abdiel Janulgue <abdiel.janulgue@gmail.com>, Alexander Potapenko
	<glider@google.com>, Alex Gaynor <alex.gaynor@gmail.com>, Andrew Morton
	<akpm@linux-foundation.org>, Christoph Hellwig <hch@lst.de>, Danilo
	Krummrich <dakr@kernel.org>, iommu@lists.linux.dev, Jason Wang
	<jasowang@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joerg Roedel
	<joro@8bytes.org>, Jonathan Corbet <corbet@lwn.net>, Juergen Gross
	<jgross@suse.com>, kasan-dev@googlegroups.com, Keith Busch
	<kbusch@kernel.org>, linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
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
In-Reply-To: <20250807141929.GN184255@nvidia.com>
Content-Transfer-Encoding: quoted-printable
X-CMS-MailID: 20250808185112eucas1p285bfbeb3352a16df0b5c8f262fadbf2f
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20250807141938eucas1p2319a0526b25db120b3c9aeb49f69cce1
X-EPHeader: CA
X-CMS-RootMailID: 20250807141938eucas1p2319a0526b25db120b3c9aeb49f69cce1
References: <cover.1754292567.git.leon@kernel.org>
	<CGME20250807141938eucas1p2319a0526b25db120b3c9aeb49f69cce1@eucas1p2.samsung.com>
	<20250807141929.GN184255@nvidia.com>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=WGyqUFMD;       spf=pass
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

On 07.08.2025 16:19, Jason Gunthorpe wrote:
> On Mon, Aug 04, 2025 at 03:42:34PM +0300, Leon Romanovsky wrote:
>> Changelog:
>> v1:
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
> Lets elaborate this as Robin asked:
>
> This series refactors the DMA mapping API to provide a phys_addr_t
> based, and struct-page free, external API that can handle all the
> mapping cases we want in modern systems:
>
>   - struct page based cachable DRAM
>   - struct page MEMORY_DEVICE_PCI_P2PDMA PCI peer to peer non-cachable MM=
IO
>   - struct page-less PCI peer to peer non-cachable MMIO
>   - struct page-less "resource" MMIO
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
> will give the same treatement to the legacy dma_ops implementation.

Thanks for the elaborate description, that's something that was missing=20
in the previous attempt. I read again all the previous discussion and=20
this explanation and there are still=C2=A0two things that imho needs more=
=20
clarification.


First - basing the=C2=A0API on the phys_addr_t.

Page based API had the advantage that it was really hard to abuse it and=20
call for something that is not 'a normal RAM'. I initially though that=20
phys_addr_t based API will somehow simplify arch specific=20
implementation, as some of them indeed rely on phys_addr_t internally,=20
but I missed other things pointed by Robin. Do we have here any=20
alternative?


Second - making dma_map_phys() a single API to handle all cases.

Do we really need such single function to handle all cases? To handle=20
P2P case, the caller already must pass DMA_ATTR_MMIO, so it must somehow=20
keep such information internally. Cannot it just call existing=20
dma_map_resource(), so there will be clear=C2=A0distinction between these 2=
=20
cases (DMA to RAM and P2P DMA)? Do we need additional check for=20
DMA_ATTR_MMIO for every typical DMA user? I know that branching is=20
cheap, but this will probably increase code size for most of the typical=20
users for no reason.


Best regards
--=20
Marek Szyprowski, PhD
Samsung R&D Institute Poland

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
154e058-c0e6-4208-9f52-57cec22eaf7d%40samsung.com.
