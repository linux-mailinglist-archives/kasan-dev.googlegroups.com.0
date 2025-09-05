Return-Path: <kasan-dev+bncBDG6PF6SSYDRB2M35TCQMGQEYP3S7MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id B93E1B45DD6
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 18:20:58 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-3e1260394dcsf1172539f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 09:20:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757089258; cv=pass;
        d=google.com; s=arc-20240605;
        b=LyvA19LRB1/G52ce5NPYKdob7KEsTkUl0xgdKJClNDyArXRmVtWkC5tsm8cxmtZPO6
         M3BgaNG+ZFxHiuA1QdZcCK3qnKL/sNJedbc65+ciyoEpYlUvZ4Liba3eYaWGr/rLWRey
         5FCpsQw1ubsvUO4Ec/zZV5eUFRL51esPM077bKuq+mknjBQssPDw1dGMyaJDZebFn/bb
         84d4EaCSvevw6HfMkjiBpRncDfm/Oxtb9uw5vf3I2BTA20F1nhmmMcnib+xybJ6hQUop
         //86tiLCOnPvR8UWBImd78e6b9L34EI0MP6zJH1SebFR1JD+Tj9Mlo1N6ie/qdDmux61
         p0Ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references
         :content-transfer-encoding:in-reply-to:from:content-language:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-filter:sender
         :dkim-signature;
        bh=3RHSTLkKk2DvaCR+mBw88Ssf8rhCA845h2DXdODkM1o=;
        fh=f19tbYNS+sJDBEvf3f9F36n8FAyROvcnWdD01jlfJgw=;
        b=Zf/vOKyzZ/vAocMADYH5iF8O5JYwwfx9TMan13O7LzZ94jQT2nRHCgjwzdhL17lF2B
         I6pZvjjxTmuwEQZ23Fht3q734giSn+fEDtyxeXiuQA02T5fScJEEIeb6NsO8YZMMVPZI
         MmImujzxv2PQPIQcapDGcn7f81YdolfuH/S93oxIw3GRXUXLYa9e2roL4fszlV8Pa5wI
         nNAFJWcWGv85Of5j4xjShvA5L1Niy6LRFIUbNZoazv/ck097u2PhgkQgHYfgveVlvA6P
         0qddLP5DUMLlHJY74hJ+1E854f9VcvEZTuOYBQUnyFZYAW6QWK42U/ItYqFZL7e5r0mR
         u7DA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=BH1gDTlm;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757089258; x=1757694058; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:content-transfer-encoding:in-reply-to
         :from:content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3RHSTLkKk2DvaCR+mBw88Ssf8rhCA845h2DXdODkM1o=;
        b=AdsMxdWdk4kCGCvmB3LCbb7S88FOOHLRb2929Usxhoj1qqbK9f9ghvGLWVVgOzZ95c
         iikE6VDjNk4WN45V8FMJBKPgV1uwsaCjb5MkBzDV+zrl3ZxqZaUGp9N++oaBTGIznR7N
         u+Oe5uB7s1rcvHoXgZrLWHj3tyM3qSz/dSeqC4Bo2Bf3VdjfIcDnNEB74OFdcdLuAc+F
         4kNRt0N2oaNbxURm1ncPbwwnbrqSlI4lG18r1VTvgiDgIgihVrCWxdwWhAriYStWAPNB
         Kc/Ftd/XZyPxFB3qGyPRvOYPpfpzV6C3jnrEbv2Lk4SjHFATcpaKTwe8KaFDM9Gox/m3
         Tt9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757089258; x=1757694058;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :content-transfer-encoding:in-reply-to:from:content-language:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-filter
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3RHSTLkKk2DvaCR+mBw88Ssf8rhCA845h2DXdODkM1o=;
        b=AdE8RDmz2gXzpRcYyvtH2iHZooALLZ1y8uJ/T9F1n6r3dmM8yRCj6UGMQ8P9+MSD4d
         t2PpqA6R9btLCJOebDXf5qGefKjC5iFigoU7z6eRaDDgfk/gP+mnJgN2MYxUS/jm0cXc
         VrngA0h86yIwKOAuqSp3Hkad37xf4XDst+lm0g5BhHpwIMHwqtXGxCQHTYJSPB53oeze
         ggCmOOLKallQ/37ABJA5sUohCZ5J1HSC3URB6F0YMGpPp40egiahiCaddxGEsDTiSxNY
         6Oaq1jJ5KFJjXBGKtDRe/O8tnltq6n47pN8wTBlwUeCyuZFJULinUFTQfcXNgk8ZjWHF
         aDIw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUz4BBZo6CXxAP5aiQsGFAeAYG+Lgo2b6//w6QaYpq+du8gKpfOhAEVzJnlNsbXHBUyZNPPKg==@lfdr.de
X-Gm-Message-State: AOJu0YyEl1hxIMGnOv0Wqk98x8SHYuqq3qkTIj2k0gFHubJWOQL3ARma
	QA4Se2zoPH2AMUrUXF7jpNJumgRuecf6y0byoXZ5P5iii/eJSZiwf4je
X-Google-Smtp-Source: AGHT+IGFcVAiTL+CfbJwvzbvA+2YRFWE9HlvmrcDsAV1mt1y7I/dOtpuED/U69pS0JM9YiB//dW1bg==
X-Received: by 2002:a05:6000:2089:b0:3e2:f336:7731 with SMTP id ffacd0b85a97d-3e2f33677f1mr3440050f8f.16.1757089257750;
        Fri, 05 Sep 2025 09:20:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfwQxwXsoYylD+6N+8uuT9uoQzCxJeGi4Gulzpr2/2pjg==
Received: by 2002:a05:600c:1d22:b0:45d:d27e:8caf with SMTP id
 5b1f17b1804b1-45dd83dfc4els5793475e9.2.-pod-prod-01-eu; Fri, 05 Sep 2025
 09:20:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV2OSYmE94Jv8X98mvQ7So890IzBgzzdogD4SqtBhKxv/qM03RmC4dVDeFm8Bve3bI6fwRuUk81OLw=@googlegroups.com
X-Received: by 2002:a05:600c:45cf:b0:45b:868e:7f80 with SMTP id 5b1f17b1804b1-45dd5d2186cmr38401505e9.8.1757089255046;
        Fri, 05 Sep 2025 09:20:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757089255; cv=none;
        d=google.com; s=arc-20240605;
        b=SLXXqGerbU6Z2z4EjPo7Ll6louqmnMzJphHZvxc1QnhXg1FgUsNUyA2zMmnmGaejeY
         LZhYl0lhP3mI+FbujFCrTRDdBoEK7R4ydgtpxbr0x8XinXHR0RAQzYgRS0i24mng0lz8
         SCiQ/doNWyeK8O6hD482jFf8XmWEpAebQ/vLOzhAclKaLLBG/SgvkiaziCBuKscRInkJ
         yqrdkT3i64p3m1X0QEhR1iG/nTwzmdmtVjkaILiJRMuqErgCyHTZ4itfqeAXqLv/nBVQ
         1vjkIlkzh1T5cVLUgAttIFG8q6bjhz7HtoIQxdMrHORqPn0pWmxoNu0d61YR9XmVTyPx
         OUew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=r+uJO0KPgHoqZtk4UB2d6cw6Lk6DbEyEjBWC0P92zgA=;
        fh=8zUy9eVyy10sI6vo7zt7kRBAFba1pEnRAgAKKwuE6vk=;
        b=aHtDz2ghuCIggsmrl5p9FzgxqLrw2db28Jv/A/LsA7YkIpjPPLjPv7x6irn9Y2G1Oj
         WpNI9CTLX9ZB7vdBwHNv5Y55Zs2KrWpXwwUIMsBfNmN53SpjlFClK2UJWCBUvroGvyBy
         nlE1gabu368ngQGZZq6fOMezhytN21xttjOE2se0Ngf1Wk/235WFeCQLyPu2raQIGWLZ
         U0tOWKLJsQNHey6HbsQT4DRzMNTK40U5e704zcEpSJx+9xv/PM48XKcgUG8S0a4vgHej
         HJtP64W8XoZpmZr977il1n/tn5+DpHL4aht0bcdn+NeraknKmu3LthbrEiXZlXcbZPEK
         XLDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=BH1gDTlm;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.w1.samsung.com (mailout2.w1.samsung.com. [210.118.77.12])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45b9c6073e2si1798315e9.1.2025.09.05.09.20.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Sep 2025 09:20:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) client-ip=210.118.77.12;
Received: from eucas1p1.samsung.com (unknown [182.198.249.206])
	by mailout2.w1.samsung.com (KnoxPortal) with ESMTP id 20250905162054euoutp02e77d244e0cafd5d952c3328dee47f20d~ib14B25gK1750017500euoutp02R;
	Fri,  5 Sep 2025 16:20:54 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.w1.samsung.com 20250905162054euoutp02e77d244e0cafd5d952c3328dee47f20d~ib14B25gK1750017500euoutp02R
Received: from eusmtip1.samsung.com (unknown [203.254.199.221]) by
	eucas1p1.samsung.com (KnoxPortal) with ESMTPA id
	20250905162053eucas1p1b9fec0adff4c7d35b6b6add1249d881b~ib13cmmn22364123641eucas1p1e;
	Fri,  5 Sep 2025 16:20:53 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip1.samsung.com (KnoxPortal) with ESMTPA id
	20250905162051eusmtip1e4d21f9bc61a423579ce48c4e618b6af~ib11sI1Nb2344623446eusmtip1s;
	Fri,  5 Sep 2025 16:20:51 +0000 (GMT)
Message-ID: <7557f31e-1504-4f62-b00b-70e25bb793cb@samsung.com>
Date: Fri, 5 Sep 2025 18:20:51 +0200
MIME-Version: 1.0
User-Agent: Betterbird (Windows)
Subject: Re: [PATCH v4 00/16] dma-mapping: migrate to physical address-based
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
In-Reply-To: <20250829131625.GK9469@nvidia.com>
Content-Transfer-Encoding: quoted-printable
X-CMS-MailID: 20250905162053eucas1p1b9fec0adff4c7d35b6b6add1249d881b
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20250829131641eucas1p2ddd687e4e8c16a2bc64a293b6364fa6f
X-EPHeader: CA
X-CMS-RootMailID: 20250829131641eucas1p2ddd687e4e8c16a2bc64a293b6364fa6f
References: <cover.1755624249.git.leon@kernel.org>
	<CGME20250829131641eucas1p2ddd687e4e8c16a2bc64a293b6364fa6f@eucas1p2.samsung.com>
	<20250829131625.GK9469@nvidia.com>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=BH1gDTlm;       spf=pass
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

On 29.08.2025 15:16, Jason Gunthorpe wrote:
> On Tue, Aug 19, 2025 at 08:36:44PM +0300, Leon Romanovsky wrote:
>
>> This series does the core code and modern flows. A followup series
>> will give the same treatment to the legacy dma_ops implementation.
> I took a quick check over this to see that it is sane.  I think using
> phys is an improvement for most of the dma_ops implemenations.
>
>    arch/sparc/kernel/pci_sun4v.c
>    arch/sparc/kernel/iommu.c
>      Uses __pa to get phys from the page, never touches page
>
>    arch/alpha/kernel/pci_iommu.c
>    arch/sparc/mm/io-unit.c
>    drivers/parisc/ccio-dma.c
>    drivers/parisc/sba_iommu.c
>      Does page_addres() and later does __pa on it. Doesn't touch struct p=
age
>
>    arch/x86/kernel/amd_gart_64.c
>    drivers/xen/swiotlb-xen.c
>    arch/mips/jazz/jazzdma.c
>      Immediately does page_to_phys(), never touches struct page
>
>    drivers/vdpa/vdpa_user/vduse_dev.c
>      Does page_to_phys() to call iommu_map()
>
>    drivers/xen/grant-dma-ops.c
>      Does page_to_pfn() and nothing else
>
>    arch/powerpc/platforms/ps3/system-bus.c
>     This is a maze but I think it wants only phys and the virt is only
>     used for debug prints.
>
> The above all never touch a KVA and just want a phys_addr_t.
>
> The below are touching the KVA somehow:
>
>    arch/sparc/mm/iommu.c
>    arch/arm/mm/dma-mapping.c
>      Uses page_address to cache flush, would be happy with phys_to_virt()
>      and a PhysHighMem()
>
>    arch/powerpc/kernel/dma-iommu.c
>    arch/powerpc/platforms/pseries/vio.c
>     Uses iommu_map_page() which wants phys_to_virt(), doesn't touch
>     struct page
>
>    arch/powerpc/platforms/pseries/ibmebus.c
>      Returns phys_to_virt() as dma_addr_t.
>
> The two PPC ones are weird, I didn't figure out how that was working..
>
> It would be easy to make map_phys patches for about half of these, in
> the first grouping. Doing so would also grant those arches
> map_resource capability.
>
> Overall I didn't think there was any reduction in maintainability in
> these places. Most are improvements eliminating code, and some are
> just switching to phys_to_virt() from page_address(), which we could
> further guard with DMA_ATTR_MMIO and a check for highmem.

Thanks for this summary.

However I would still like to get an answer for the simple question -=20
why all this work cannot be replaced by a simple use of dma_map_resource()?

I've checked the most advertised use case in=20
https://git.kernel.org/pub/scm/linux/kernel/git/leon/linux-rdma.git/log/?h=
=3Ddmabuf-vfio=20
and I still don't see the reason why it cannot be based=20
on=C2=A0dma_map_resource() API? I'm aware of the=C2=A0little asymmetry of t=
he=20
client calls is such case, indeed it is not preety, but this should work=20
even now:

phys =3D phys_vec[i].paddr;

if (is_mmio)
 =C2=A0=C2=A0=C2=A0 dma_map_resource(phys, len, ...);
else
 =C2=A0=C2=A0=C2=A0 dma_map_page(phys_to_page(phys), offset_in_page(phys), =
...);

What did I miss?

I'm not=C2=A0against this rework, but I would really like to know the=20
rationale. I know that the 2-step dma-mapping API also use phys=20
addresses and this is the same direction.

This patchset focuses only on the dma_map_page -> dma_map_phys rework.=20
There are also other interfaces, like dma_alloc_pages() and so far=20
nothing has been proposed for them so far.

Best regards
--=20
Marek Szyprowski, PhD
Samsung R&D Institute Poland

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
557f31e-1504-4f62-b00b-70e25bb793cb%40samsung.com.
