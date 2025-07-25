Return-Path: <kasan-dev+bncBCUJBAM67YFRBJGHR7CAMGQE5UTH25A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C4ACB12520
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 22:06:01 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-31e3d563a53sf3454204a91.3
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 13:06:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753473957; cv=pass;
        d=google.com; s=arc-20240605;
        b=azN51Htyh+JmvMO2z9HpjqMipGP5xkPuSZKqxiHOelMDgLGdMG7ilMmGy4CO5F435s
         0k9vD9m9gGmfyMBIExYyFUn0wEa+BuvM9zvXbMA/picWZr7VL6652xi4VjBAYxTjRLJA
         a358EU/5H0jgb7/uIdvJ0I8H2TO7z8jtQgong3rluBPC1rhVbxVvugfGqCeTp7+cM+AV
         vU/GCz444MFRuSQSH8+xgZuNsQWfUeR9rS97jI8yBk4ag4g9fep0wnaRWMHaRwbAbxhw
         ifc0OU8mAXzk743qd/dP8HI7UUh9cE9nB2aqYPeVbPrseLh6qak4IQgzbOfpJwFuJOm8
         ZSRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=33ErXTMil1SzGbRzJHEK33EOIY8288zjV/ehJhzdI9c=;
        fh=0TRwfu6iFfAIM67d+xYXSoR0XfPlnROnJ+ddglyemvc=;
        b=aq+MMWOdLI5s+iqXrGODzOUlAoJ8w3dA8ci1qJc45H90Qaoc6iI6co8XFhIYTlpjVV
         mDd2Fg8QAJdWQCNeDoUKTp//2AwAok82T3XwAriqsZ7AotAbNXcgfB6CjWXRGtioRDXx
         73btY1xXC/qS1duZRIZPWRmEipAwF41nyVRZhYuPRN6dRvpDagGErao8WUsW+W7/28u7
         fsYdEQ/sj3N45VfTGEcKwJdz4RZAOaUxQ/kXHor4R+RgvojhhIo6pM/uNJ+70az9SZ3T
         XVQpUSt6WkzO2aOZWkq85zCfdFm/q0OsoHYna8PK0pziXi2enOYQ1DHC/rubDjahiyf0
         KMgg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=robin.murphy@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753473957; x=1754078757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=33ErXTMil1SzGbRzJHEK33EOIY8288zjV/ehJhzdI9c=;
        b=mqotwYBJMrDhts7/CmVxP+3WZQ44xXONeOezpevt20JM4IQiaTLoer8FlCJaPM+tqX
         8iafrDCB5I7O0PIsaDxUT6hWteA3jWO7c0TuoNA6kjeYSsVEji7laHp6GGq7kqR+tYYD
         f/lwVcmUhu+kwY46fw0u8K7YCjlNZ1uCdKgriQ9ceYZXSw+owUPe1/G4NZ8oTTYm+vj9
         48dc5coOY2TdLcikH6S3fHaqZF8winhpopN4dJBUJfBiQbVhi/oGOTPGbgh4A+xWJeQX
         R0S6SlM4qsSG/Gkx5bxHmekWGjXrcQagp7Y07UdEsntLJfX2VtdWMH73kgTsavN6LOiG
         iDlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753473957; x=1754078757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=33ErXTMil1SzGbRzJHEK33EOIY8288zjV/ehJhzdI9c=;
        b=dT0FkioLPW4rylbbkzXk0mvEKTCMeqvFVdTxO/X8gYTtfYl+ZA/WPvhU1HGtpgS3hk
         buIrDgMmVGafZZljWOjjN/BaifmVE0bh3YHdoOxjVH/UPKAx1MGLUQ922G9QhPvCTjjD
         KQnSMkLYbB3YJK06WRdKAfH8Oedos4crn9u7czVB/W2bIqWsY24wMbg41aDOsjowdeKW
         fUxNZs6Ye3kdSAxKHmUaDy2rqcvKfD8qUYDrbB2599p9xqueUUFFVNrKq9NEZF1liYRm
         jmC9Jn4w9H9poP4SQlVSdVNkqXSVO9zMgd9jaedaSukMeO6tmIqb+d81DvVOmBLXiYC4
         EqVA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV5QLSQCBD2hRwKfGAb2r4QMjpMn504sfcBO35rMAdFwWmTvwT29qhoKqDDJXiIro2G6ctGlA==@lfdr.de
X-Gm-Message-State: AOJu0YxDjVmkOqSkSGEGWj5QIeARejwai+rhacpgGAfBd2HvzHoXLKzc
	rOclTuoe+gGGI/jRRjycT1IEpy49eXrGHE8nauYZTGMzjMFiwM/aPOiL
X-Google-Smtp-Source: AGHT+IHj4PzKnF4iETjN1+oS2w8yIWqft7SImEkqu4D8bRhGsxZ3K/09sNQJPv5bQguUhqfwVKJDNQ==
X-Received: by 2002:a17:90b:3141:b0:311:d28a:73ef with SMTP id 98e67ed59e1d1-31e7788d06emr4811837a91.10.1753473956940;
        Fri, 25 Jul 2025 13:05:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfVEtCxkdh1fpKIonH9SIS17KIPMvN3jlm0DFmTNnxvuQ==
Received: by 2002:a17:90a:108f:b0:314:21ab:c5d3 with SMTP id
 98e67ed59e1d1-31e5fabd0afls2407298a91.1.-pod-prod-06-us; Fri, 25 Jul 2025
 13:05:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXlYjg5J3HHLtrYT36O68CGuoEpzRgXLV2SEt5DHx1CIvSxwzHA/P2y1UpqXQzHD0LPcCb8ckkmqvY=@googlegroups.com
X-Received: by 2002:a17:90b:38ce:b0:313:f83a:e473 with SMTP id 98e67ed59e1d1-31e778a4218mr4532990a91.15.1753473955428;
        Fri, 25 Jul 2025 13:05:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753473955; cv=none;
        d=google.com; s=arc-20240605;
        b=jR4wgRJybhhgDBpAkXOT+OwCprVPNEBB939wHCvQtYUmyVguDyyhmCY6Q4r1t0T0TD
         m+TlaZpOQ7+h7CvdODfptckddTvQPOqGdA03b4Fdk3wBis3lVCBXxujy899Y3kmjq0fb
         ENne9mctQf8bdYn1ncu84kAYh2Nm6wdSw2SuvWvQsABENwPmAZt4mrFLWrlE2CDvORdK
         y8NL20P5GO5iId2UdUq5D1auTSnDYBGT1QBr8l9JBMSr3crALxOdnP8F/sSiNFrTGeX6
         VojmNxLhG2nq7T2RsLvADUGkprrd0AUeQHPffrf+FeNz+slhb6ICtio7grbESuhimZ+Y
         xADQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=7KxOmurkyhSp/5ecauaZ/zErl9WiG9PB8RxRwEHPPjE=;
        fh=ubkqpMocYGmVknHdUqUJj6zRAVVlCm9mKqEE0MDosUg=;
        b=IAMvvZDR8TC0Myjgd5F3Vpy4svY8eA+eo1JYqX/jg5JseNZnCUzPmRNxFkQpanHW+O
         HP044CgOiMZtF9m/299+6FZsyzCVegoQ04hkswFloM5fWYeRIHmCWw17i6c+4jIMTNN8
         ocFiSsLyI9E7LtTO9TnrHCGNDC5MvQylVP6ApxnPGdtY5c+ZXSd3Y3gp/zQNhyJ2C+hO
         rkosmdXTRV34HCO5+RIxFP2gk6qKUVA2285KEAU+DPv03XSvY0mHR1HxkjyrIu0ucUMi
         ygVEFy2HQiwZfOCVVHJEID4DQdFOn66HU35dWuT0I6qwNqHT3d3d66nG2cGyGoG81F7q
         p73w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=robin.murphy@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-31e6224edafsi200557a91.1.2025.07.25.13.05.55
        for <kasan-dev@googlegroups.com>;
        Fri, 25 Jul 2025 13:05:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4BFC91A00;
	Fri, 25 Jul 2025 13:05:47 -0700 (PDT)
Received: from [10.57.4.83] (unknown [10.57.4.83])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1A7893F6A8;
	Fri, 25 Jul 2025 13:05:48 -0700 (PDT)
Message-ID: <751e7ece-8640-4653-b308-96da6731b8e7@arm.com>
Date: Fri, 25 Jul 2025 21:05:46 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 0/8] dma-mapping: migrate to physical address-based API
To: Leon Romanovsky <leon@kernel.org>,
 Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Christoph Hellwig <hch@lst.de>, Jonathan Corbet <corbet@lwn.net>,
 Madhavan Srinivasan <maddy@linux.ibm.com>,
 Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>,
 Christophe Leroy <christophe.leroy@csgroup.eu>,
 Joerg Roedel <joro@8bytes.org>, Will Deacon <will@kernel.org>,
 "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>,
 Xuan Zhuo <xuanzhuo@linux.alibaba.com>, =?UTF-8?Q?Eugenio_P=C3=A9rez?=
 <eperezma@redhat.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Masami Hiramatsu <mhiramat@kernel.org>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 =?UTF-8?B?SsOpcsO0bWUgR2xpc3Nl?= <jglisse@redhat.com>,
 Andrew Morton <akpm@linux-foundation.org>, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
 iommu@lists.linux.dev, virtualization@lists.linux.dev,
 kasan-dev@googlegroups.com, linux-trace-kernel@vger.kernel.org,
 linux-mm@kvack.org
References: <cover.1750854543.git.leon@kernel.org>
From: Robin Murphy <robin.murphy@arm.com>
Content-Language: en-GB
In-Reply-To: <cover.1750854543.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: robin.murphy@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=robin.murphy@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 2025-06-25 2:18 pm, Leon Romanovsky wrote:
> This series refactors the DMA mapping to use physical addresses
> as the primary interface instead of page+offset parameters. This
> change aligns the DMA API with the underlying hardware reality where
> DMA operations work with physical addresses, not page structures.

That is obvious nonsense - the DMA *API* does not exist in "hardware 
reality"; the DMA API abstracts *software* operations that must be 
performed before and after the actual hardware DMA operation in order to 
preserve memory coherency etc.

Streaming DMA API callers get their buffers from alloc_pages() or 
kmalloc(); they do not have physical addresses, they have a page or 
virtual address. The internal operations of pretty much every DMA API 
implementation that isn't a no-op also require a page and/or virtual 
address. It is 100% logical for the DMA API interfaces to take a page or 
virtual address (and since virt_to_page() is pretty trivial, we already 
consolidated the two interfaces ages ago).

Yes, once you get right down to the low-level arch_sync_dma_*() 
interfaces that passes a physical address, but that's mostly an artefact 
of them being factored out of old dma_sync_single_*() implementations 
that took a (physical) DMA address. Nearly all of them then use __va() 
or phys_to_virt() to actually consume it. Even though it's a 
phys_addr_t, the implicit guarantee that it represents page-backed 
memory is absolutely vital.

Take a step back; what do you imagine that a DMA API call on a 
non-page-backed physical address could actually *do*?

- Cache maintenance? No, it would be illogical for a P2P address to be 
cached in a CPU cache, and anyway it would almost always crash because 
it requires page-backed memory with a virtual address.

- Bounce buffering? Again no, that would be illogical, defeat the entire 
point of a P2P operation, and anyway would definitely crash because it 
requires page-backed memory with a virtual address.

- IOMMU mappings? Oh hey look that's exactly what dma_map_resource() has 
been doing for 9 years. Not to mention your new IOMMU API if callers 
want to be IOMMU-aware (although without the same guarantee of not also 
doing the crashy things.)

- Debug tracking? Again, already taken care of by dma_map_resource().

- Some entirely new concept? Well, I'm eager to be enlightened if so!

But given what we do already know of from decades of experience, obvious 
question: For the tiny minority of users who know full well when they're 
dealing with a non-page-backed physical address, what's wrong with using 
dma_map_resource?

Does it make sense to try to consolidate our p2p infrastructure so 
dma_map_resource() could return bus addresses where appropriate? Yes, 
almost certainly, if it makes it more convenient to use. And with only 
about 20 users it's not too impractical to add some extra arguments or 
even rejig the whole interface if need be. Indeed an overhaul might even 
help solve the current grey area as to when it should take dma_range_map 
into account or not for platform devices.

> The series consists of 8 patches that progressively convert the DMA
> mapping infrastructure from page-based to physical address-based APIs:

And as a result ends up making said DMA mapping infrastructure slightly 
more complicated and slightly less efficient for all its legitimate 
users, all so one or two highly specialised users can then pretend to 
call it in situations where it must be a no-op anyway? Please explain 
convincingly why that is not a giant waste of time.

Are we trying to remove struct page from the kernel altogether? If yes, 
then for goodness' sake lead with that, but even then I'd still prefer 
to see the replacements for critical related infrastructure like 
pfn_valid() in place before we start trying to reshape the DMA API to fit.

Thanks,
Robin.

> The series maintains backward compatibility by keeping the old
> page-based API as wrapper functions around the new physical
> address-based implementations.
> 
> Thanks
> 
> Leon Romanovsky (8):
>    dma-debug: refactor to use physical addresses for page mapping
>    dma-mapping: rename trace_dma_*map_page to trace_dma_*map_phys
>    iommu/dma: rename iommu_dma_*map_page to iommu_dma_*map_phys
>    dma-mapping: convert dma_direct_*map_page to be phys_addr_t based
>    kmsan: convert kmsan_handle_dma to use physical addresses
>    dma-mapping: fail early if physical address is mapped through platform
>      callback
>    dma-mapping: export new dma_*map_phys() interface
>    mm/hmm: migrate to physical address-based DMA mapping API
> 
>   Documentation/core-api/dma-api.rst |  4 +-
>   arch/powerpc/kernel/dma-iommu.c    |  4 +-
>   drivers/iommu/dma-iommu.c          | 14 +++----
>   drivers/virtio/virtio_ring.c       |  4 +-
>   include/linux/dma-map-ops.h        |  8 ++--
>   include/linux/dma-mapping.h        | 13 ++++++
>   include/linux/iommu-dma.h          |  7 ++--
>   include/linux/kmsan.h              | 12 +++---
>   include/trace/events/dma.h         |  4 +-
>   kernel/dma/debug.c                 | 28 ++++++++-----
>   kernel/dma/debug.h                 | 16 ++++---
>   kernel/dma/direct.c                |  6 +--
>   kernel/dma/direct.h                | 13 +++---
>   kernel/dma/mapping.c               | 67 +++++++++++++++++++++---------
>   kernel/dma/ops_helpers.c           |  6 +--
>   mm/hmm.c                           |  8 ++--
>   mm/kmsan/hooks.c                   | 36 ++++++++++++----
>   tools/virtio/linux/kmsan.h         |  2 +-
>   18 files changed, 159 insertions(+), 93 deletions(-)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/751e7ece-8640-4653-b308-96da6731b8e7%40arm.com.
