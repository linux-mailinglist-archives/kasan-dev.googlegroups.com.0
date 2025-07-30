Return-Path: <kasan-dev+bncBCUJBAM67YFRB3P3U7CAMGQEWHBEKCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id D9B4FB15F1E
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 13:11:51 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-31ed9a17f22sf5550576a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 04:11:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753873902; cv=pass;
        d=google.com; s=arc-20240605;
        b=F6vUNEfHG1qDnC0maK3apclfq3tp1wiYV/KfMIAS5NOvuoqWBM1+ETFFgBd4A3DvBG
         SuBs4Jr3NxrQkUB1aNBaIY0Tiv2cPRsRAKLOWHYpnsYYBts0DS7r/bnY9T956N1RidPw
         m9oU0EyCLIu4Mip988VKmgDuGmfCDFORn2AyL7YMsTm2zRwWHyIJscPhCC/jwlGQ/WoI
         6AW2EyaGF+tM1nU8wCP5XzHfpSsUWNAfAgHymiBFzfSy6qab/Ot5FF6CURvNqJBEw0Cr
         UYOffdJMw4TGZgJ2YqPSfPmbrjxBnlA5SXixzvwTq5BQAFTzvpIzmsysn7zy2x9gLXbL
         WkwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=TqCUuM1htNJjpWZ4+Y728AALzOO0tmUTNUrM/JKWowk=;
        fh=PiB1aEvP/XQIpr5eh9ItBcc7TOMYHWxC4TMOXM8Hvn4=;
        b=C0CIPWQIPCJNpWbkDgmo/ok2UK73oR5MsaqVZzyJ1iJVQlLkZUulIHjZYyLIXC/prZ
         rPIdv0DokauDykePwYlP+znwB3ORfQgZIw8tjHkjaaaEY4IekQogylufUuAlgb/gPE27
         tPjmxDhigV0w9LmiMdktSa+24lWNoo7O+l3yHCvKuKcesxtBTok4qb6vbX4PQpDBBRKr
         H0+XDI3J67eo2Sb8ATIwAznixv+a4GVm1p2BQb36X+qiu2fWZY+8iYlU232Io4KegmzI
         iKSWrwibf6YtPmMKcI+SgbBPS48JFVHaYWaxpkmr1XgKxofJn/0znkkQU8gCQbPKTHEq
         M8fg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=robin.murphy@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753873902; x=1754478702; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=TqCUuM1htNJjpWZ4+Y728AALzOO0tmUTNUrM/JKWowk=;
        b=M8iB/pqHhGDIjyLOEBwm7jU3G0RuD/vcv6l4jiRsYgKdU+BI/m32aam0sYvxtyK3nG
         KqM3SXTVuU4k8EZN2/7OyAcXG7njaxBCJMK08/5M6sq62YadnGhuxsPXK6QdeZ2HtSKl
         TtFD7ew7QYUZpSwT0zW+Vr2uPd15ZUX0f+SGpIwNWuAQ1l7eaPsm40xO6iOH9ghCAiGa
         hBDTKVYmPvBa/WTY/GuufgkE0nmJwls1cgtezJmm8cwN60yxME1Ig257mh+XxcWxYPjt
         Dhiz5zaj3gWVtlUJRWbywvvuXJBnJSuIvBiDd3nnmCW8KOIyK9xaclEfqc31HyB7eIac
         OpHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753873902; x=1754478702;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TqCUuM1htNJjpWZ4+Y728AALzOO0tmUTNUrM/JKWowk=;
        b=Nd5UVf6wgZej/7JqkpVY9bxTxXNsyY1o/+dIapP+yKCDxvflIYFzSN34M6/0zPK4ss
         8op/7C9tXjlv0IBJS87Q9eh8peyZtBiSOzcyYlmeAtmr6fEK5FfVnXqgqglOeKW9Xi2Z
         /WvSIC3HLMOtQ8OlFIf4TS7DzwctYNMczzPzVUj086vORGzXHHi1sgnSGFemN4V51bSR
         IWUyFaVAjNS3KurfEOvucF11rLQ0pQm6FMFiQS47s1GKhsdgap61EpUqeAS6u2FcbWrX
         a5QCcmfytx/MbZ4zuZDzacAIU4nDXewP7SL9aVzRoQZLTKcn0jOUuufhBSuHKnvB5FCR
         XGBw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWgyRqangVjDM5xa8SL70zPWw3v3G7Nq1YvynBcsCgJsQb0AoOre/P8d7t+JevUUvp5srQ0Xw==@lfdr.de
X-Gm-Message-State: AOJu0Yzq/58Y2RFktR1LZQFHso+CvZDOWRIQMbkQjCsTzprlSXSUsSlH
	a7y4LwNkUq9DjghFMn2BLAhJcEBO7ZA+TyvNRmMmzot3xVK2ypIHbqBm
X-Google-Smtp-Source: AGHT+IFSDLbUTohKQ9xm3UK4T7o6wpwBSsvN8r6ww2Ae/S1/FZOWPVWUrcMReQjCvTrK7ZX7zlhTog==
X-Received: by 2002:a17:90a:e70f:b0:312:25dd:1c99 with SMTP id 98e67ed59e1d1-31f5de55570mr4511841a91.19.1753873901714;
        Wed, 30 Jul 2025 04:11:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfxp983bUQUUPoge2r6p9R55MhSFWiq3dRbOv8Wkc/QJw==
Received: by 2002:a17:90a:1016:b0:31e:b3c1:308 with SMTP id
 98e67ed59e1d1-31eb3c10497ls3913594a91.1.-pod-prod-06-us; Wed, 30 Jul 2025
 04:11:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU5GcLqa7Eww1Horjc6corw8zv6SzAdN6aX1abZ9TOSg8SPgRaqsaYx8fnMv9sHXh2pwkWQejPYLmY=@googlegroups.com
X-Received: by 2002:a17:90b:4a0a:b0:312:e279:9ccf with SMTP id 98e67ed59e1d1-31f5ddb7e79mr4276968a91.5.1753873899869;
        Wed, 30 Jul 2025 04:11:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753873899; cv=none;
        d=google.com; s=arc-20240605;
        b=JBh4OPDe/PD0LLrfXn5uXUyFPiND4YkaRr2Wj4okalxircR9/7MQ7riQYEYHL8Fz19
         5M2p8I0UlVBguw/EE/nRpZU6XBGmLOda5ZbFYiVwm8rLJ4Bf6cVeoryhKpT7rsdVgfuQ
         btak3dplLrkAzIs9Uk/ZJ8OENt9WmPvb//PxOU0qIBjx+dGPnM6l0lCsdEDsnZp6v1dL
         DOG9q0/3/mgKc6Q2FZFqoAhe0YjM9F1J8FncdEgsCpPlTiKMIb+wiCL056FHowLx4GnK
         sg0Dy8rP2jWWSM3PmmHrMv+bJ1u1/napQ3hw++wgvQJm9eJpF3S9wgmPRquG/CpyB9KA
         BB+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=tTgLyvTZgN5Rt8Z+AwFysB1xxPIwzHY5WQRBxQh+D0k=;
        fh=LOOrIZb2MUEW+lG6ZEp720tZf8V2uYYWyUVOa30ySOM=;
        b=UIzy+WSOyIFbe+Piy+WHwdWWs3dKqpEvQhSXt+YAy1YoaWRI4N1aSBjzJ14u4eCWwT
         9iyUqT3Q5t+bDLE1BJlh7N3KlYfMFLNsXTKeEoP804vBUAzL8UklF97nf7TitaCQjeKP
         N+g2gU6W+iXEKu2k3Tw9ar86gVkPZCNeNlSoOWk17d8x9P7NoQw/oCulv8zcZbgPBxTg
         sX2loEvcNzab1ZVAeuqDYgK9RakSRJLPDxrV8Uz3RG9hhxALd9V8wlF8l4Nsnohuqdj+
         tlVzNxNGvEAUHcxZGDBDP093rqqh1OTRIVgfgRJBCcsFvM5EncT774N35PMYJv6N9iyU
         XJQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=robin.murphy@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-31f2ef276a0si207861a91.0.2025.07.30.04.11.39
        for <kasan-dev@googlegroups.com>;
        Wed, 30 Jul 2025 04:11:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E047C1E5E;
	Wed, 30 Jul 2025 04:11:30 -0700 (PDT)
Received: from [10.57.3.116] (unknown [10.57.3.116])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3E3A73F673;
	Wed, 30 Jul 2025 04:11:34 -0700 (PDT)
Message-ID: <f912c446-1ae9-4390-9c11-00dce7bf0fd3@arm.com>
Date: Wed, 30 Jul 2025 12:11:32 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 0/8] dma-mapping: migrate to physical address-based API
To: Marek Szyprowski <m.szyprowski@samsung.com>,
 Christoph Hellwig <hch@lst.de>, Leon Romanovsky <leon@kernel.org>
Cc: Jonathan Corbet <corbet@lwn.net>,
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
 linux-mm@kvack.org, Jason Gunthorpe <jgg@ziepe.ca>
References: <CGME20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf@eucas1p2.samsung.com>
 <cover.1750854543.git.leon@kernel.org>
 <35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
 <20250627170213.GL17401@unreal> <20250630133839.GA26981@lst.de>
 <69b177dc-c149-40d3-bbde-3f6bad0efd0e@samsung.com>
From: Robin Murphy <robin.murphy@arm.com>
Content-Language: en-GB
In-Reply-To: <69b177dc-c149-40d3-bbde-3f6bad0efd0e@samsung.com>
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

On 2025-07-08 11:27 am, Marek Szyprowski wrote:
> On 30.06.2025 15:38, Christoph Hellwig wrote:
>> On Fri, Jun 27, 2025 at 08:02:13PM +0300, Leon Romanovsky wrote:
>>>> Thanks for this rework! I assume that the next step is to add map_phys
>>>> callback also to the dma_map_ops and teach various dma-mapping providers
>>>> to use it to avoid more phys-to-page-to-phys conversions.
>>> Probably Christoph will say yes, however I personally don't see any
>>> benefit in this. Maybe I wrong here, but all existing .map_page()
>>> implementation platforms don't support p2p anyway. They won't benefit
>>> from this such conversion.
>> I think that conversion should eventually happen, and rather sooner than
>> later.
> 
> Agreed.
> 
> Applied patches 1-7 to my dma-mapping-next branch. Let me know if one
> needs a stable branch with it.

As the maintainer of iommu-dma, please drop the iommu-dma patch because 
it is broken. It does not in any way remove the struct page dependency 
from iommu-dma, it merely hides it so things can crash more easily in 
circumstances that clearly nobody's bothered to test.

> Leon, it would be great if You could also prepare an incremental patch
> adding map_phys callback to the dma_maps_ops, so the individual
> arch-specific dma-mapping providers can be then converted (or simplified
> in many cases) too.

Marek, I'm surprised that even you aren't seeing why that would at best 
be pointless churn. The fundamental design of dma_map_page() operating 
on struct page is that it sits in between alloc_pages() at the caller 
and kmap_atomic() deep down in the DMA API implementation (which also 
subsumes any dependencies on having a kernel virtual address at the 
implementation end). The natural working unit for whatever replaces 
dma_map_page() will be whatever the replacement for alloc_pages() 
returns, and the replacement for kmap_atomic() operates on. Until that 
exists (and I simply cannot believe it would be an unadorned physical 
address) there cannot be any *meaningful* progress made towards removing 
the struct page dependency from the DMA API. If there is also a goal to 
kill off highmem before then, then logically we should just wait for 
that to land, then revert back to dma_map_single() being the first-class 
interface, and dma_map_page() can turn into a trivial page_to_virt() 
wrapper for the long tail of caller conversions.

Simply obfuscating the struct page dependency today by dressing it up as 
a phys_addr_t with implicit baggage is not not in any way helpful. It 
only makes the code harder to understand and more bug-prone. Despite the 
disingenuous claims, it is quite blatantly the opposite of "efficient" 
for callers to do extra work to throw away useful information with 
page_to_phys(), and the implementation then have to re-derive that 
information with pfn_valid()/phys_to_page().

And by "bug-prone" I also include greater distractions like this 
misguided idea that the same API could somehow work for non-memory 
addresses too, so then everyone can move on bikeshedding VFIO while 
overlooking the fundamental flaws in the whole premise. I mean, besides 
all the issues I've already pointed out in that regard, not least the 
glaring fact that it's literally just a worse version of *an API we 
already have*, as DMA API maintainer do you *really* approve of a design 
that depends on callers abusing DMA_ATTR_SKIP_CPU_SYNC, yet will still 
readily blow up if they did then call a dma_sync op?

Thanks,
Robin.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f912c446-1ae9-4390-9c11-00dce7bf0fd3%40arm.com.
