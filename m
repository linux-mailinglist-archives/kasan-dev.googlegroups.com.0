Return-Path: <kasan-dev+bncBCUJBAM67YFRBJVZYWUQMGQEMQJ2LZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A182B7CFFD8
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 18:43:20 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-507be692ce4sf3434786e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 09:43:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697733800; cv=pass;
        d=google.com; s=arc-20160816;
        b=qj1ImN9tXDmQyL4ioSIgd3Obj9ckaV0UT5WN1Iee+vTWGz66aQ4WV2NDnQf0GQ+Fpz
         DI33x7DEfdJHGvcC24WwSCgosGf79OC/FaYKxUf+L1uP4KWSeHYW0oeHwjz+E/grlRII
         VwGnE9zktpnxGpa93S9in2X55ENijI2jBHy4I/ppVbT2dutr/0uN4VoMykh2XxOBP3Cp
         b2KcCAvNSV8vL+nD+PsEiwU2dcZ0G/QJNUIEJWoyJwlW4quL7lcRBfKDC6F3emuxTES9
         WR1V2NQuHv+FTnje1L8groxexqJibXfLP17rmqVIs6BhP9/s5VujYCgnRpoiteWU3YYF
         UENg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=k2SKgjZnwF/aG9VWbF46MNDv0mYmea/nbxZGxY5vylQ=;
        fh=IfwhX36A+QHMoaJTPlYVbO6mDydmfWBkUd4siFoLcIo=;
        b=wFpCq4Jp23wWVUGwNjVJujdq5kRjmhek6Toz8eEbO/SiTlBMZwiFCMqeRMVADkgQnk
         6xIBAoQ6CePS7iRjAvZYM+ZBS70meVLK4HuHIYU+u2vZsNybmPX3VH3zD/WdqdQRSlBL
         7lapdk/3FzsLUxKqrIFWHOcJOO/YhGAxjXIxw7JVbUE6bzizbkKGy9KuIKGn7xoTHwbN
         CRckZewJjaVeGJSDjP8LGywGSJtCPLxBtBlJrU//B28w/z5MJa/VCA4eix+BJ8RPVvbW
         Ns8XLl7yHuqd8uf0nTC9X/wNDgFD3GKuHNY8P6td0vzRm246DAnFNYqcAYRQ+5C4bAlU
         Eksg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=robin.murphy@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697733800; x=1698338600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=k2SKgjZnwF/aG9VWbF46MNDv0mYmea/nbxZGxY5vylQ=;
        b=Z7Um0d20xHEQaFAr0+rViBgR2Y55oxx0YhQ//yS5DKwwKqrv3CbmXzcvPw+/zLf4p/
         ZHQlZ/9Gr3EZ/G4QyMnfrSfKU/wsWki5CDxwLtBu/uoQCaQ4XtS9MAZIMG1LQ3MkFQ/0
         rktThvlwedX8eJ8HPm3rEtHkIStcUCTtgwDWGfQ7K1HzthzFOyUITzDeTxwYTqc4Tffd
         1bs9/xp+uRJt7mtaiy9KCxctxpcQxaq2ei1+dQQUZbDvBkLjbZuz9yyVJJxN6GEwVk9i
         vtzddCucAoPA4ghOZWS/QIm/HmbjM/ej83BU1Fue53K59DTxemXo6lCH1Mf5+jLbiA0b
         Na2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697733800; x=1698338600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=k2SKgjZnwF/aG9VWbF46MNDv0mYmea/nbxZGxY5vylQ=;
        b=S2wrtuC9RnF99Z+oWsPtWtPy5kBEswnGI6C1KJe67vI+RKKJ+oVdsBAPggxUfLIO2E
         38w2s/IENtkEjuuIgi0Ggra/P19FbZxnR6FpO55V3Aay4f0yiwSlkEGYj+TsIjZbuadP
         crsubi20eZbylxLOsUyvzRxVICtptRR8gVuJI0+HLkvE3fVIy/MPc5Deuc9tEpncqw9t
         +G2ErAbsY7mmQbbDrWGwNx/BZAPFkxZCbbAx9IZd6z56p2AHLukGoVuDlc0KdCyVY9id
         KRyqBmxh9YoYWSbK/7XIcyovDHwLAf74x3Yopz3j/oOCfdmrDehz008mWrN/6krcI3wC
         vjvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yygis80XKMzA2SbrWtQ/N2er1LHOgGuEsZHC6u54jEX0GImwo4n
	iEf/mcjUaTi1heW+UDeJjfQ=
X-Google-Smtp-Source: AGHT+IGKdCf6g62vDzsONyEB933wuNX69rRijQPw8j6gUrtFIjvySQcZqOcwoYNjtTlG+SCLcVxGGg==
X-Received: by 2002:a05:6512:51a:b0:507:9ff7:2ed4 with SMTP id o26-20020a056512051a00b005079ff72ed4mr1831346lfb.43.1697733798624;
        Thu, 19 Oct 2023 09:43:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ad0:b0:507:b8d5:d6d4 with SMTP id
 n16-20020a0565120ad000b00507b8d5d6d4ls73896lfu.0.-pod-prod-03-eu; Thu, 19 Oct
 2023 09:43:16 -0700 (PDT)
X-Received: by 2002:a2e:9b0a:0:b0:2c4:feef:852 with SMTP id u10-20020a2e9b0a000000b002c4feef0852mr1642592lji.32.1697733796440;
        Thu, 19 Oct 2023 09:43:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697733796; cv=none;
        d=google.com; s=arc-20160816;
        b=mPGkFySrlt7X61xWTXwriUyX9C17foi3OOBf1xVvh0YWWZ44BCE+9hDe8fleqOoxXS
         4U2H3ETMvCK7qq7kADdeTDlI4/gEKieVOi6q0f/BAf79awpl9baKgC16rnmRmvlqR+3I
         ss+OSNtwyjKoHAYLj2CeLmi2eBzIlBfrjnA3qGemcrpACEof3S+GVY1CQ+YN+QZ2BUGe
         LutNxOSe+OSirqzEpWvJZOqt5dcVkGzlvZqb5tvwrVlDLYalijYWY7rZUTP7K8GNa0yN
         iriK4Mw1nWCZvUEmd2dUfh0oE5w3veexIJwSHVdI4CO8ETVEPgVNL9JSJdUVawwYNOmU
         w+tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=Y3lIkX/FowZ3rzaRGGmmq3AoGPXW7t/P7tI15d3ku6A=;
        fh=IfwhX36A+QHMoaJTPlYVbO6mDydmfWBkUd4siFoLcIo=;
        b=KPg30Q1IsewaPoh0vuJZsLYhaSilJwh0RUjzlj588FLl9B3HKn6Sjg0wSwZbBPQnSE
         RIO1jmwYLV/xgebeApTLTRuxQKoMEijlknMFvg2C6QoA0xBu3Q+uzm6zuC4swICqke4k
         w+EO8qtb8ezv6J1TmukCaWSpGUcjDcTOG9FZrGB/jCdBS3wSJoOs7WZBW/82SmSQLpbA
         TQP6Q/cMqkQK01/Je057oO7gjBDeK8NExPpbmIL+AyZPoeKuqea1tMhGzEPRRCt2Xh4C
         uLJydQqTUuCEFrTareRipn5zUhlDprN58B2fmttGnagtslrm4shJhvbHznTbAHqJjOW6
         hmSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=robin.murphy@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b20-20020a2ebc14000000b002c28192fe0fsi277183ljf.0.2023.10.19.09.43.15
        for <kasan-dev@googlegroups.com>;
        Thu, 19 Oct 2023 09:43:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 892062F4;
	Thu, 19 Oct 2023 09:43:55 -0700 (PDT)
Received: from [10.1.196.40] (e121345-lin.cambridge.arm.com [10.1.196.40])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0AD7E3F762;
	Thu, 19 Oct 2023 09:43:12 -0700 (PDT)
Message-ID: <3f5d24f0-5e06-42d5-8e73-d874dd5ffa3d@arm.com>
Date: Thu, 19 Oct 2023 17:43:11 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 0/9] Exploring biovec support in (R)DMA API
Content-Language: en-GB
To: Chuck Lever <cel@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
 Chuck Lever <chuck.lever@oracle.com>, Alexander Potapenko
 <glider@google.com>, linux-mm@kvack.org, linux-rdma@vger.kernel.org,
 Jens Axboe <axboe@kernel.dk>, kasan-dev@googlegroups.com,
 David Howells <dhowells@redhat.com>, iommu@lists.linux.dev,
 Christoph Hellwig <hch@lst.de>, Jason Gunthorpe <jgg@nvidia.com>
References: <169772852492.5232.17148564580779995849.stgit@klimt.1015granger.net>
From: Robin Murphy <robin.murphy@arm.com>
In-Reply-To: <169772852492.5232.17148564580779995849.stgit@klimt.1015granger.net>
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

On 19/10/2023 4:25 pm, Chuck Lever wrote:
> The SunRPC stack manages pages (and eventually, folios) via an
> array of struct biovec items within struct xdr_buf. We have not
> fully committed to replacing the struct page array in xdr_buf
> because, although the socket API supports biovec arrays, the RDMA
> stack uses struct scatterlist rather than struct biovec.
> 
> This (incomplete) series explores what it might look like if the
> RDMA core API could support struct biovec array arguments. The
> series compiles on x86, but I haven't tested it further. I'm posting
> early in hopes of starting further discussion.
> 
> Are there other upper layer API consumers, besides SunRPC, who might
> prefer the use of biovec over scatterlist?
> 
> Besides handling folios as well as single pages in bv_page, what
> other work might be needed in the DMA layer?

Eww, please no. It's already well established that the scatterlist 
design is horrible and we want to move to something sane and actually 
suitable for modern DMA scenarios. Something where callers can pass a 
set of pages/physical address ranges in, and get a (separate) set of DMA 
ranges out. Without any bonkers packing of different-length lists into 
the same list structure. IIRC Jason did a bit of prototyping a while 
back, but it may be looking for someone else to pick up the idea and 
give it some more attention.

What we definitely don't what at this point is a copy-paste of the same 
bad design with all the same problems. I would have to NAK patch 8 on 
principle, because the existing iommu_dma_map_sg() stuff has always been 
utterly mad, but it had to be to work around the limitations of the 
existing scatterlist design while bridging between two other established 
APIs; there's no good excuse for having *two* copies of all that to 
maintain if one doesn't have an existing precedent to fit into.

Thanks,
Robin.

> What RDMA core APIs should be converted? IMO a DMA mapping and
> registration API for biovecs would be needed. Maybe RDMA Read and
> Write too?
> 
> ---
> 
> Chuck Lever (9):
>        dma-debug: Fix a typo in a debugging eye-catcher
>        bvec: Add bio_vec fields to manage DMA mapping
>        dma-debug: Add dma_debug_ helpers for mapping bio_vec arrays
>        mm: kmsan: Add support for DMA mapping bio_vec arrays
>        dma-direct: Support direct mapping bio_vec arrays
>        DMA-API: Add dma_sync_bvecs_for_cpu() and dma_sync_bvecs_for_device()
>        DMA: Add dma_map_bvecs_attrs()
>        iommu/dma: Support DMA-mapping a bio_vec array
>        RDMA: Add helpers for DMA-mapping an array of bio_vecs
> 
> 
>   drivers/iommu/dma-iommu.c   | 368 ++++++++++++++++++++++++++++++++++++
>   drivers/iommu/iommu.c       |  58 ++++++
>   include/linux/bvec.h        | 143 ++++++++++++++
>   include/linux/dma-map-ops.h |   8 +
>   include/linux/dma-mapping.h |   9 +
>   include/linux/iommu.h       |   4 +
>   include/linux/kmsan.h       |  20 ++
>   include/rdma/ib_verbs.h     |  29 +++
>   kernel/dma/debug.c          | 165 +++++++++++++++-
>   kernel/dma/debug.h          |  38 ++++
>   kernel/dma/direct.c         |  92 +++++++++
>   kernel/dma/direct.h         |  17 ++
>   kernel/dma/mapping.c        |  93 +++++++++
>   mm/kmsan/hooks.c            |  13 ++
>   14 files changed, 1056 insertions(+), 1 deletion(-)
> 
> --
> Chuck Lever
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3f5d24f0-5e06-42d5-8e73-d874dd5ffa3d%40arm.com.
