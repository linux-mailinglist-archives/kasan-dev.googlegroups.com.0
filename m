Return-Path: <kasan-dev+bncBCUJBAM67YFRBN5NZGUQMGQEJ4VYWBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id AE4A97D0D1E
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Oct 2023 12:30:16 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-53faa428644sf9935a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Oct 2023 03:30:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697797816; cv=pass;
        d=google.com; s=arc-20160816;
        b=q/gQGZ+WcwUnzKrOqBlHdcCSmKvbEdHIOIKSC5bwlo5VoQMf5eAx0nw2RAMp9Z0IlX
         TJgvJVSGqO1yKODb6ytwnC8/XBVdnJ1JAPP1mk0W19YFTAJdoD/Iimv0nlt0zOuOjIVO
         grkhxfizuEufSXv/TccRcFG9oEc5I/bniCG+HynR2wQGt36kGC/+R+5ylD+qVhDOiyBc
         asoR4+QJHPLdl0Ib2aYrCM2FTtl40ipmA5U+b9M1D5k+tTugYu21CcdDXdHuGCZPJuKk
         gxo+Z8AbYBo0cZ3p2QRgSbQO+Xr36b4TE1KdaNxfVzVJ74JsMKKRA46DtVhCsKXuHFM4
         DDqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=EdSM53C9weMppyrumFor2WZCsMlUlQPrNnAnPA+Pn0U=;
        fh=sieOV9ukeyHbHrHd/Gy220eFvvIXVMuXMoD3Jwn9O7M=;
        b=Tl5cqXBwxQHPAjvjGlI1wyIcUwyHP54Eh3gdWIiEW2CJJFOY1CZsyCF/2wkvlNibKS
         M0vBufzoqVwDVq8U3SWCvinaK33vfAImjqvpSyc2ek9fy21PtFQVxKiLfU+ZletaiRbT
         mvBKZ5JPyjgTRkcPVlJQQBghriwOR20DUagUmXnzFNm6ujgpOzY2CMIREbFkZfeNKOhD
         F0WP6ECosNopzojBqM39PEWsd/QOaQi9k7QBLmyag/E2Qr3lBN/znXmdQ+Zw9HJkIELv
         rJ2CEN64z0UH4+RWHniq2Vb5SUMa2c2RuUq1wOE6jeAoUiYOzbQ2m6N0gAtW+uDar+Oe
         wFmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=robin.murphy@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697797816; x=1698402616; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=EdSM53C9weMppyrumFor2WZCsMlUlQPrNnAnPA+Pn0U=;
        b=mr0/T0lqHbVewK+DtFcAwEB2iqOhA4rCJKmZZt9FVFiPYEbje95Tbk1/67qQ7UMllZ
         vXP7BLjegmsuSwHZIeb6THiL8beAhGp4w4oH4nvWx/6G0vo10AlREwE73FyHkXN6SnQx
         iCaiqdX8/41fGDkIB9C0Z7vl3e/wmzuH07NTGTesGsu5PAB9RhaaL0tDINE3uLjTm+ND
         0bay7KV8CAvtQikEIgsjf4t3v214/SyslgOSgBfXJRtpsTnpsFb9qa9lUvIOxILCO9sK
         BYKwBDXMY5h1zlAgT5reMGs4lcZY1gTVCY8+Z6VrQ+i5rlclyMySw3GBCZ5zQLKjdHZ7
         QCgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697797816; x=1698402616;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=EdSM53C9weMppyrumFor2WZCsMlUlQPrNnAnPA+Pn0U=;
        b=Rg0UKyJhb5OGzeLeFH++mGqzyMBeysnAHlzUYX8X/iGSUeoo22qS6ruOIVdaYrko6X
         FG/o6eqNYvIb7eQiwG06wUTK54j/ydP7olv5EiKaOJ8kMhPayA9eMerOjTXlySU30fTg
         lQLb/ZJH78HGWnmuNfnpqM0VluL5Vz4WKo3hh9deYo4M4jAhs6J4LyCF3t491N+R2SVB
         bZ4b1oS4g0JC6uPId3NC4ZjiExFrg17vL5+XbUtzCagY0HIu1S/MIVA4Wt4wq5bKjIM7
         xr4JI0QIVgJae5lsBGR6npuV9fplXBpGczisblRg3Ou6lV71vcQoFQUkxW5NolV7wb4W
         daQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwbYmnmXt/xJX0HoKO0cdV50HNTEdh/7WBMhi+prXeSkxbSr6p2
	Hx/x4nN81LBwydKsYxkP26A=
X-Google-Smtp-Source: AGHT+IERWAzhEDZp1QwiOLXaUY7EkDFfXzzRJlP2N8VKP8lwNfFbcnoENJS9UbWIWA8uxxNGt60sHw==
X-Received: by 2002:a05:6402:50d2:b0:53f:c607:c87a with SMTP id h18-20020a05640250d200b0053fc607c87amr95504edb.7.1697797815615;
        Fri, 20 Oct 2023 03:30:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d1cd:0:b0:32d:8578:9fd2 with SMTP id b13-20020adfd1cd000000b0032d85789fd2ls285405wrd.2.-pod-prod-08-eu;
 Fri, 20 Oct 2023 03:30:13 -0700 (PDT)
X-Received: by 2002:a5d:453a:0:b0:32d:96e0:8048 with SMTP id j26-20020a5d453a000000b0032d96e08048mr1134371wra.9.1697797813552;
        Fri, 20 Oct 2023 03:30:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697797813; cv=none;
        d=google.com; s=arc-20160816;
        b=ht+7/7O2U7hbjhvmbUr3H/xqclr5lxQVydJ0MgO4EM3rJXIK4xp4Ud0ZPHvK1wRaIi
         1pPuz3r6CQ/dkl+Vqt0yCKHUlJBgEcXufca18ESO640aSP6BnuwZwQ0B4nZdt/qnWe4v
         dh8139OxRgFSNFmNAtdW8LRv3fSr3gFSaYBpPzq6GPUrewuCOlSMcKa+VwnBavFumtUA
         2oqUj9u0TK7K+JmvME+jisaxKTskWyY+6Yg9TYLCHkfzJsOF8VKZMv/LOqVK/aa4WYM8
         eI5Bqdm5wKAL/gaUM7Ocx8Y56vyI+/apsvPZ0bRFVTIIa/dS7cQEEJEKkUA73ETMi6/i
         dx1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=VWfmSKAPvLHMCZdWUFjJaH7egPQqe7DszqtOPyP/7IE=;
        fh=sieOV9ukeyHbHrHd/Gy220eFvvIXVMuXMoD3Jwn9O7M=;
        b=kEYXKf3ccaWlffeIWoBHyEQPbdRxaZtzwHUAh4YPlmbUToFtSmCouSac10J05DyCtN
         4FEi811UojEamMrS1cp3/TVctKYBDhEmfNaM2vQaV+GF57vsaxkRIm4eqa7Wkyq5G3eT
         6Ez/JkHKPmCGlOJdlUtAzGz8b/cY7wDRIU/gQD3yyos1oL9G6oTkycumOWfb6JSJA+N5
         JqoqokJPVlWQMHo7uCN+2EXZnc44E4HBdIb219ej21Yu4CmVt8dkevZV53kKIQtEBF8R
         0wIcDqiMbLCJnwuG9UqdFnNGuXGMs7sUZyLtTs5qbd/kQo02Z0A64MipgW5GGH5RdOQt
         aRiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=robin.murphy@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m9-20020adff389000000b0032d8f0b5663si48163wro.7.2023.10.20.03.30.13
        for <kasan-dev@googlegroups.com>;
        Fri, 20 Oct 2023 03:30:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A0A722F4;
	Fri, 20 Oct 2023 03:30:53 -0700 (PDT)
Received: from [10.57.68.58] (unknown [10.57.68.58])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CB6683F5A1;
	Fri, 20 Oct 2023 03:30:10 -0700 (PDT)
Message-ID: <41218260-1e5f-4d36-8287-fc6f50f3ec00@arm.com>
Date: Fri, 20 Oct 2023 11:30:06 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 0/9] Exploring biovec support in (R)DMA API
Content-Language: en-GB
To: Christoph Hellwig <hch@lst.de>, Matthew Wilcox <willy@infradead.org>
Cc: Chuck Lever <cel@kernel.org>, Marek Szyprowski
 <m.szyprowski@samsung.com>, Chuck Lever <chuck.lever@oracle.com>,
 Alexander Potapenko <glider@google.com>, linux-mm@kvack.org,
 linux-rdma@vger.kernel.org, Jens Axboe <axboe@kernel.dk>,
 kasan-dev@googlegroups.com, David Howells <dhowells@redhat.com>,
 iommu@lists.linux.dev
References: <169772852492.5232.17148564580779995849.stgit@klimt.1015granger.net>
 <ZTFRBxVFQIjtQEsP@casper.infradead.org> <20231020045849.GA12269@lst.de>
From: Robin Murphy <robin.murphy@arm.com>
In-Reply-To: <20231020045849.GA12269@lst.de>
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

On 2023-10-20 05:58, Christoph Hellwig wrote:
> On Thu, Oct 19, 2023 at 04:53:43PM +0100, Matthew Wilcox wrote:
>>> RDMA core API could support struct biovec array arguments. The
>>> series compiles on x86, but I haven't tested it further. I'm posting
>>> early in hopes of starting further discussion.
>>
>> Good call, because I think patch 2/9 is a complete non-starter.
>>
>> The fundamental problem with scatterlist is that it is both input
>> and output for the mapping operation.  You're replicating this mistake
>> in a different data structure.
> 
> Agreed.
> 
>>
>> My vision for the future is that we have phyr as our input structure.
>> That looks something like:
>>
>> struct phyr {
>> 	phys_addr_t start;
>> 	size_t len;
>> };
> 
> So my plan was always to turn the bio_vec into that structure, since
> before you came u wit hthe phyr name.  But that's really a separate
> discussion as we might as well support multiple input formats if we
> really have to.
> 
>> Our output structure can continue being called the scatterlist, but
>> it needs to go on a diet and look more like:
>>
>> struct scatterlist {
>> 	dma_addr_t dma_address;
>> 	size_t dma_length;
>> };
> 
> I called it a dma_vec in my years old proposal I can't find any more.
> 
>> Getting to this point is going to be a huge amount of work, and I need
>> to finish folios first.  Or somebody else can work on it ;-)
> 
> Well, we can stage this.  I wish I could find my old proposal about the
> dma_batch API (I remember Robin commented on it, my he is better at
> finding it than me).

Heh, the dirty secret is that Office 365 is surprisingly effective at 
searching 9 years worth of email I haven't deleted :)

https://lore.kernel.org/linux-iommu/79926b59-0eb9-2b88-b1bb-1bd472b10370@arm.com/

>  I think that mostly still stands, independent
> of the transformation of the input structure.  The basic idea is that
> we add a dma batching API, where you start a batch with one call,
> and then add new physically discontiguous vectors to add it until
> it is full and finalized it.  Very similar to how the iommu API
> works internally.  We'd then only use this API if we actually have
> an iommu (or if we want to be fancy swiotlb that could do the same
> linearization), for the direct map we'd still do the equivalent
> of dma_map_page for each element as we need one output vector per
> input vector anyway.

The other thing that's clear by now is that I think we definitely want 
distinct APIs for "please map this bunch of disjoint things" for true 
scatter-gather cases like biovecs where it's largely just convenient to 
keep them grouped together (but opportunistic merging might still be a 
bonus), vs. "please give me a linearised DMA mapping of these pages (and 
fail if you can't)" for the dma-buf style cases.

Cheers,
Robin.

> As Jason pointed out the only fancy implementation we need for now
> is the IOMMU API.  arm32 and powerpc will need to do the work
> to convert to it or do their own work.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/41218260-1e5f-4d36-8287-fc6f50f3ec00%40arm.com.
