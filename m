Return-Path: <kasan-dev+bncBCUJBAM67YFRB3GGR7CAMGQEDJKECIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 759BDB12513
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 22:05:02 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3e3cba15753sf2140945ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 13:05:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753473901; cv=pass;
        d=google.com; s=arc-20240605;
        b=JntBV7JUMMKnAUwcbBsUHAVc/S9ipb5kf6nKOuF8DGbnsBywiStd0ekeAZOZySS/uy
         N0inn0X1SIicjGjfBo7IvECwXZsSj7QsTAzSLw0VPZoQtruylRt4dYyfEKN/2EC5T5ke
         sZUv/2BAZPJdqABHUiwcOLOttFTHVY8hGjUSedLH5+HgTTkKSaikhUQOPbAZ8sRJ5TaC
         jsUOQSB+3hbS/7hmsI7pGcQFv6ngFlelrJlyyh1x8SCdRHJIciqCRACkwpbAMPzsHCaC
         7LuCXL7Q59M1y0wC5Y9TE5X3LndCiQ7Jyp7ykih1Jp8bz0Rf8wWdvH7WTo96kjlijZqe
         wApw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=5I9/7Df5gL9PGbGLMl+HQHcFg0LrICCNK75mDsk+NDs=;
        fh=mf6cCKJZxlxl1na9CNuqmwTaRmpPgMAZv9Emci6xNos=;
        b=f6ag8KnjHxqg+jyQF4Vdt2lxSMFxt3dhnf+thPjAW8s5JkWH3H918cdN7cAapIxO5Z
         Dv9nybWLLHCdnnVLAsXj5D+1kdTzoH2aqIliW//fyzLgdkdfGpHtSUh4Y0G0QzQQ9ZdF
         UdYNx6TsQ95SXaFK02ZIPyIRLKzvkqpb2MkmAnEYP+ZIAQPy/ltEKmlmyTJKRyGi6Oam
         RZUt8u1b1eOK9wqUdQII+UvY06j5UlMK4G49IzWAdQ4VuJWd8ZdyOk11uatnXAdj6jE9
         ctg2E0b51ILvLZC70yJj/tAVK5i5JXp3DfNbASM7RICuutX/X0a8HR+z5BvVmG4zK/ju
         TCMg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=robin.murphy@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753473901; x=1754078701; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=5I9/7Df5gL9PGbGLMl+HQHcFg0LrICCNK75mDsk+NDs=;
        b=Pp/n5FNvLdNSZfuwvZap5ct03DjK3w3ltHveCC9Acn8rV3tEVF4D8KuLPoMqtw+j1m
         UA9P2IZcM64M20YB0BXDVYfwZOJPZ3JAsL5++EwfCiERS8IjFtin95U0wQG9EWtRdZdN
         bLk1AwTpuDFzxWnsyK3GJvTouFm0M45SM3NVzph26KKaAM6Wv1BKANkVps+4hE2n9h7y
         CGwrdAa6hNIwdJ9VJXhca/cH2MI9j35X6382xgHioe5y4N2wV/3ST9UE0pXInZEq01dE
         EXfYb0DNl7DzOSve6fEyeUV4poA64824Bpe4BvjQFOmtLLykW+2uzGJHv1b1yIAAd+TJ
         hOQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753473901; x=1754078701;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5I9/7Df5gL9PGbGLMl+HQHcFg0LrICCNK75mDsk+NDs=;
        b=QdhOTq7HY+VLSIVn/ZrTCGLzUuoLuXGa+EuP6g9n35Uu7+NnJK5j0hvyjIXmIjVZIa
         NahzHZoN7zgAy8A1l5nJVX8RyWoqQ0JshZ1dKT5kIKn8ZzU1FeOUAt+nzfi09K6eT1zQ
         1GU4i+FLrwp9TZ1AbyiH0UpgqrBeBfYYUEeWXgjiu/DLTeQzT7FWRm0lhWpQXYSqprtE
         GCKlCOqgQCQAsH1P0T+0HkfQd7BPgIB9HGBtbjSwlhX/f4njEWcX4JPtlmZLTpwapnm5
         reMkEHYDBctjlG7dMX33SO17951GAVv466w6iQ7IFH6/3OyxnBB0DSc5h3/bEGGO5kJG
         CxsA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUrb/GYEYkEtof4AI8FmwNfG0c6RMp0j+aboB4PbQjJK9jUbRdzoOlsgIfTfI7rS3hkd0pvOg==@lfdr.de
X-Gm-Message-State: AOJu0Yyun+yAGmvIR6hLIkDecr4UqnXBI3aWzLhcRZQXTpGBl95Vbt9p
	rwoaJSq09yGSXDanKL7DBCSKeqc5bLpDjWZMTAK4984LAgVbf2OjP9br
X-Google-Smtp-Source: AGHT+IH6oGP1HuIktmtSM9PV6OwnLB/Yj5aGHsVsuAslBeeWtholKJ/DeAwqVpkPflxZZ+XXmKmRdQ==
X-Received: by 2002:a05:6e02:11:b0:3e2:abbc:c0c with SMTP id e9e14a558f8ab-3e3c527cf90mr47028785ab.7.1753473900603;
        Fri, 25 Jul 2025 13:05:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcD6y9svEjL1g6M7kv2d2lM+p6ONUmOYbTsOTFVVgXSJQ==
Received: by 2002:a05:6e02:2182:b0:3dd:c3df:51ee with SMTP id
 e9e14a558f8ab-3e3b4f8dc47ls28123555ab.0.-pod-prod-06-us; Fri, 25 Jul 2025
 13:04:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWXIFs0aiTm3m4O5RrjVwehd89zIyv5IFRM6DEQJm5/0C1XICSUB4EbeHQavqh0gurZUtPblG7PjM8=@googlegroups.com
X-Received: by 2002:a05:6e02:16c9:b0:3e2:8e44:8240 with SMTP id e9e14a558f8ab-3e3c52e3e54mr42435635ab.11.1753473899421;
        Fri, 25 Jul 2025 13:04:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753473899; cv=none;
        d=google.com; s=arc-20240605;
        b=F+sMTtVkKLrEMRaifz74UldNR2Hach0GfG8fhFtJXH31vnGxBx7R42IkSl38DuE4E4
         itJchx6GrdzxsLAY775zngtZQUAQ8NlzaNmWzNs5b+WK0DLEpFDK67g1rb2Z+0EXWNtP
         QaiRt/MPNVoW9K7//JLbW5QkBfj3iul8F23NTTrDArlkC6kyzLTej5sSCt7REhoXfIYB
         QWtQrk2cDSMjcKFNHDZzpiGY2j5NjPRVB2Z23tiLVABCEfy64Np4W/zvklHJs818h/em
         bOzJjJbYYjwzuNrxDC6/YQ/qBEEemgppK9tsiBwqbYj3qadFlfavyHNtnNeBiTnYhWmA
         GQJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=QMHalZqBHj5+vLhnCWsCzA0DqNLiKy2tC9hrHiUhNds=;
        fh=1HtAbHoqHUiw2ZpZsQg9wfFqUHSdlFQcUawwbx1FZgI=;
        b=Vb/YGAWqTYVMQW+iOqZIuS4t68zQ3O/GPHVs56WbtAQ02K7yRUJ7M4Zp4zI8UHyL+X
         U198TUMkoCcxcQpmOdQ7OCZWTGU0XJIRJrDGHp4ytqsdJOKcM2UMKCu5Vl0hqTDxxi/2
         PNgWks00c9yRtlWIvYGiDz7RtQOOJCjHCT1GX3mjIcyX4+9Z5PVyaVTxi+9s7wGR0HC3
         h4jifOCoecE6xJZCqJ/J8A6Ip+iA59KAo6G0I2UKRbVsbcnZw+oxwTkMGhs/M8R1VQP0
         bNY7uYa5DvxUbit+95WLLnFloBD9FbrgkW3vfSx1IeHQGk1u0mgez7DRsBZfo/BY1Q8x
         KZYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=robin.murphy@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e9e14a558f8ab-3e3ca84dc9asi608995ab.2.2025.07.25.13.04.59
        for <kasan-dev@googlegroups.com>;
        Fri, 25 Jul 2025 13:04:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8E344176C;
	Fri, 25 Jul 2025 13:04:51 -0700 (PDT)
Received: from [10.57.4.83] (unknown [10.57.4.83])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 167FB3F6A8;
	Fri, 25 Jul 2025 13:04:52 -0700 (PDT)
Message-ID: <02240cf7-c4d4-4296-9b1e-87b4231874a1@arm.com>
Date: Fri, 25 Jul 2025 21:04:50 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 6/8] dma-mapping: fail early if physical address is mapped
 through platform callback
To: Leon Romanovsky <leon@kernel.org>,
 Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leonro@nvidia.com>, Christoph Hellwig <hch@lst.de>,
 Jonathan Corbet <corbet@lwn.net>, Madhavan Srinivasan <maddy@linux.ibm.com>,
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
 <5fc1f0ca52a85834b3e978c5d6a3171d7dd3c194.1750854543.git.leon@kernel.org>
From: Robin Murphy <robin.murphy@arm.com>
Content-Language: en-GB
In-Reply-To: <5fc1f0ca52a85834b3e978c5d6a3171d7dd3c194.1750854543.git.leon@kernel.org>
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

On 2025-06-25 2:19 pm, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> All platforms which implement map_page interface don't support physical
> addresses without real struct page. Add condition to check it.

As-is, the condition also needs to cover iommu-dma, because that also 
still doesn't support non-page-backed addresses. You can't just do a 
simple s/page/phys/ rename and hope it's OK because you happen to get 
away with it for coherent, 64-bit, trusted devices.

Thanks,
Robin.

> Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
> ---
>   kernel/dma/mapping.c | 15 ++++++++++++++-
>   1 file changed, 14 insertions(+), 1 deletion(-)
> 
> diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
> index 709405d46b2b..74efb6909103 100644
> --- a/kernel/dma/mapping.c
> +++ b/kernel/dma/mapping.c
> @@ -158,6 +158,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
>   {
>   	const struct dma_map_ops *ops = get_dma_ops(dev);
>   	phys_addr_t phys = page_to_phys(page) + offset;
> +	bool is_pfn_valid = true;
>   	dma_addr_t addr;
>   
>   	BUG_ON(!valid_dma_direction(dir));
> @@ -170,8 +171,20 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
>   		addr = dma_direct_map_phys(dev, phys, size, dir, attrs);
>   	else if (use_dma_iommu(dev))
>   		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
> -	else
> +	else {
> +		if (IS_ENABLED(CONFIG_DMA_API_DEBUG))
> +			is_pfn_valid = pfn_valid(PHYS_PFN(phys));
> +
> +		if (unlikely(!is_pfn_valid))
> +			return DMA_MAPPING_ERROR;
> +
> +		/*
> +		 * All platforms which implement .map_page() don't support
> +		 * non-struct page backed addresses.
> +		 */
>   		addr = ops->map_page(dev, page, offset, size, dir, attrs);
> +	}
> +
>   	kmsan_handle_dma(phys, size, dir);
>   	trace_dma_map_phys(dev, phys, addr, size, dir, attrs);
>   	debug_dma_map_phys(dev, phys, size, dir, addr, attrs);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/02240cf7-c4d4-4296-9b1e-87b4231874a1%40arm.com.
