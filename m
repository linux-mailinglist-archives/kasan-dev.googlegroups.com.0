Return-Path: <kasan-dev+bncBDG6PF6SSYDRBMUSVHCAMGQEL3HV3KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id B7A5CB164C0
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 18:32:51 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-456175dba68sf42186415e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 09:32:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753893171; cv=pass;
        d=google.com; s=arc-20240605;
        b=jPN/hP+PN7TiUDe07YXUlDdrB97WwXWSxw1EqkHXZQUaGNlRA/IfiAAyL7nveqkjZs
         BSE70PwtQN+261NgqC/CpL3LX2LzxGoHMnJ7s5XlP8fzTT3EMeT9HMFw2bsokxVacXoe
         ZKNym/rF52C1SIjx8edZ6wPeFBsK23qtgWgzljieTdNEvcxgJ8RtOATW95hYixQ1memt
         hwta+xVi1tovTjRZc5RocvrenlpUA/kpYAkStAyiakvxla/P08MDbBvtBn1NFc7qNZW1
         AN3lgzY3AlPrwAtgDu1HDgcVl8Agybf7AZ6nTy7ean7SzQ0l2SNj/UrVEHfwNHm/VLP1
         2j5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:dkim-signature;
        bh=4nwbZUPb8lI1IufU5W5VwuWWWCorZIK9+UIi1oUA2n0=;
        fh=mPsO8x4rJwRjnZqQ7hESk5F8UUVnJMRq/k1blCoc9dk=;
        b=SMHTsyNxWrHRbxaxQY9Dqb8e2NAmxDZg6R4dIVCjE0f20tSfDhvM17+Qvc46N073xf
         OKb4FdYLgp1u0QCX50j9a1YSJRSKZo01nonQ3oKcX7XYp2bw96cfqNW8rOwhaikR2AFU
         xLfTkFHprk0WJ8jTQ0Kh+lfXXXAPrFvrDdDJaPcD5En2ywJ0gwISwxJs7Uea24/mfxrF
         hpUcSlAOCnjeGVg+7nd3m1n4VJBNr42uDPnVJ+XEHVKM8Sl0gY2OSDaBaNfFCc7/ntpU
         kkDUJdfI6cckn94RQ3lF8jknrQFVGo7I8rUIaQSERwG++sY9+MQbC0+AmO2q2q68r/CW
         cb9A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=tQBF5gQj;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753893171; x=1754497971; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:from:content-language:cc
         :to:subject:user-agent:mime-version:date:message-id:dkim-filter
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4nwbZUPb8lI1IufU5W5VwuWWWCorZIK9+UIi1oUA2n0=;
        b=eMIB0HFo6sjDN0aYoPQffWhcsBXQmNtD48BS989oOtzVj3YqjCkccJYv/xLf1x5u/7
         //13EDxjnpgfYcSdUnXPP4VyUG4BMmFE90XKNdZ2pKm/dDNCoEFH/e3HNgQr0GCipxYL
         Ik6AHJDfPqB+Xbk8VIcNfuqdktAQA9o1DHybe5TopdUMsrsxzVFyIEtQoDkhQPJWa12e
         GnJjbH1aQq0ND7JeSUK7MLsyAWFIqtwskR1/I6aXaiQnYC8UHKaHkE5tuG5mwyHd9+ou
         LOj7HqYR0mZmjTvSezYjTmWcLSCMBCD6gsyU2dApPdtu3HBbAr1OfpsUA4HxA596u6ki
         j0Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753893171; x=1754497971;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:from:content-language:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-filter:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4nwbZUPb8lI1IufU5W5VwuWWWCorZIK9+UIi1oUA2n0=;
        b=uWtmy8mu+YzaaA6iaR2ilZRb9zH53M2AFItaxaUfP2DBBAKSJR179kmBrbamCarRT1
         VHPmsymyDLdqAnP+ZZf0rcezeZ0H0mfhm/aqM8sTXt/YxlELlxxL/6EWcQ2rsrB6BJkD
         Ln9/9fFe/C91KbIhXY1pwH2NocHIo+9j2RpFv2bu/ExvcAJLUNxElVBtzYghUXV7TaQ0
         ybCLV/+CIVhE8NAC0WIYghyfm6lmLPScjPkDVtJ+W5rHLoYhz+xnDFfx0mpjjP1zmtrb
         YN76qjJRvNESNm0ljxNImMaR1PH+nWiciNv14YjNbbgDTP9h/91C1GSbcIgTD9aDDyri
         MohQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUyK3DCL4RuhQZq0Hnab3AJwJgKrWxn6U+moBEKhjzkOIF9ApB8CNXx1dtiFPZA8auyn5VTig==@lfdr.de
X-Gm-Message-State: AOJu0Ywnx/pWqtP/hxJhxOiW6hkf76T21QSPkSSqkKI4gpKsqMn9xui/
	5Ht2s5K48TRSNbMladqs6asuGAqB7B8TweTSb1Om6bDYoyyggXZW9HGf
X-Google-Smtp-Source: AGHT+IER9aQrD/23aBBoICBZC885DdFW/eLSitSOUhAtVFJuvxEjCGi3G4Xbd8cODOsgSSx5qbYNkg==
X-Received: by 2002:a05:600d:108:20b0:456:11cc:360d with SMTP id 5b1f17b1804b1-458930ecc54mr26859745e9.9.1753893170600;
        Wed, 30 Jul 2025 09:32:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeECG7UnF7BJ0HNS1CdJHuAciVB1JRTYQckyJYKlMF4jQ==
Received: by 2002:a05:600c:4503:b0:456:136f:d41f with SMTP id
 5b1f17b1804b1-4586e6442d9ls40156475e9.1.-pod-prod-07-eu; Wed, 30 Jul 2025
 09:32:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWngXDCijuNzIF1Lbg1omwo7Od1e20Kg+RZaQiwIuQwCpZ3LSdQciezA+6yzPUffww1/HFetnawKUA=@googlegroups.com
X-Received: by 2002:a05:600c:6297:b0:456:2771:e654 with SMTP id 5b1f17b1804b1-45892bd1a7fmr34895745e9.24.1753893167915;
        Wed, 30 Jul 2025 09:32:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753893167; cv=none;
        d=google.com; s=arc-20240605;
        b=IU2TKeLV4duBjkKU/o/bVVlzwthRSh81poGtPXt4oP161Mjdi/cN4rIYv+5o4KImFy
         gKQT2WMHPMx0trXYkgPBTCTWVXQ1LdCK6TeaN83294bU7D3gUswaGOiMfVLtXmBfeeiF
         j627eAkL5CACSMyh61ZsW7CyD5GiVt8b9TWLv1oegJdprUM7uxVHVhX6ea5nXlYAcLjf
         uS6XvV9ej6Gy12uVIBr5O7z25gZxTN4H5euU9rtGK/rSffnir2+WsZPNJKkoVZpY+iaL
         wNvT6NtsOjxFjr02YOhcDFlNxy+ne8llB8JbhDsZy0G1aM7W9z0sYWKPMLILPpr4NlW2
         n/cA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=BSL5Fd5ey+NSvWwk5RIT5oUBgeHAV3OrGjQZ6pf7CNI=;
        fh=dsYYUBz9iA9CFmcqRzhyGUkR6xXWV/CHpNFA3WI3V3A=;
        b=jU3iXB2cWmKAXIGdSM9L/6O71epd2SyOiowfD9zug2qMmXxHdbkPuEcRlgETR1qRjN
         Lo0PaHCgDxk7zbf0A62aAsVAjkrVRXj7ygCnmB2zF2379VL2U6QufxLLze+Mo+rTuVUi
         JTB/TjTjv4irHLRKGBRtePbyipJ5SLWepFCSWp0FQnYEsnmTgUThqbtc+4SjD24zmAuM
         4uFrht0hboyqzPUOWCKDxYVAGjX9gr0vi09TLj5b8G1/aEOdJY24/nugGxjzPrjakeKA
         +OQF9s7fhb5cIY5ujdt7Mk9s2krNfNLVprQWp1j7XKTQD/H60+akBXCWYRQH4kmc7Ext
         GipA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=tQBF5gQj;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.w1.samsung.com (mailout2.w1.samsung.com. [210.118.77.12])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4588dd3fe52si1693105e9.1.2025.07.30.09.32.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 30 Jul 2025 09:32:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) client-ip=210.118.77.12;
Received: from eucas1p2.samsung.com (unknown [182.198.249.207])
	by mailout2.w1.samsung.com (KnoxPortal) with ESMTP id 20250730163247euoutp026d72db55600fb5de9a233ba7f952def3~XFIsd2Xxu0494304943euoutp02C
	for <kasan-dev@googlegroups.com>; Wed, 30 Jul 2025 16:32:47 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.w1.samsung.com 20250730163247euoutp026d72db55600fb5de9a233ba7f952def3~XFIsd2Xxu0494304943euoutp02C
Received: from eusmtip2.samsung.com (unknown [203.254.199.222]) by
	eucas1p2.samsung.com (KnoxPortal) with ESMTPA id
	20250730163246eucas1p2c966d8d5061fc0214cf993906aeab2f5~XFIrva-kQ2815928159eucas1p2i;
	Wed, 30 Jul 2025 16:32:46 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20250730163244eusmtip2f48699419babf589223e18bf9ee0d79d~XFIp1n5Qn1925219252eusmtip2o;
	Wed, 30 Jul 2025 16:32:44 +0000 (GMT)
Message-ID: <ff84b386-4bfa-423b-9364-040598a1ece0@samsung.com>
Date: Wed, 30 Jul 2025 18:32:44 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 0/8] dma-mapping: migrate to physical address-based API
To: Robin Murphy <robin.murphy@arm.com>, Christoph Hellwig <hch@lst.de>,
	Leon Romanovsky <leon@kernel.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Madhavan Srinivasan
	<maddy@linux.ibm.com>, Michael Ellerman <mpe@ellerman.id.au>, Nicholas
	Piggin <npiggin@gmail.com>, Christophe Leroy <christophe.leroy@csgroup.eu>,
	Joerg Roedel <joro@8bytes.org>, Will Deacon <will@kernel.org>, "Michael S.
 Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>, Xuan Zhuo
	<xuanzhuo@linux.alibaba.com>, =?UTF-8?Q?Eugenio_P=C3=A9rez?=
	<eperezma@redhat.com>, Alexander Potapenko <glider@google.com>, Marco Elver
	<elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Masami Hiramatsu
	<mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?UTF-8?B?SsOpcsO0bWUgR2xpc3Nl?= <jglisse@redhat.com>, Andrew Morton
	<akpm@linux-foundation.org>, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	iommu@lists.linux.dev, virtualization@lists.linux.dev,
	kasan-dev@googlegroups.com, linux-trace-kernel@vger.kernel.org,
	linux-mm@kvack.org, Jason Gunthorpe <jgg@ziepe.ca>
Content-Language: en-US
From: Marek Szyprowski <m.szyprowski@samsung.com>
In-Reply-To: <f912c446-1ae9-4390-9c11-00dce7bf0fd3@arm.com>
X-CMS-MailID: 20250730163246eucas1p2c966d8d5061fc0214cf993906aeab2f5
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf
X-EPHeader: CA
X-CMS-RootMailID: 20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf
References: <CGME20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf@eucas1p2.samsung.com>
	<cover.1750854543.git.leon@kernel.org>
	<35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
	<20250627170213.GL17401@unreal> <20250630133839.GA26981@lst.de>
	<69b177dc-c149-40d3-bbde-3f6bad0efd0e@samsung.com>
	<f912c446-1ae9-4390-9c11-00dce7bf0fd3@arm.com>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=tQBF5gQj;       spf=pass
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

On 30.07.2025 13:11, Robin Murphy wrote:
> On 2025-07-08 11:27 am, Marek Szyprowski wrote:
>> On 30.06.2025 15:38, Christoph Hellwig wrote:
>>> On Fri, Jun 27, 2025 at 08:02:13PM +0300, Leon Romanovsky wrote:
>>>>> Thanks for this rework! I assume that the next step is to add 
>>>>> map_phys
>>>>> callback also to the dma_map_ops and teach various dma-mapping 
>>>>> providers
>>>>> to use it to avoid more phys-to-page-to-phys conversions.
>>>> Probably Christoph will say yes, however I personally don't see any
>>>> benefit in this. Maybe I wrong here, but all existing .map_page()
>>>> implementation platforms don't support p2p anyway. They won't benefit
>>>> from this such conversion.
>>> I think that conversion should eventually happen, and rather sooner 
>>> than
>>> later.
>>
>> Agreed.
>>
>> Applied patches 1-7 to my dma-mapping-next branch. Let me know if one
>> needs a stable branch with it.
>
> As the maintainer of iommu-dma, please drop the iommu-dma patch 
> because it is broken. It does not in any way remove the struct page 
> dependency from iommu-dma, it merely hides it so things can crash more 
> easily in circumstances that clearly nobody's bothered to test.
>
>> Leon, it would be great if You could also prepare an incremental patch
>> adding map_phys callback to the dma_maps_ops, so the individual
>> arch-specific dma-mapping providers can be then converted (or simplified
>> in many cases) too.
>
> Marek, I'm surprised that even you aren't seeing why that would at 
> best be pointless churn. The fundamental design of dma_map_page() 
> operating on struct page is that it sits in between alloc_pages() at 
> the caller and kmap_atomic() deep down in the DMA API implementation 
> (which also subsumes any dependencies on having a kernel virtual 
> address at the implementation end). The natural working unit for 
> whatever replaces dma_map_page() will be whatever the replacement for 
> alloc_pages() returns, and the replacement for kmap_atomic() operates 
> on. Until that exists (and I simply cannot believe it would be an 
> unadorned physical address) there cannot be any *meaningful* progress 
> made towards removing the struct page dependency from the DMA API. If 
> there is also a goal to kill off highmem before then, then logically 
> we should just wait for that to land, then revert back to 
> dma_map_single() being the first-class interface, and dma_map_page() 
> can turn into a trivial page_to_virt() wrapper for the long tail of 
> caller conversions.
>
> Simply obfuscating the struct page dependency today by dressing it up 
> as a phys_addr_t with implicit baggage is not not in any way helpful. 
> It only makes the code harder to understand and more bug-prone. 
> Despite the disingenuous claims, it is quite blatantly the opposite of 
> "efficient" for callers to do extra work to throw away useful 
> information with page_to_phys(), and the implementation then have to 
> re-derive that information with pfn_valid()/phys_to_page().
>
> And by "bug-prone" I also include greater distractions like this 
> misguided idea that the same API could somehow work for non-memory 
> addresses too, so then everyone can move on bikeshedding VFIO while 
> overlooking the fundamental flaws in the whole premise. I mean, 
> besides all the issues I've already pointed out in that regard, not 
> least the glaring fact that it's literally just a worse version of *an 
> API we already have*, as DMA API maintainer do you *really* approve of 
> a design that depends on callers abusing DMA_ATTR_SKIP_CPU_SYNC, yet 
> will still readily blow up if they did then call a dma_sync op?
>
Robin, Your concerns are right. I missed the fact that making everything 
depend on phys_addr_t would make DMA-mapping API prone for various 
abuses. I need to think a bit more on this and try to understand more 
the PCI P2P case, what means that I will probably miss this merge 
window. I'm sorry for the lack of being active in the discussion, but I 
just got back from my holidays and I'm trying to catch up.


Best regards
-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ff84b386-4bfa-423b-9364-040598a1ece0%40samsung.com.
