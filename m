Return-Path: <kasan-dev+bncBC32535MUICBBTMMT3CQMGQEO7N42HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id A0615B306A7
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:49:18 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-70a88de16c0sf29201106d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:49:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755809357; cv=pass;
        d=google.com; s=arc-20240605;
        b=A7kd48X/TTZ8S+tqpu6/Fw+iQJFwlyn2TSiakBWrDQv3fW87FAJHU/Uz/ZlJRL1OR3
         B8o5dRMZGNA3Ekx7jOi3HcZdAgE62iozCsaZYrUqZms3QG1a54LfpAfTL68I7+HVi5TF
         Rk63itfY+3dmq4wVvw/WSpG+IFD/XAgcSRLfRDMLr/V33xUPUFAcIVMQhLLpOJX+uOVv
         11IgcE7O5DyVcCyxqw+hIvaseC4fTVI/3XdCY/FQ4nl2nAZ8iYRPlpxlaQQ32aich4RN
         VYRRU3vZGgSsa37vIYgnCa7B4o7X+kHnc9eI3r1s9CXs8w8FTkohq0ex6SXcoqPBqDWK
         CL+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=k3B05Mqya63fKy8U3LP4M1+A5XmET6vXecnHvhsGRDY=;
        fh=du7Oz9LYCYEU0qy/OMzWSTl3/Rrb+MCbMTw/IaJvEm4=;
        b=MzaTs0yyd09h+DPWX8PmeMTHf7rgvAL1UtXARXyx6CHbX0/bN+mGSX6GGh4fueB1h7
         EWuls5A/Jvi8fexITu2DQ0S9AEvxwkqQbcWTz7HkpL3vOSDaHmUokmz9ykwC4u3vboDU
         syNTPMMzqQrNKpQnnnq/d5+TBdqz96t5jUf3xb0Upe14pgaacXJV8WECy6kncIetEZ5+
         WNAjLQ3xuF18M4Dn02vzVWBR0WYk4Z9IfkORpsc4fPYRBcZtqC430RkW1uuw2yRJkeuw
         g+5fPawevEmZHe8nkK2LQ8ppX8pH3FxVdSbIvLeNSPNpUoAAGk/AWuD/1yezFuAYP2y9
         9u6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=G40SbERB;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755809357; x=1756414157; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=k3B05Mqya63fKy8U3LP4M1+A5XmET6vXecnHvhsGRDY=;
        b=mfZW1DiCTT4pjLuY1QcTcEGfvr2Ah422JjPEEivoz+OCwoe1JuFfCSxC+WGYZ31v+M
         O44tOPAU5IQ28SkGhK84w2LROKyim0d1vhh3i8Yh9vKgXt+n4aDlNBSQ2LpWGz46pJs5
         8GDoQVp35gCw5frvekHIk8lH0vExLbbIgDmAbFb+cgXUWeKTn9+p+lqymJt/OB7kXB/g
         weBYOHD/uhkdI7R8s/uEBM2OlQc+SRnWrADo/LtRh0rwwqbsb5rfLYZCu+mfMUhNOJyA
         Tf5qfzSgVDNtOk0xyulb8ZuisN/Qon3wN50ttYMek6RsDy9wvf7Gvlg6O5aGL0mDuv3E
         3GjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755809357; x=1756414157;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=k3B05Mqya63fKy8U3LP4M1+A5XmET6vXecnHvhsGRDY=;
        b=V7MXNzmJkXNf+smiI5DX1lMrO/vUARei0WCddzBMrtXFpQ6k81VcO1qGMgevs1UXXI
         3H2gW/AS811GIsvd60l77+ra+2g9Knx3PHo0G+/60quwr/PnG51pyx+iEN1/dEH6qGAg
         DqaBzRjWzgq/U7BqqWwA/fWFZpqlGxG1twBgeRd+Ia9WxVSitMiwPz+ACUsqn8YFAyiS
         fl7pPQKx0yTIUxZwV9sKjf3VPy/7ZXPGgau30Bb7MJA+oCPvio9jFpC4Kx6rvEOFeRek
         Qobt1vKiFQCFGBUi/7rcMSmnv9eAgjs1JyLCGRp4zeEXEAEV9gyHWLmSmnrVgsHpwXir
         U6Ng==
X-Forwarded-Encrypted: i=2; AJvYcCXxI8PHRdQmyB3iMXYOJYNjHjh6PmdR5zVCg3ff4NJel/Vdvh0rZyvBLa4Lcj/Z2YOsZTVDeQ==@lfdr.de
X-Gm-Message-State: AOJu0YyC0T3xX5rZritvYGhGdYTPCKYsudGmQI0knKdOcDmvDZ3zW5mf
	Y3EakaI4UbvaFsrrEBFwWVMwtzlO52tf5/rNaC3H+bBWggzF3IEQ+KTI
X-Google-Smtp-Source: AGHT+IE816JjoLXZNXiciHIGGGfOhZh4KRaZThqTgMQft4Surj3wcx/VHQznBfd6f+rTG/p4qEpPrQ==
X-Received: by 2002:ad4:5c4e:0:b0:70b:9a85:2cad with SMTP id 6a1803df08f44-70d9726e8e6mr9836766d6.24.1755809357424;
        Thu, 21 Aug 2025 13:49:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfpQkDj7gEmBDPh/ZslR0L/WXso+bTM9UlJiZ8PCWv9kg==
Received: by 2002:a05:6214:20c3:b0:707:1972:6f43 with SMTP id
 6a1803df08f44-70d85c3f115ls23542886d6.2.-pod-prod-05-us; Thu, 21 Aug 2025
 13:49:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXc6BVSUW52Z7/wo58JiFWC8/gzAFrTozC3s8HuXewvZs1KACVByPl5TeJFDChy22/MxcRn6FRePqo=@googlegroups.com
X-Received: by 2002:a05:6102:5986:b0:519:534a:6c21 with SMTP id ada2fe7eead31-51d0f90dad5mr199825137.31.1755809356552;
        Thu, 21 Aug 2025 13:49:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755809356; cv=none;
        d=google.com; s=arc-20240605;
        b=INyf8FpKFZhHPXPzOThVOlE49ZvXWdJyzlS9YLE9REsL5KSWoiw/wiGmwhjV8hl2m5
         TIQBCT6pWH8DPZnEjeX9Sba6eUfb0Ruq1lieaU5epnu7i8eNsBymar+mbcyqOofeuF1f
         RBB10PvS0nWL4kboNIC7sT+Z1G4qoTNw/X/YlZj5dwNk4AsB8rZXQn6XY3C5I2dR/S3c
         Y8m+dwbP7HZ0ZOWC7gslbrJXSHgpmycHaggpf3ld3t4NLM82v8Zn6nH0hTka+/IRIsCo
         NH8kJzRNCFh/YkxZ9jpwNXIx5N2jIh5aOExrBwOwa8GUYoOO1IVu7kmetXTYmfZ3IOLH
         aDdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=OQbfbvrWDouK+ZcKIphQE1nervr1PSIMFSTWfTxDfjA=;
        fh=PMz1vNc1ugJGFTpV3BS8t0xqvRtjZl7XSZHD5mKYkOg=;
        b=cSysj+RR0OKX6Rza99+UjvaBnhP345hctXRxXU+UAzb7OvWubPJllqQcfxga92qxEt
         Yy2Ynevoznf/hhU51ldB2tltHZfQ7HWii3LCQsQ4GqrHRBOA2hawXuy3hfOAao6D8Ltp
         XXVRpmFBY5lPPqpppPwJJ+QvKGUN1/n43EAgfVNfqHqe+71Ddjv0vRJNwo07h79vuHs1
         69eEPDw2WtjCR5S4uG0Rcv+RWAEzK1SIkhp5piduTe54kDuHtS3dqTn2BHKS1HbTUjtg
         oF7u7SP+ih1GPNCZkoPoLOLYYEl1TCymT+LMucxzyXGrsvVPGiR4LlpJv5i+dZdkEKwe
         o3YQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=G40SbERB;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53cba1cc38fsi4626e0c.2.2025.08.21.13.49.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:49:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-570-icPCL4xsOAW2zyg2ibjHcQ-1; Thu, 21 Aug 2025 16:49:12 -0400
X-MC-Unique: icPCL4xsOAW2zyg2ibjHcQ-1
X-Mimecast-MFC-AGG-ID: icPCL4xsOAW2zyg2ibjHcQ_1755809352
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45a1b05d8d0so8973705e9.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:49:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXQBFZqpDbuRnyA8ISOmqP+WzC/IgohqxuwfDd7yz5pjt+gY4nII3wx8jeQt5phw7PzOdiQk6ow/Ag=@googlegroups.com
X-Gm-Gg: ASbGncvT0VkBdt602u5SHwL5P1uBBi/Mr9PcgssQea6riDAsG65VI/NW85mMCS0Nwlx
	kHZUkWD1cDoP5cRavQCRImimBUfnVPTvN8z0lCEcqfZGLfOvPoHGfUZGJLGVV7NMl+FKecpAnGv
	MWn8zTsKyZChEgu4a9qDnqGRfncAUpPSc62Af44uhB6V5RtxBhhq20rfiZ7mK6B3H7wGiC9NTqC
	FJhnkROQb9zEYzsDlN0YAqqVLGSPvGNlqM1I9DKhLQRiIO4m76UeNgBlBNIoL7YfHWLvx6I6l/5
	/ojADjMAQwVOShHRjOTDzvxvJTv2uLD5RF40iU28SPfVqCRALOi5BLM4fGkJcWhuvWKgSilqeLo
	Rsh7TYbEgmTJGCA14C4p+G59ST0puIwaxLLNjyKn4bp7fMqgkRcRXwdSDQOvWjA==
X-Received: by 2002:a05:600c:3584:b0:459:a1c7:99ad with SMTP id 5b1f17b1804b1-45b517c5dc0mr2898175e9.22.1755809351431;
        Thu, 21 Aug 2025 13:49:11 -0700 (PDT)
X-Received: by 2002:a05:600c:3584:b0:459:a1c7:99ad with SMTP id 5b1f17b1804b1-45b517c5dc0mr2897695e9.22.1755809350879;
        Thu, 21 Aug 2025 13:49:10 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f26:ba00:803:6ec5:9918:6fd? (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3c4c218c599sm3550158f8f.67.2025.08.21.13.49.07
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:49:10 -0700 (PDT)
Message-ID: <835b776a-4e15-4821-a601-1470807373a1@redhat.com>
Date: Thu, 21 Aug 2025 22:49:07 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 12/35] mm: limit folio/compound page sizes in
 problematic kernel configs
To: Zi Yan <ziy@nvidia.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
 Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
 Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
 Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>,
 Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev,
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-13-david@redhat.com>
 <FFF22E91-6CA5-4C8F-92DE-89C22DB3EAD7@nvidia.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <FFF22E91-6CA5-4C8F-92DE-89C22DB3EAD7@nvidia.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: bqnaaAunLMpe3PBWMaNHeUDoIAWZUVceLI4o9LtagrY_1755809352
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=G40SbERB;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

On 21.08.25 22:46, Zi Yan wrote:
> On 21 Aug 2025, at 16:06, David Hildenbrand wrote:
>=20
>> Let's limit the maximum folio size in problematic kernel config where
>> the memmap is allocated per memory section (SPARSEMEM without
>> SPARSEMEM_VMEMMAP) to a single memory section.
>>
>> Currently, only a single architectures supports ARCH_HAS_GIGANTIC_PAGE
>> but not SPARSEMEM_VMEMMAP: sh.
>>
>> Fortunately, the biggest hugetlb size sh supports is 64 MiB
>> (HUGETLB_PAGE_SIZE_64MB) and the section size is at least 64 MiB
>> (SECTION_SIZE_BITS =3D=3D 26), so their use case is not degraded.
>>
>> As folios and memory sections are naturally aligned to their order-2 siz=
e
>> in memory, consequently a single folio can no longer span multiple memor=
y
>> sections on these problematic kernel configs.
>>
>> nth_page() is no longer required when operating within a single compound
>> page / folio.
>>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
>> ---
>>   include/linux/mm.h | 22 ++++++++++++++++++----
>>   1 file changed, 18 insertions(+), 4 deletions(-)
>>
>> diff --git a/include/linux/mm.h b/include/linux/mm.h
>> index 77737cbf2216a..48a985e17ef4e 100644
>> --- a/include/linux/mm.h
>> +++ b/include/linux/mm.h
>> @@ -2053,11 +2053,25 @@ static inline long folio_nr_pages(const struct f=
olio *folio)
>>   	return folio_large_nr_pages(folio);
>>   }
>>
>> -/* Only hugetlbfs can allocate folios larger than MAX_ORDER */
>> -#ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
>> -#define MAX_FOLIO_ORDER		PUD_ORDER
>> -#else
>> +#if !defined(CONFIG_ARCH_HAS_GIGANTIC_PAGE)
>> +/*
>> + * We don't expect any folios that exceed buddy sizes (and consequently
>> + * memory sections).
>> + */
>>   #define MAX_FOLIO_ORDER		MAX_PAGE_ORDER
>> +#elif defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
>> +/*
>> + * Only pages within a single memory section are guaranteed to be
>> + * contiguous. By limiting folios to a single memory section, all folio
>> + * pages are guaranteed to be contiguous.
>> + */
>> +#define MAX_FOLIO_ORDER		PFN_SECTION_SHIFT
>> +#else
>> +/*
>> + * There is no real limit on the folio size. We limit them to the maxim=
um we
>> + * currently expect.
>=20
> The comment about hugetlbfs is helpful here, since the other folios are s=
till
> limited by buddy allocator=E2=80=99s MAX_ORDER.

Yeah, but the old comment was wrong (there is DAX).

I can add here "currently expect (e.g., hugetlfs, dax)."

--=20
Cheers

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8=
35b776a-4e15-4821-a601-1470807373a1%40redhat.com.
