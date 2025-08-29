Return-Path: <kasan-dev+bncBC32535MUICBBJXXYXCQMGQEJC57PMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 79237B3B810
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 12:06:32 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-70de47323ddsf53507346d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 03:06:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756461991; cv=pass;
        d=google.com; s=arc-20240605;
        b=ia5u5udDuh+QVnZUr0lULwppPByV+XOHcqEtmlOr/0VPyULa0KnwCFm1b1p6dMIITm
         1IpcKjX1Km3GB1d+KdLwCMnGUDSBCctqRCmgyNvROcOOSsIBG7ozfrZ+k6EBKKGTTPfI
         VveG9P+MH4B2GQBJEWZYmGx+VVGpYe41+IJrXlmWYqNkNuV4ivpKxt2KqdHCLB4rNyUe
         VYNUap8e1ltigx1pbrtaiE2fZVOSubuCQw9LLaUC9mmwNN6JjVkRNaWPCKvGy0p8twqH
         saoMWVK2o4uNKLrN1mNLmMh33rHL3sK0G/K8wqHBTpulKu81TGbW2FF4souBsrvsZD7Z
         AHmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=tXlxLfPqsz0sJbQL5hu7u9O996r10o04CxZ0i27alqA=;
        fh=mbOlQDp2o5X0parO4Tg0b9w4nwpjC2tX/1CcPl4MVZg=;
        b=lV/l57bZ1+VMCHuTFyZ+jnmXSYLQhmk0h694RtfijUIEs3gpNJFSiqUoyHf1AjCO3g
         IsO8hWtsJGa8Nk9rmjSukCyZ3ZTfrl+wCBK48Mrt2/f0AA3A/2utSvJfbHitoW6jxF5B
         ebLVHBPBvSmU5v/kO/zSSqNh4lZ2uxHUewP581HN7rxN28wnt/Yu45EufBlAFO+5u2qA
         4/2ccNmLfafO6Iq+0EdTyiwmB95yvN/rzLvJHwCFeBniERTd6HgTT1SQU4yMVSx0LTnu
         +U/14kKeWrWyRo7pMAqq36N6zBsbIL3GmXJbTJcSLjPTCkhmJ7Wk2AaY6cR9kWJMD/wM
         ANEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=N35AhSz4;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756461991; x=1757066791; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=tXlxLfPqsz0sJbQL5hu7u9O996r10o04CxZ0i27alqA=;
        b=bFa8Hlp7+XM506WEYrturT+lKxXRuImtacpyr4X8o0/n5YJKAIXS34nV2/fwJz50X5
         wLj0jenN6IHySaEeJSIeDF5+Y2UyYjK1DtQr99Oxy/N7Cu3vJh6va0M3Fwzrq89JzecH
         XKcdQFrJhyCQ8ZJ9v7pvY/wtGUAt9C+MNMT2VYnO7L9lHNoUEOi0AB+nCTd8aDkLAP+d
         tVBJkwdgveTP9G9cYOq3PfxMymAPWcjf1blV9JoprHi1ciRnJ16OCoZ4DGOrwdDSPRD0
         8i8esBRYEEyznQQu3s9hxbdSOqzm54M2Xkxgqp07R34eOsMIuKfgSVMyUunvxtAdQugx
         DFyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756461991; x=1757066791;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=tXlxLfPqsz0sJbQL5hu7u9O996r10o04CxZ0i27alqA=;
        b=tTCsFE5XMVD51N/7wZmx10nMaYdGQGXtIQ3JJJSpVPd2Xe0COu9e+QHUqAm7N8cIz+
         lGtOh6wb6BP5vQ5iI3g9Y/PDKOek2Q0xOdISj7HYQESGEfVrF5pRKnOOnilpQie8Moxm
         hb7SIuTOYT0JcTiPlBzVKlo+v0uOj3lswtrjmTg3DEul5DDz/LMPv0qBoHRowaEsjhDK
         HSXI6S1WBEZiOFNmRvIbwt4DOYYfbHFHkVmbXU2bl6h0Snb+sFkvaM3d2KnbsmIFKlRU
         dzzZOukquOR1nU7srtx8U8+S4bfo7IYHzsMiwdFZEPC7NjTzRFKcUuunNObLMOnJPxtM
         Y4PQ==
X-Forwarded-Encrypted: i=2; AJvYcCXhwj7pUqSyhWw6uAhdf2EmCOSVNbyq+uhsKm0BNH/Nj5caoUdLy2XqzOYUVsktebFlzWMXhg==@lfdr.de
X-Gm-Message-State: AOJu0YyXYooACCnVGJqt1waXAk7dGY4sJzaCcNHJITyW1rptJjDpxiNk
	8+iW6uFKFsNmmAaea27yt4A0A0ITEPfUjMWbPG+wOsbu5SMgxLbE7nqj
X-Google-Smtp-Source: AGHT+IHzM6yI62ZPEkS27Vc00tGQad4ADgyoHpcFO+GgQVAMXIgOmrPgZSMmwUH/7xDH8duIBunF/Q==
X-Received: by 2002:a05:6214:2aaf:b0:707:5273:9dd2 with SMTP id 6a1803df08f44-70d97236dcbmr350255226d6.45.1756461990965;
        Fri, 29 Aug 2025 03:06:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfAY6KziL2+oUrSnRZdtol1746VdVcIy5O/JnGt/aCWRw==
Received: by 2002:a05:6214:459f:b0:70f:a06e:1d5c with SMTP id
 6a1803df08f44-70fa06e2432ls4026056d6.2.-pod-prod-04-us; Fri, 29 Aug 2025
 03:06:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUuNJvZPG53EZIgJe+6gRnMuO9wsb8+twnOZUxJpkoBJjVa0bbUbvyj7b3Z1tU6Jc1sydmUCJNYN+E=@googlegroups.com
X-Received: by 2002:a05:6214:2a4e:b0:70d:bc0d:bf50 with SMTP id 6a1803df08f44-70dbc0dc99dmr215294406d6.8.1756461990074;
        Fri, 29 Aug 2025 03:06:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756461990; cv=none;
        d=google.com; s=arc-20240605;
        b=HamYgRxBhFx1qrFh8/qg2LXLaJrzX9H7YNV6SoQzYO/qBWZIzk782jN+W00Wp53/X7
         pLonEZABx6p3RfURHVd/rB1gV+iHYhuzOGkutOkYndkwV734gM5Otnp77/nchSagdxv9
         /JoMb7AtOFfuzLcPX6NaiiG+WEBhq7Y4Rimtl9JYbLD7MQFpsCBP2Ro3/U4p99+Lbe8Y
         1m4J3zwF0rtwjOSnuxO2+yWi1C21CuKOT+2y/6dsfg2q9rIM3+yAzms3avsxsYq/Xnia
         mOaX05JN+P/bqelgEioRmz397/el5C16+F4wH3hEtUVYvtCqq5VGZ+U0eXbiW6j4XNZR
         xSEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=lPHoMHV5vJS1QZV5L+lWiiTGuBUarel82A4quq5C180=;
        fh=FiW+nAwZeJKR+0sZolHSzOlA39ZxLUYun+seTwMRPP0=;
        b=Fb3htWJdssVwEXvgq25osNnMLPLIrrR+hgOErRhN/qe4IFK2mE1E+HTF9EOj//+xqG
         /vIjzRDUXASfgLSxWTekY3VCKfMQ1mOSvrzfwyDz8+TgQxAVr0KLYWotwY2gdADmhEpk
         SMjBAAYffHBdT1n/rhMYHPaIUvTVuNcA8rn4v6wHR9zPQGrIwfZ/7v+HV1d5+oXT3cJ0
         7FPxTlcF31G5auAXCjJFZ0kzVPkE71hIm5lV+7TmWZlmJQVaMTCUvJqzIfpQXlaL9vaR
         TuAeFsmZPVmDFIsWr8IJtUpdthMoC0UUE+LeufBjtp11VCoUKCmXzl7Xr8rNVZk//tLj
         Q12A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=N35AhSz4;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70e57e1a4d6si768946d6.1.2025.08.29.03.06.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 03:06:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-358-D1KHK7pOPI2wH3XF6FCXyA-1; Fri, 29 Aug 2025 06:06:26 -0400
X-MC-Unique: D1KHK7pOPI2wH3XF6FCXyA-1
X-Mimecast-MFC-AGG-ID: D1KHK7pOPI2wH3XF6FCXyA_1756461985
Received: by mail-wr1-f70.google.com with SMTP id ffacd0b85a97d-3ce7f782622so647331f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 03:06:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV2qett1LI+s/B3AC6tJOSNP/0Qf4D2HrQqIDjJx+Hq1FarR75ujsNg3SFIb0la9TsFK/MIYDiyPK0=@googlegroups.com
X-Gm-Gg: ASbGncsmiv9NQLe4RGM/dsIZh7GrekfB6/uL8YbT6QZbNWMg3QWzPPWV8y4ihk4MpiP
	AGO+hbtAjPaKbON1/QE18KQfCEchJF8ws5ZB9EQCr1IoZsBWX3GLE/bEbf4+ccDro0EILARB5cm
	ZwStR2lfFOL3VlEpHmt+PqFPMm3i6yTRexSqTb3dXKrwHd+WpXnONUTzsdPk/N/sDZ0//3DQ8ps
	e7nYfDfiFasVlViQ0DUaKrLYYTekInOQQvsyHRyGUDTWNSEOcqiIN780jNq/YNAVy5soRJ2hpp4
	BiAz4eoA5HOAYn9ILC63EwD/382ujcuR3e2mrba1o0jhqKHkHN+nA8X5EqD+SjfU6J7LG9CGrOc
	Q3LBQ+IgXizple0elgaFnUlkoZGobYL9aoGJtR71kmIeTkQOc5dkKZKAZ7Z3REaSg
X-Received: by 2002:a05:6000:2082:b0:3ce:663a:c92f with SMTP id ffacd0b85a97d-3ce663af648mr3716817f8f.25.1756461984516;
        Fri, 29 Aug 2025 03:06:24 -0700 (PDT)
X-Received: by 2002:a05:6000:2082:b0:3ce:663a:c92f with SMTP id ffacd0b85a97d-3ce663af648mr3716770f8f.25.1756461983963;
        Fri, 29 Aug 2025 03:06:23 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b74950639sm85846585e9.17.2025.08.29.03.06.21
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 03:06:23 -0700 (PDT)
Message-ID: <547145e0-9b0e-40ca-8201-e94cc5d19356@redhat.com>
Date: Fri, 29 Aug 2025 12:06:21 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 06/36] mm/page_alloc: reject unreasonable
 folio/compound page sizes in alloc_contig_range_noprof()
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
 SeongJae Park <sj@kernel.org>, Alexander Potapenko <glider@google.com>,
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
 linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
 Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>,
 Mike Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
 Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
 Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-7-david@redhat.com>
 <f195300e-42e2-4eaa-84c8-c37501c3339c@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <f195300e-42e2-4eaa-84c8-c37501c3339c@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: 20uz2gWjhDKpRGziN6pWo47bKf-VgJ_WrbZqmu8y8xg_1756461985
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=N35AhSz4;
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

On 28.08.25 16:37, Lorenzo Stoakes wrote:
> On Thu, Aug 28, 2025 at 12:01:10AM +0200, David Hildenbrand wrote:
>> Let's reject them early, which in turn makes folio_alloc_gigantic() reject
>> them properly.
>>
>> To avoid converting from order to nr_pages, let's just add MAX_FOLIO_ORDER
>> and calculate MAX_FOLIO_NR_PAGES based on that.
>>
>> Reviewed-by: Zi Yan <ziy@nvidia.com>
>> Acked-by: SeongJae Park <sj@kernel.org>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
> 
> Some nits, but overall LGTM so:
> 
> Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> 
>> ---
>>   include/linux/mm.h | 6 ++++--
>>   mm/page_alloc.c    | 5 ++++-
>>   2 files changed, 8 insertions(+), 3 deletions(-)
>>
>> diff --git a/include/linux/mm.h b/include/linux/mm.h
>> index 00c8a54127d37..77737cbf2216a 100644
>> --- a/include/linux/mm.h
>> +++ b/include/linux/mm.h
>> @@ -2055,11 +2055,13 @@ static inline long folio_nr_pages(const struct folio *folio)
>>
>>   /* Only hugetlbfs can allocate folios larger than MAX_ORDER */
>>   #ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
>> -#define MAX_FOLIO_NR_PAGES	(1UL << PUD_ORDER)
>> +#define MAX_FOLIO_ORDER		PUD_ORDER
>>   #else
>> -#define MAX_FOLIO_NR_PAGES	MAX_ORDER_NR_PAGES
>> +#define MAX_FOLIO_ORDER		MAX_PAGE_ORDER
>>   #endif
>>
>> +#define MAX_FOLIO_NR_PAGES	(1UL << MAX_FOLIO_ORDER)
> 
> BIT()?

I don't think we want to use BIT whenever we convert from order -> folio 
-- which is why we also don't do that in other code.

BIT() is nice in the context of flags and bitmaps, but not really in the 
context of converting orders to pages.

One could argue that maybe one would want a order_to_pages() helper 
(that could use BIT() internally), but I am certainly not someone that 
would suggest that at this point ...  :)

> 
>> +
>>   /*
>>    * compound_nr() returns the number of pages in this potentially compound
>>    * page.  compound_nr() can be called on a tail page, and is defined to
>> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
>> index baead29b3e67b..426bc404b80cc 100644
>> --- a/mm/page_alloc.c
>> +++ b/mm/page_alloc.c
>> @@ -6833,6 +6833,7 @@ static int __alloc_contig_verify_gfp_mask(gfp_t gfp_mask, gfp_t *gfp_cc_mask)
>>   int alloc_contig_range_noprof(unsigned long start, unsigned long end,
>>   			      acr_flags_t alloc_flags, gfp_t gfp_mask)
>>   {
>> +	const unsigned int order = ilog2(end - start);
>>   	unsigned long outer_start, outer_end;
>>   	int ret = 0;
>>
>> @@ -6850,6 +6851,9 @@ int alloc_contig_range_noprof(unsigned long start, unsigned long end,
>>   					    PB_ISOLATE_MODE_CMA_ALLOC :
>>   					    PB_ISOLATE_MODE_OTHER;
>>
>> +	if (WARN_ON_ONCE((gfp_mask & __GFP_COMP) && order > MAX_FOLIO_ORDER))
>> +		return -EINVAL;
> 
> Possibly not worth it for a one off, but be nice to have this as a helper function, like:
> 
> static bool is_valid_order(gfp_t gfp_mask, unsigned int order)
> {
> 	return !(gfp_mask & __GFP_COMP) || order <= MAX_FOLIO_ORDER;
> }
> 
> Then makes this:
> 
> 	if (WARN_ON_ONCE(!is_valid_order(gfp_mask, order)))
> 		return -EINVAL;
> 
> Kinda self-documenting!

I don't like it -- especially forwarding __GFP_COMP.

is_valid_folio_order() to wrap the order check? Also not sure.

So I'll leave it as is I think.

Thanks for all the review!

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/547145e0-9b0e-40ca-8201-e94cc5d19356%40redhat.com.
