Return-Path: <kasan-dev+bncBC32535MUICBBI6NY3CQMGQESD2PWZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id CA306B3BBFA
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 15:09:56 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4b109affec8sf42879631cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 06:09:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756472995; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZMAiCkxfx0eQ8htywaArk8remwLS351V71sUMvm0km9EMvuXeL+e+zsD8XIcRcloKR
         a3pD4/CqqXFyWnidntLBt0UF4NVFhRqXwdPjU3FT3mmQhJscmn50D18HijLbP68ket/Y
         /Tk2ieEa4EET1bnjFUGVpo7wye/JjBmHJ0GRNjNFApk2EX0M4xts08qnwx38uAbTFq1N
         QtSY64Eo6I4XvvjfIH7CMEDOHTUQkEZr2dbOc4vkyeVEkMocqreytX+clzYWmImrPXjn
         0oQ2eqxooYCeZXGJUMxpvsD2VtCOS/eDPyyGOx+JSOR3Ff3UfzFcQ6K0O+ubLbcVqroe
         /HpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=IaoYMD1YXianD0woDn4T7Oy/AhU5+pygM+uNs4Mqkx4=;
        fh=3ac3zmbH/UFflO4/5wMWKDed5VXiwO3MFSb3Ezv7v1A=;
        b=ex18fhc/h5QP9UqE5KtEimfxilWfYCQ+CCklEFBI4UXlFKqCvSIgPLiihJSsjghwpu
         O6doPo5ZplQv9Ye85yyc0zevJunk+ergoRazmVDphekW3lm/JuVbQc0BXrNOQMj5jsp/
         zqRpe44eK3842brdobhy/71xdpKVVRjFRTLW7j6QrvUGP8MUPFYeYvhbuYbLW13heXQY
         eROSSDXlduycIgqseSMQPrXbrLHPpyD/xf8lQc3FJIJi7u/qphF/vPSh20Kr59GALo+f
         YKzrXAzM2df89PCRkxlOedBcMaAc2FXFIcI3uQo6676BtcmICbhAWPGgeqB+S2Lqgl0+
         IuYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=W77Nk43K;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756472995; x=1757077795; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=IaoYMD1YXianD0woDn4T7Oy/AhU5+pygM+uNs4Mqkx4=;
        b=LMyGYIJNkhguZg9up5CaLMrXWHRSBT+CEchhU59T7BAAV9gHxbIkTRAI4j7Y1RSRQS
         PWIADIXs2auQLjDvzXWYd5MD+7U2o+SMm2X70mbis6HIvhzMR2r0oHhVCw6UxfxnNrzZ
         XmNZdoP0P7w3xNlV2nZaFdhe8JMppt1heThToOhwl1A+ZSk1tLZKXUly+uUp9rH0pWCg
         L9zpJP0EH5JiseyjR8XqHBMbNTqrB7Ma4mtD/mTNC+lE2C0gxQ+8qrbKlbdce9u0BWNF
         Et1rXRGztezc4V0jZngafXen69XQnJlgsEWrj7ocw0jD/ODax25fI96c5sG4Q1AvGbxZ
         z9rA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756472995; x=1757077795;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=IaoYMD1YXianD0woDn4T7Oy/AhU5+pygM+uNs4Mqkx4=;
        b=aCrpF/myDsyMJVKoR5IJEP5Qz/6a8N9zqk85BzuVxjrGPDgO3zK9iT4GN359fkAOW0
         XXtQXmUfVNBYG966vspka7LGml/Y5Sc5qMJqHTLEJd4lI/FyE4S/Da2TqEejPvzHAqQt
         yhr9Gm0oGakGEzR7gbB9ec8CS9N6zUNVEFA1oFnl6cbp64ML79oS0tRy41xK0ahrE7/Z
         OmYpN1DykEHJhb+GB4TIx0Uk0VoVRuf2bphH7h0SEJtzbVhz/vbJgPAe0CtRYdgGp28z
         +bCy8iv5xhiR9Lft04S7/GC7etIcgGPLg7nZ3ksjzE5fbD9xmSjsy5h3sVQI1BWVfEw0
         t6Zg==
X-Forwarded-Encrypted: i=2; AJvYcCUWP3ldrrLhYJiUDb8vMm2i6x4iUDXFkY1czb6+8itCpW6K4bMM5ohl4qwG2JW85Y4nYf8q5w==@lfdr.de
X-Gm-Message-State: AOJu0YwHt4KMRO62dVGvdb41GIgqC8UQdU8vOoEu0rhKzL807WwSP6eB
	C1FMHPHe9vyV4kYBT4aU5Ddfs2ciWxqC1qnlgyVFRuiB3TEJApUlQYZH
X-Google-Smtp-Source: AGHT+IF+P9jRzyNhN6lylNSAhchk8VycUz5xq88XiDLgc6Xa3/RuV2q16SYbDEOVOsAxe3/3G2p8nQ==
X-Received: by 2002:a05:622a:1dc6:b0:4b3:102c:9263 with SMTP id d75a77b69052e-4b3102c9b0cmr20455201cf.39.1756472995494;
        Fri, 29 Aug 2025 06:09:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdF/EIWaU5r8KI2/IT7mZ9zg8xCcYDHOpESjkrGwnPSZA==
Received: by 2002:a05:622a:1207:b0:4b0:8b27:4e49 with SMTP id
 d75a77b69052e-4b2fe66330els29974761cf.0.-pod-prod-02-us; Fri, 29 Aug 2025
 06:09:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU7II1LUjcYseguw7QjjKj06dobZMvPUd38Ty6DYCQ0+pGj9VX3RdPDYWFGxqxcpJqvpbjq7YHxJ6c=@googlegroups.com
X-Received: by 2002:a05:622a:489:b0:4b0:ad2d:ab84 with SMTP id d75a77b69052e-4b2aaad3a10mr293952771cf.52.1756472991377;
        Fri, 29 Aug 2025 06:09:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756472991; cv=none;
        d=google.com; s=arc-20240605;
        b=ckacKpcK+BCLI39K81ZZRmmAXXbAqju3ZpD09Rk6FuFamK+c/Z2p3bDi/1AOzopjQF
         I052LyzauRwAauv6VfmeOoe2Go7FfIXQg47/EeH5kKJGO8J4/aQzpCnUnQ3b4rQYg8nv
         eQNS0xXnjh3mvp6XRvutPfmMG8oRAXyfOL8gHpOAOsWG1HPjrGL64rK+MhcMOFjvdQJr
         iz6QEqF/EEXi0WFd1atmNxR2pGHgXcANM7Z9idZ8EUBYN4Go8DxOj1HmA1b2KFxkAa7T
         yNY3fUA8+x3p73R8F8EhC1B28H6gx2pWjBi02XRhCeHQAEbH8Ceolov51IE9acW2VJqH
         JbOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=GMW9HLrWQaKZG+KlEEwhYfHDFt7S0jSgL0MHJQucZHQ=;
        fh=wN8LMaxtrP351KrWijW3kbejCbuIQuptqZXyYa6Fns0=;
        b=XouXc/kqJ50PVod6ZjME5ZRFYGB36vCj/3J3NwcYx6wkITl6Cl0z48/eBIQ4UYoHSn
         Bxqg0PcFXWdtEk6FDXO4rrz3n3Vx7lalmZbYJv0X+YrTnXh+139WqjjAGhGVGBqeYcwK
         qLY+bFXgCuAElLqfh4Rx8l4PJwllyzqKHX38oDAequVU+v4/WkQHRCjcvJjgCCRi/DdQ
         gaJwtbFY5t2DTVN0tAO98IUEK33v01WKSCCQb7A62nbU6RZtT8HJnSWQPbGlh4LYfoPm
         pwCavteziIUv4fjhI9lgS/4CLR3uPb5YWpiyGLRtpiYMMdFtOb3mlQlxVl7eOt6l2uSq
         AgPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=W77Nk43K;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b30b62cd1esi1078151cf.3.2025.08.29.06.09.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 06:09:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com
 [209.85.221.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-185-Umj1L4CWNEq13ZU4aguYHA-1; Fri, 29 Aug 2025 09:09:49 -0400
X-MC-Unique: Umj1L4CWNEq13ZU4aguYHA-1
X-Mimecast-MFC-AGG-ID: Umj1L4CWNEq13ZU4aguYHA_1756472989
Received: by mail-wr1-f72.google.com with SMTP id ffacd0b85a97d-3cc3765679fso770100f8f.2
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 06:09:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXr0gDvSsF9rnI6OiTrKdMZRxMCrrFYtLCr/gmLDY2gJx0t9kexd1GibIPpNH00Bu0OuLxqFCNhbLY=@googlegroups.com
X-Gm-Gg: ASbGncuvUYIHBzy/Obb+/wA5nSZ/DSmu8idSwSYaqer3DFwZ+a6I6zkKQbbVvqd+36S
	WsU/FYqnXyBm7XL4wdDxqMxHHUYY5XQ+/QmzD7ZKualqml+vCz/71ZsiMGrSPoDYpGtMpCSZYCj
	Bj4Dow7pkpFphTEE+6xxkyEbFqozsXogXfF3OKW6oryfHRuwJMvvSAa9VTrGYSo6BLVkFf7VCa7
	x3RdMMAeARGfYDkAU8dR0RJAJKBIXVLgxV2cV+cX0hYaupuezQzZZUJvOmuEHkPZG8TUwTUEwDQ
	Fr//tJhoHPf0VVh6fypb+Zlg4ju8iY+ii6MJDYGwidxLkJJSC2tm3ux7bMFShxID6E13tziI6qt
	P7rHdahtsyBUSNuzFP1Cup/ooGWN9sbDJRU04fU8qVX+trG/87ywmEhkAsPYa+fKI
X-Received: by 2002:a05:6000:4023:b0:3d0:d6e6:5d96 with SMTP id ffacd0b85a97d-3d0d6e6642emr1463772f8f.38.1756472988578;
        Fri, 29 Aug 2025 06:09:48 -0700 (PDT)
X-Received: by 2002:a05:6000:4023:b0:3d0:d6e6:5d96 with SMTP id ffacd0b85a97d-3d0d6e6642emr1463686f8f.38.1756472987991;
        Fri, 29 Aug 2025 06:09:47 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3d12c90a01bsm906716f8f.31.2025.08.29.06.09.45
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 06:09:47 -0700 (PDT)
Message-ID: <4f6e66a1-1747-402e-8f1a-f6b7783fc2e5@redhat.com>
Date: Fri, 29 Aug 2025 15:09:45 +0200
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
 <547145e0-9b0e-40ca-8201-e94cc5d19356@redhat.com>
 <34edaa0d-0d5f-4041-9a3d-fb5b2dd584e8@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <34edaa0d-0d5f-4041-9a3d-fb5b2dd584e8@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: L_xMLw0Rn57wrzu2XEbXeZ6M4CXUM_9tX6C0phOk3Vk_1756472989
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=W77Nk43K;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

> 
> It seems a bit arbitrary, like we open-code this (at risk of making a mistake)
> in some places but not others.

[...]

>>
>> One could argue that maybe one would want a order_to_pages() helper (that
>> could use BIT() internally), but I am certainly not someone that would
>> suggest that at this point ...  :)
> 
> I mean maybe.
> 
> Anyway as I said none of this is massively important, the open-coding here is
> correct, just seems silly.

Maybe we really want a ORDER_PAGES() and PAGES_ORDER().

But I mean, we also have PHYS_PFN() PFN_PHYS() and see how many "<< 
PAGE_SIZE" etc we are using all over the place.

> 
>>
>>>
>>>> +
>>>>    /*
>>>>     * compound_nr() returns the number of pages in this potentially compound
>>>>     * page.  compound_nr() can be called on a tail page, and is defined to
>>>> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
>>>> index baead29b3e67b..426bc404b80cc 100644
>>>> --- a/mm/page_alloc.c
>>>> +++ b/mm/page_alloc.c
>>>> @@ -6833,6 +6833,7 @@ static int __alloc_contig_verify_gfp_mask(gfp_t gfp_mask, gfp_t *gfp_cc_mask)
>>>>    int alloc_contig_range_noprof(unsigned long start, unsigned long end,
>>>>    			      acr_flags_t alloc_flags, gfp_t gfp_mask)
> 
> Funny btw th
> 
>>>>    {
>>>> +	const unsigned int order = ilog2(end - start);
>>>>    	unsigned long outer_start, outer_end;
>>>>    	int ret = 0;
>>>>
>>>> @@ -6850,6 +6851,9 @@ int alloc_contig_range_noprof(unsigned long start, unsigned long end,
>>>>    					    PB_ISOLATE_MODE_CMA_ALLOC :
>>>>    					    PB_ISOLATE_MODE_OTHER;
>>>>
>>>> +	if (WARN_ON_ONCE((gfp_mask & __GFP_COMP) && order > MAX_FOLIO_ORDER))
>>>> +		return -EINVAL;
>>>
>>> Possibly not worth it for a one off, but be nice to have this as a helper function, like:
>>>
>>> static bool is_valid_order(gfp_t gfp_mask, unsigned int order)
>>> {
>>> 	return !(gfp_mask & __GFP_COMP) || order <= MAX_FOLIO_ORDER;
>>> }
>>>
>>> Then makes this:
>>>
>>> 	if (WARN_ON_ONCE(!is_valid_order(gfp_mask, order)))
>>> 		return -EINVAL;
>>>
>>> Kinda self-documenting!
>>
>> I don't like it -- especially forwarding __GFP_COMP.
>>
>> is_valid_folio_order() to wrap the order check? Also not sure.
> 
> OK, it's not a big deal.
> 
> Can we have a comment explaining this though? As people might be confused
> as to why we check this here and not elsewhere.

I can add a comment.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4f6e66a1-1747-402e-8f1a-f6b7783fc2e5%40redhat.com.
