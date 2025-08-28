Return-Path: <kasan-dev+bncBC32535MUICBBWNBYDCQMGQE4XIBUVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 91CA0B396A4
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 10:18:34 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-74381e1e0casf827170a34.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 01:18:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756369113; cv=pass;
        d=google.com; s=arc-20240605;
        b=XJ2K2XWPXIM4y60voZ9j3otIkvqaf02zE18ClCPtq0jZKFr1Os0rxsWhVZPoZnJdfq
         VLYpVqE/P3VQWIWHqGNfyv/0lqXcBjtG0bTuhEi/9TnYUEVvq/hAX8Q8X/gmNSbgyFFq
         gGE4c5uHf1zIfVC2+u5loRaU+haZ2dX+0hvmX8LNMNkBMtGGYg8wGZqcIhZ1jQhtW1Jp
         6t+gxojSVgS4ZGz3xi8esX9kxIFzrbWkglrQa6/j4Qkg1bUmi5R2Nt5Eem4BSsQ5gyni
         Z0QIEwV62FhotIK55ewP3kTDpV8N2bBSm/Y96W0sVynxsmsDo+64ZFWTXAHQ4+mw1tQk
         KMhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=aPPlu6EfW/YryDpaBpEHKA3wJ5JXpKv80wNHgkP6XxY=;
        fh=Zm5qNUMszaz+s5Ckf7i5KtrPNYYggyI1R0cQcBddIl8=;
        b=ib3YrK50UH6qLqCoQYakfneaSGt7qlRZNQw24UtTlS7ws9AlvVOiKBh1FsSj6i2iTo
         3GEfdMwPkU8S7KOgNMW1OVAxmUNnMvehj3iW3X67XdaxIi7mGpjVp/BeW593DAzLJtjH
         2izB1nTaVfW2Av6bsspG2lpY1tuNS0z/dlMf/oehBzW6gvjA/Szkq+QiX+ogtKG/fMs/
         NTrxTYJ73IiVMm0Qxv4+e7a3Y5/zs1BYGFdqZf1RSQMamfX9ykGGP5+njH85jwBaXijy
         D9ajef4LJhxlffOf9CPfZHbf/Bqm1WsMIhSEoqhV81jzCivgmgPTTa5RYx7XE/CGNM6t
         94hA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BJjycywl;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756369113; x=1756973913; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=aPPlu6EfW/YryDpaBpEHKA3wJ5JXpKv80wNHgkP6XxY=;
        b=WFfUP2e13JsXuEN6oCvXeRsbGe8nX3rDgqqCmxpAgtpZivGUGrnUhAljVQ5oAtJQmW
         QaOo8nDofeQFv2Ah9brBmS6Ytb65rcqPbq+o0VP58Uyi7bC9MHoJ179YbdTKsT9Ye8uh
         k3diJVein6bEm5zX9Sskfb0XVMTWgmbMXyHAiEOqapBQMp9clg9ATvbzk0UWUJ0woWTo
         SeyfhkL3TmAIFYmyeBSnKvmwPVeRsDQeZoyDO+xv55XXWwhG5mODYn9ZUFnEg9bgLLKn
         M495U2DR+2MtSqZkKY/lwoWxfK900RNCfWc7qgpowZ0787wFmWeqvoVZ32lPj7qAjyVs
         Q0EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756369113; x=1756973913;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=aPPlu6EfW/YryDpaBpEHKA3wJ5JXpKv80wNHgkP6XxY=;
        b=DytfQM75MUuNL4htOl58acfyf1K7C/entHtD9Io0EhVs3+hAuCjfZDQ/+keKOfcMXC
         5Azc7AFgIOLZ/7LXGZfHUwWYCMaCCFZleDghotRLlLJT1n0We1WCUL1zusaqXhVChJ+P
         D3PhbN4+fiu6wiewvb2Tacq5OBHeKTEQLrWInPYqHjDEPv1QPEQx3kLPnAP5YiC0Rc7Y
         Qi3dSGZosGqU7CMIrHcSFHHYOiek+XAXT29G7z3cCGCz8fYyWBELISPeRuu/TJBgMeqk
         7/sSoKvkgK45PcRH2PAX1BJ6t35XFOChi4tKEhcHyGXxWqemlNnq5212txraCo0vfL7n
         b6zg==
X-Forwarded-Encrypted: i=2; AJvYcCWTVwv35UHKaP68SouJO9ABiAwyHNYEu6aZBLKGqjd85StxoM6B+bkhantLk4TI8hkeeMMafQ==@lfdr.de
X-Gm-Message-State: AOJu0YyqUVc6p/i9+CczNUrEjf3s62hN/eDhzQE+v0oOOPrGd8YjIyP5
	XgqdQAPNj4nue2U4sa88POuaWB2nDfcZ8FPLWLFC2hKocUY7FPuUgsUy
X-Google-Smtp-Source: AGHT+IH/cb98TVF+sn+B1tXi+FQ5Lxl4UiOst5aw0H8R+m7vqHbXoA0XhWHvSkT5TsLqvjeUfChqLw==
X-Received: by 2002:a05:6830:2783:b0:745:47d1:31ed with SMTP id 46e09a7af769-74547d13a1fmr1081426a34.2.1756369113305;
        Thu, 28 Aug 2025 01:18:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdk6CRRA8syly0bce/Zk509StDSfZgXuOExLVVz58nbCA==
Received: by 2002:a05:6820:3093:b0:61e:d18:ba6b with SMTP id
 006d021491bc7-61e127c7a44ls256399eaf.2.-pod-prod-07-us; Thu, 28 Aug 2025
 01:18:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXW7YPuA1a4hbl4Kg5rLGzgmC/+cIOIXb8IhxSp+/rtvLQ87I17gx2zkg2YghCpZheK5lhCPAd6FEA=@googlegroups.com
X-Received: by 2002:a05:6830:2114:b0:72b:9fb2:2abd with SMTP id 46e09a7af769-74500b326e1mr7388822a34.20.1756369112282;
        Thu, 28 Aug 2025 01:18:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756369112; cv=none;
        d=google.com; s=arc-20240605;
        b=hWWjHUYz8JJYlfzszxqktiT78WRNNktJBwSmty5d5QAe+NmDvENegnPl8922cqCFK2
         fxvxwBJlw90ZTIUmKpIjfrh2ECGt2AXR/uUqyblb8KJunVqV4xnfARQvBZplGxPwgHDx
         B1ZviXwUHANciPkxiHilPLtEUp0LWquCYEst8elqeIyleEDeLX+aOo8788lnLlAbOhRh
         NstT1mg1DoOzvSoYHeU60JsamSkTybOUHvCbesN+9WtY+AVULlJZc4vha371hSTQzBgW
         YshHJFlzyEi70zxM20n7mVedebZD7gyu7w9Cgdroqto5t0XsN4zKiyGmZu/iTGcjp0TH
         R0gQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=dQiayb6TF/jkGdLdQdDfmQoC9oGAqREv3FJiJ/1tw1w=;
        fh=UNzgZqGzrZxo/pU38XaMaZWksUX7fSVe+mv7DU//dE0=;
        b=aZZsK8j50zzLyrYIN3tVXNJyAiaCcTwPaiEIOmDBdSVNb6B9lOEivRIKwvClIIfKqv
         R4lpPNVoWqk5W3oOjaVmJnOaglUkMsq6yvBd5K0zaYGZM6YLA6Y1ZtRxZftaceEKEDlz
         5Xtl5UWiTLXHGtrzYt/3z1SQobcPWaP4wVHo9JvoYCZXoqXJBF3kD/uPrgYgKwXXvDC1
         AhXLXNO6Le+s8TIflQG8/j8lOVsP5hJ0UNi8bSJfiW0XfE/w2COFJ59g/ok1XRYBigYL
         yale2muK5lW8F5GGJHK3rECfdOxcAxqm5irh+iZKnonjFF7aKzN7Ngp+pKjDhxHuSl8f
         Tl3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BJjycywl;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7450e46e387si245619a34.5.2025.08.28.01.18.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 01:18:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-21-DPzI2_ZFOm-SMSDEKt41sw-1; Thu, 28 Aug 2025 04:18:28 -0400
X-MC-Unique: DPzI2_ZFOm-SMSDEKt41sw-1
X-Mimecast-MFC-AGG-ID: DPzI2_ZFOm-SMSDEKt41sw_1756369107
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45a1b10418aso3308225e9.3
        for <kasan-dev@googlegroups.com>; Thu, 28 Aug 2025 01:18:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXwBLunYsDft0ETjb/uM+0I1l8+ZPORx4iRo7tu4LZDzPZl0Cep+yGoCHYbMmBm/sxx3dlXLw+l0SE=@googlegroups.com
X-Gm-Gg: ASbGncukRCvnxU/SPvS9fa4PLIlsb2GWiOMa2baZXBDsIx/7gBeAhn0Gy1Cq0Eo0D8O
	POr9HQ0/NP09dewhUDmwP3OcIo0G0yHxFny+Z6NCph3baXBJMKEDVU+yac5iVHy5GrX9WHz2la8
	bvd256QaubZtR7U9ZCkLtAEsUblkL62wRejQX6OGrxk/spEyg48Hq/x5FcegdhAzNiVeIs4QE4Q
	x94lAYj1Fz4aBUjq/X5Ha9rWlmrawEiENIlNuhUsUxyc2DJosPBP3ToPCLlJFM6z6UhZjlH3JlJ
	p29T4cPVhgzJQYf7sgdBqvUwBmJQdzhRVbv1k7/YBUY/XosIO6hhthrC0uJcjzsDRcL44f0YnUe
	YkfBqLnHOZfhIh0QFKy52sXia4+v44D02daAIpZPUPrjsX3lZwoKjcd70r3KumhvhWUY=
X-Received: by 2002:a05:600c:190b:b0:45b:6743:2240 with SMTP id 5b1f17b1804b1-45b68aa25cbmr59784715e9.27.1756369107134;
        Thu, 28 Aug 2025 01:18:27 -0700 (PDT)
X-Received: by 2002:a05:600c:190b:b0:45b:6743:2240 with SMTP id 5b1f17b1804b1-45b68aa25cbmr59784365e9.27.1756369106625;
        Thu, 28 Aug 2025 01:18:26 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f28:c100:2225:10aa:f247:7b85? (p200300d82f28c100222510aaf2477b85.dip0.t-ipconnect.de. [2003:d8:2f28:c100:2225:10aa:f247:7b85])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b732671b7sm21138515e9.3.2025.08.28.01.18.24
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Aug 2025 01:18:26 -0700 (PDT)
Message-ID: <6880f125-803d-4eea-88ac-b67fdcc5995d@redhat.com>
Date: Thu, 28 Aug 2025 10:18:23 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 13/36] mm/hugetlb: cleanup
 hugetlb_folio_init_tail_vmemmap()
To: Mike Rapoport <rppt@kernel.org>
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
 Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
 Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
 Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-14-david@redhat.com> <aLADXP89cp6hAq0q@kernel.org>
 <377449bd-3c06-4a09-8647-e41354e64b30@redhat.com>
 <aLAN7xS4WQsN6Hpm@kernel.org>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <aLAN7xS4WQsN6Hpm@kernel.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: W2GP9T4ZYAbEsRn6MjctCUVHLi9m3c2XfP_2npF8CkM_1756369107
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=BJjycywl;
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

On 28.08.25 10:06, Mike Rapoport wrote:
> On Thu, Aug 28, 2025 at 09:44:27AM +0200, David Hildenbrand wrote:
>> On 28.08.25 09:21, Mike Rapoport wrote:
>>> On Thu, Aug 28, 2025 at 12:01:17AM +0200, David Hildenbrand wrote:
>>>> We can now safely iterate over all pages in a folio, so no need for the
>>>> pfn_to_page().
>>>>
>>>> Also, as we already force the refcount in __init_single_page() to 1,
>>>> we can just set the refcount to 0 and avoid page_ref_freeze() +
>>>> VM_BUG_ON. Likely, in the future, we would just want to tell
>>>> __init_single_page() to which value to initialize the refcount.
>>>>
>>>> Further, adjust the comments to highlight that we are dealing with an
>>>> open-coded prep_compound_page() variant, and add another comment explaining
>>>> why we really need the __init_single_page() only on the tail pages.
>>>>
>>>> Note that the current code was likely problematic, but we never ran into
>>>> it: prep_compound_tail() would have been called with an offset that might
>>>> exceed a memory section, and prep_compound_tail() would have simply
>>>> added that offset to the page pointer -- which would not have done the
>>>> right thing on sparsemem without vmemmap.
>>>>
>>>> Signed-off-by: David Hildenbrand <david@redhat.com>
>>>> ---
>>>>    mm/hugetlb.c | 20 ++++++++++++--------
>>>>    1 file changed, 12 insertions(+), 8 deletions(-)
>>>>
>>>> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
>>>> index 4a97e4f14c0dc..1f42186a85ea4 100644
>>>> --- a/mm/hugetlb.c
>>>> +++ b/mm/hugetlb.c
>>>> @@ -3237,17 +3237,18 @@ static void __init hugetlb_folio_init_tail_vmemmap(struct folio *folio,
>>>>    {
>>>>    	enum zone_type zone = zone_idx(folio_zone(folio));
>>>>    	int nid = folio_nid(folio);
>>>> +	struct page *page = folio_page(folio, start_page_number);
>>>>    	unsigned long head_pfn = folio_pfn(folio);
>>>>    	unsigned long pfn, end_pfn = head_pfn + end_page_number;
>>>> -	int ret;
>>>> -
>>>> -	for (pfn = head_pfn + start_page_number; pfn < end_pfn; pfn++) {
>>>> -		struct page *page = pfn_to_page(pfn);
>>>> +	/*
>>>> +	 * We mark all tail pages with memblock_reserved_mark_noinit(),
>>>> +	 * so these pages are completely uninitialized.
>>>
>>>                                ^ not? ;-)
>>
>> Can you elaborate?
> 
> Oh, sorry, I misread "uninitialized".
> Still, I'd phrase it as
> 
> 	/*
> 	 * We marked all tail pages with memblock_reserved_mark_noinit(),
> 	 * so we must initialize them here.
> 	 */

I prefer what I currently have, but thanks for the review.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6880f125-803d-4eea-88ac-b67fdcc5995d%40redhat.com.
