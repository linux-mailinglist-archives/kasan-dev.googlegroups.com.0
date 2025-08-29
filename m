Return-Path: <kasan-dev+bncBC32535MUICBBPG5Y3CQMGQE24ONCPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id BC8ECB3BCB8
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 15:44:30 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-70dd6d25992sf44479736d6.2
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 06:44:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756475069; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jm+9srurVLHrPmriX/I1AEFoCrw72DKp+B1PWaAiWTcgE1fy4pFkVP8eHFppqfTZwp
         yAX/iyg4kMyCGeJeMf5/U+eqzAgWPjSa+zGP+UeigV6DFUxrgCywDQJ8QMKxe+e77bdl
         5r2zSCY30QsCrgUgmD1vEINRQ2RMUWfqnKuUqL+zbNJT2lw6gS6pgnuFPFYCbgRyyFJw
         bQIwkNBOsr4BvWzCcLqcMIQLeQZ6OZPnu+PaBsKlu4H83rJX/I3LXKpAgZsmb5nPNHQf
         +qoQOl6hsN+0NvqXs/pP8yN1aQH29hlgX4I4YGsSXWxU1TZPpfX4QoZ0K9PjwKUp6iU3
         sB8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=mbdCQ+JSLsbJ1+a5no69FG1aldeztak7eIDs9jAxUz8=;
        fh=gcXvVIScshyG2Rgbg1E0DHF+HCMIra5ZoWNMkdm9rdE=;
        b=UtrzlZs+Z4SiTuuA34adt8DrzwTDiddc8H4BTvMME0QURMy1sSKR0VHdA0wmbCFcCT
         40jpN4ocjjsOrU1D6J1TtZ+x2y5pb+msPLH+LZpuq5z6ji36Sc8XJ93chzWZUOF39H0w
         vUvDJ9NVR9DL8JeXdHwPZTu78GWE3KvEUnl3RGhkDkxpQoWbKzuNLf8pcjHfeDZMszs9
         OY8ru/twIGQTJh51/MT+k2ozwCjH1IiEr7a70dcK2tOqeo21qlX07roGRCzAa4C9ypQC
         tUzSq0aMNloxkT9mcQqWadIiD0wz+xux5RjcSsow3GdmmvegTbaIo4F5F4yy70h2h/cp
         kNTA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BcUQemeY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756475069; x=1757079869; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=mbdCQ+JSLsbJ1+a5no69FG1aldeztak7eIDs9jAxUz8=;
        b=M7iSZZb6/MAtD83T1RqnInAXMXFSCQDDQjO1TwkPh3wAMnaFHl0k5k7gKBg6842cxk
         B46b1fzSBaNvMfxYXzs8RX2gFh0KfOGvU+8A/ynZKLmPtUH34ZifrCjnI5ff9B5uKOmX
         jYexsJFPJHav5pE49TIshciqkUEDULZvjbHECKCpmX1yTvGFqO0eUAl/adhg3o/pn/Nm
         K1BEH2GDo98shDjUS15QzkuG+XMi7ebaTt+80pqLUwYyzrWUd8jU4st1VM+kmDLjrtSl
         UPQR2N563sasSMACL98Dt4gsa2MVEnGPumnqNMRuWdY7doF+sOEHwHBvxlCPZ90OB0Jd
         mmwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756475069; x=1757079869;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=mbdCQ+JSLsbJ1+a5no69FG1aldeztak7eIDs9jAxUz8=;
        b=lnX6ydzZIZKUAnSCPNuA4qh9gN3AqAsL1KA8g9h7bgEM6yAp/s56D/0VZIRCYXUjY3
         D+10MedH55TvjoifHso4mn6w2dpSCqVH4gYnzM7BNbcaAnTMSd/ATthaBV3tb6xINJ76
         clIDnevyuX/3qHDj0Mtv+x3fk37nU3oKEKTVPm5nlYH4LZJKoHG4aErxq5aYWVuv0vGE
         VEy6jN7KAjgsCBUAWH/KiK9vM7TiVDEctedNLtrW0JP8x9fMqCGidEhh23GVNcO7kftX
         /AxhspJ5WkRexnHGT1Zx6sm+644ZOFIDco+6t3F3y/633w+96XRqO3INl2oDNRRxEhml
         v4RQ==
X-Forwarded-Encrypted: i=2; AJvYcCV0Lzh/+YR0I4MfCeIHQxmSoWrZ/blgFfPfqg5TZfKIRqwzDCV+YwCuuv42zThdrETZYvHGSA==@lfdr.de
X-Gm-Message-State: AOJu0YwRmBxjwmxpqbOKvJ4OBTqS1CxXZhf4uwlFXPejE/TlZIQeUhrW
	7Q29tLSL1Q6/MEiAyCSrQsmUhSzieFmbk+TkLGIZ5B7dIv3r8OpobDxh
X-Google-Smtp-Source: AGHT+IGpC7umY7OfAOFGWtC3TXhVJQuu9X69wpaO484AuiyAWZwArXtmxRTX/pJ9wkBIihguK92UcQ==
X-Received: by 2002:a05:6214:1c4a:b0:70d:fada:5c22 with SMTP id 6a1803df08f44-70dfadaa362mr53676836d6.33.1756475069459;
        Fri, 29 Aug 2025 06:44:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeej6Ot7d/6SHD6qwdh1pz7vtZurLmoLRcpsVIUD9uvpA==
Received: by 2002:a05:6214:5298:b0:70d:9e42:dc8f with SMTP id
 6a1803df08f44-70df00adb76ls29225166d6.0.-pod-prod-07-us; Fri, 29 Aug 2025
 06:44:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW2aNpVVt/abw7HB8R4/zHApd0zPAaIoQNLrfMlniW5GfE/yZklTnRAJjFdQUNr5lqYYe88PPZdhqc=@googlegroups.com
X-Received: by 2002:ad4:5bec:0:b0:70e:86:af38 with SMTP id 6a1803df08f44-70e0086b374mr39513646d6.34.1756475067841;
        Fri, 29 Aug 2025 06:44:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756475067; cv=none;
        d=google.com; s=arc-20240605;
        b=FSFbREnNxUpDc+YZPcdX18wQCWIMzlz1//sonQJbq+B9kj4721bN3KiYF04FG+x3/x
         8vZ9CracYQyylTNNO21dwlFtpjggNaZLB6CAR1oRLGzmW3b3xF9OAw8UYC+GeryQxEXZ
         Kovn5oSsKqZmcdsJFpcQSDU/6K1+CTolPQKlCxB3lSrC+RO/ZutO3Ih1lbF3Gw6IFy6x
         nFe51jg0soPpHLyniAt9ZX+PWir9jihvgE+bMR7YVlEvPOMEkEMPduT7HSiJnarT0loq
         ZFWx7wlZBuqoGIZMciYwYk5BIBilmAue5csjxbl7VaxVnqDusd2va7HDZgY5rIeFX/E1
         Vdmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=qjuXMBMcmzq+emhjc+4nz3INVtnsR/3o1W/HmfSMpGo=;
        fh=9zJ4+QXiP8UHYkQcrPY+LalbRcDLREYCGEYHR50/OaM=;
        b=L+GjKWO/qvptVIuZXSgM8MbVnD2umNxV7q4oexW0e4O/d2j7gOCiEjagW7OnCB6Ld4
         XCCpn8lDNR6KXp/PCNY7CGbiZkHHqa5o5SdfwsuxF/ojX6ygEIxMgd13GPdggXA+BNGt
         54tKRZKIIKwCgGpkpBtrNJeTcpHuExAi663hm0uupR8xARRw3eylkCoR1yRPgR6pvpXd
         zl+mK2BFqy8VENvCK3g3AouoZvEzAQSEokqW3nzyEAgMHw1mqFY8lapIGRUYvjbgcu/F
         dQE9/PtomNJkpVHDmKyHjj/EBnNesgB/NHdUexON0WyG7IVipVtRENmeX11RIc4qAoc2
         ZF2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BcUQemeY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70e624c1dbcsi801226d6.7.2025.08.29.06.44.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 06:44:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-5-59ofWj4PNneBJ_s1lDUa_A-1; Fri, 29 Aug 2025 09:44:26 -0400
X-MC-Unique: 59ofWj4PNneBJ_s1lDUa_A-1
X-Mimecast-MFC-AGG-ID: 59ofWj4PNneBJ_s1lDUa_A_1756475065
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-3c79f0a5ff1so948670f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 06:44:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV7gQSQBEptRCAUh4zqZ4vwM3ON+q1QuP/mCI88ANcniqttcp6Nwxlo+AF3RaNlx9GvNEGT2mmvu7Y=@googlegroups.com
X-Gm-Gg: ASbGncv+FFE8jJV6m1gXQAyTtxW/V7ptsxbVRJObTOCQVZPf5+cnfsrV1laVplikK+G
	tKOMDWD86dyXV9r4Ig5HB5EPz9nWnu3JJDm0l3UQGa+vPW/rgUMb4voTgPJTvV4/d/fjuvV7AYW
	SXxd4A1IwOTZQmwrFkoxUZqxIlX+dLZuHhRaXHUR5cOnt98c9vYOfyoZBnb6S1udDOxcsqO6MgJ
	cOBmKCJSXsHIjLQxjbheZRvZz6/inEZVWvmbV2NXuRps4+ojGenOjt3mvoDsIj8dsO9N8IRNuHD
	g8BqU7SPHlbHqBBewRTzso4Z8/4wDgTbgWFvcW8CNJR4Dc5/MiI2LzQWdY1XKeSth0dFZmntZk1
	rTLTKwKxPWoMlhzUWxPSa74HyagPiIYYnNbuTRPggNHIXnHBoSKTu01N73xcnpVYD
X-Received: by 2002:a05:6000:4383:b0:3b7:882c:790 with SMTP id ffacd0b85a97d-3c5dc73625cmr21478698f8f.37.1756475064835;
        Fri, 29 Aug 2025 06:44:24 -0700 (PDT)
X-Received: by 2002:a05:6000:4383:b0:3b7:882c:790 with SMTP id ffacd0b85a97d-3c5dc73625cmr21478675f8f.37.1756475064268;
        Fri, 29 Aug 2025 06:44:24 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b6f306c22sm121018675e9.13.2025.08.29.06.44.21
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 06:44:23 -0700 (PDT)
Message-ID: <e877229a-ffd8-4459-a31b-ecabde28e07f@redhat.com>
Date: Fri, 29 Aug 2025 15:44:20 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 20/36] mips: mm: convert __flush_dcache_pages() to
 __flush_dcache_folio_pages()
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: linux-kernel@vger.kernel.org,
 Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
 Alexander Potapenko <glider@google.com>,
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
 wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-21-david@redhat.com>
 <ea74f0e3-bacf-449a-b7ad-213c74599df1@lucifer.local>
 <2be7db96-2fa2-4348-837e-648124bd604f@redhat.com>
 <549a60a6-25e2-48d5-b442-49404a857014@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <549a60a6-25e2-48d5-b442-49404a857014@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: CuF5iWoE2InI5Q3MId5RsyY3Q9QWe1NzZF-O9HsCVas_1756475065
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=BcUQemeY;
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

On 29.08.25 14:51, Lorenzo Stoakes wrote:
> On Thu, Aug 28, 2025 at 10:51:46PM +0200, David Hildenbrand wrote:
>> On 28.08.25 18:57, Lorenzo Stoakes wrote:
>>> On Thu, Aug 28, 2025 at 12:01:24AM +0200, David Hildenbrand wrote:
>>>> Let's make it clearer that we are operating within a single folio by
>>>> providing both the folio and the page.
>>>>
>>>> This implies that for flush_dcache_folio() we'll now avoid one more
>>>> page->folio lookup, and that we can safely drop the "nth_page" usage.
>>>>
>>>> Cc: Thomas Bogendoerfer <tsbogend@alpha.franken.de>
>>>> Signed-off-by: David Hildenbrand <david@redhat.com>
>>>> ---
>>>>    arch/mips/include/asm/cacheflush.h | 11 +++++++----
>>>>    arch/mips/mm/cache.c               |  8 ++++----
>>>>    2 files changed, 11 insertions(+), 8 deletions(-)
>>>>
>>>> diff --git a/arch/mips/include/asm/cacheflush.h b/arch/mips/include/asm/cacheflush.h
>>>> index 5d283ef89d90d..8d79bfc687d21 100644
>>>> --- a/arch/mips/include/asm/cacheflush.h
>>>> +++ b/arch/mips/include/asm/cacheflush.h
>>>> @@ -50,13 +50,14 @@ extern void (*flush_cache_mm)(struct mm_struct *mm);
>>>>    extern void (*flush_cache_range)(struct vm_area_struct *vma,
>>>>    	unsigned long start, unsigned long end);
>>>>    extern void (*flush_cache_page)(struct vm_area_struct *vma, unsigned long page, unsigned long pfn);
>>>> -extern void __flush_dcache_pages(struct page *page, unsigned int nr);
>>>> +extern void __flush_dcache_folio_pages(struct folio *folio, struct page *page, unsigned int nr);
>>>
>>> NIT: Be good to drop the extern.
>>
>> I think I'll leave the one in, though, someone should clean up all of them
>> in one go.
> 
> This is how we always clean these up though, buuut to be fair that's in mm.
> 

Well, okay, I'll make all the other functions jealous and blame it on 
you! :P

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e877229a-ffd8-4459-a31b-ecabde28e07f%40redhat.com.
