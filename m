Return-Path: <kasan-dev+bncBDR5N7WPRQGRBAES5PCQMGQENMN3RVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 552A1B45642
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 13:26:58 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4b4980c96c3sf73896211cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 04:26:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757071617; cv=pass;
        d=google.com; s=arc-20240605;
        b=EaHYBuhc1tBfn1yvM+CW1+cxG2mw2I0trlpLTNBPEvk+pEPp3IeThUhzXxbTRZpHvW
         GhJRDxRxuL1qEQ+uxrrYMVyJ3yexQLimk8/Q3Eg1zbwLd5UPCSJCilaHCRRgpYxUn4ip
         9mWPReurrdoWER66DOPGgV0W2tfkLNZk1fzSGhfwpTkM+JpB9ZFSEZI5oL1hTrOYcuMP
         FYDPeE2p8J4EoWmgvLJgKdx1PX2z4Gdn7ni9aLcQaGR91ywGN2YGTLShBxjztArMoEdK
         7XoQAI1Gt+IXomThdGD6+ndEBUDTtlL6qpPlHb8qKw4wVJOikgTw2+tmNEVOItTr0fZa
         0Fiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=KQivsfFscUEvdajr0Qq/AHXonuEAx9Ggc2mfKIGLoEM=;
        fh=UltRoqQ1CwkPQPDkZoXdgoHdLzQY3T+kwWECj/U0hjs=;
        b=Gw0h0M4ffZHDq8Cr5D0EktGeV4/mH84nCIRZNzKxV/YgXw52kC+7o1TPxe9mmauCsA
         sxadzWdvugDd9Bpv0BmZrmD6/5W6rEPpvxLUkZgtygRbkw7ieBRZZsDmhaB2MialVVsI
         6gJuUQ0JjxOP9i8RoxI2NeusvFL3JnkBoXBKDcHjZWRAYKWOZnFHC3N5K7DISvkXX93m
         X76hXIWtS0qhPB0JgKFWftFoToRSJycp06GTesWUCnrgJk1w5TzC8dJSSG5l3RSgXAqU
         +K0uYCor53SlybBcwj8Wp8PP0V8idETdyZjgYWI2pI8p47Ime8qcRSNP4fLSWvhdLK5Q
         37qQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20230601.gappssmtp.com header.s=20230601 header.b=teRod9qH;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=axboe@kernel.dk;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757071617; x=1757676417; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=KQivsfFscUEvdajr0Qq/AHXonuEAx9Ggc2mfKIGLoEM=;
        b=vf+S7CdS8CSumipIo/uQKW0xX7Phr9qYxYStsf13xJl6gI4z68v4sr9Dna6FfN2L3F
         9JhiD8T8LyGT7OkJKDnRj/0ewwWX9RJpMDZU7YGBORPW+ftXesXEhkRFFlhZM+UKORQs
         4BHQr+qxAv7OnlUkh2NvarCzoDz6nCUPXUFtcuND5y3ACZ6ehMFPUsTHhEVGP/0lgI2K
         0akL9uFB9Pm+D0z0ZpYoGWfuQhrfnOOyAsRJhBN8pgHkNynyIg70O7PY/SeUKXsFq/EE
         SaIVUeFCXKzkU1VTCVGMdomGQc39yablCwuaDR3xNL0hvWg1S6RtmEnYu0+3Roap4rE0
         /qog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757071617; x=1757676417;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KQivsfFscUEvdajr0Qq/AHXonuEAx9Ggc2mfKIGLoEM=;
        b=i7mWze4uV6MI7bwTUk+OQBjrTGFCeA1KFyc0nxlSdDjFl3MYuHXuMhf7XCZkCKqEre
         +AkvC/WpNZTJ20Va7WjYzhXXeKP3LE1oXmNdnjkSbzwVWKCdwRBZzI/26+pcEcAKTJM6
         LYBAkhGLP0M+QbwiWabOKW2l61PD+If4ndq9Tacm6m4m12aGb2Owuho7z+lPYiwmylIv
         wmsA16bxeIcr36QCgCLWGDtBmYW1hJcEz3xLX9hmmgJOi/MS75aMOxUhWB9n/n9F2Wqx
         IJcypSIM/y+a3jI9h14EjMQ1jUT1IUbFxs76uKBwZ/7basm6HGHDhiz/QU1kjSPF2ld0
         jC8g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV+NbhD4xR8cdnzzP/WXEyJDb+jesxuC81yn2Qs6cJhXxiI2Dz9L+zielfG2MdT3GYozFeO2A==@lfdr.de
X-Gm-Message-State: AOJu0YxM5Fh7N3hZKUwGTUXkN1O6Jh0PldvdKuzQv1DD3YCHs5a+C9ws
	VfEDB3vCnnKcqpVZCSgHkYANtZIfQAoTFtgye/zjxHAXAEgaR+cU8Wrk
X-Google-Smtp-Source: AGHT+IGIGhqLxR5eMnq7lc1C9W5rShmw4+pX5dvIYd3kJ2DjFZEBbv2QOBm9tIMQFcLCN00DAmMIAA==
X-Received: by 2002:ac8:5dd2:0:b0:4b4:8f2c:ba3f with SMTP id d75a77b69052e-4b48f2cbd9amr132003951cf.76.1757071616840;
        Fri, 05 Sep 2025 04:26:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdTjVsM16hKdXaYx4oChxuN9x6XBybl0XrgbgCgwTu4rg==
Received: by 2002:a05:622a:118a:b0:4b4:9d38:b941 with SMTP id
 d75a77b69052e-4b5ea7e340dls11756291cf.0.-pod-prod-04-us; Fri, 05 Sep 2025
 04:26:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXG0Zkky3wgNzn6l2nzWztcOCw69ThPkTYx3QVFlLUaRbJiKsvqWZp0YADtTFD+LISavdFKuoJChJE=@googlegroups.com
X-Received: by 2002:a05:622a:480a:b0:4b5:e8e6:f3b6 with SMTP id d75a77b69052e-4b5e8e6f729mr31754331cf.11.1757071616139;
        Fri, 05 Sep 2025 04:26:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757071616; cv=none;
        d=google.com; s=arc-20240605;
        b=Jy+albcR1RTVxSMOzysCOvI4SzdtTBKhZBU9gcVd8rFHyBPT2yiQF2oLTdx9LK9NgA
         HjAS784MaaPKwUv51++1KhJU3iCaz+hbXdrm0MhFSbyqJZeBvxDnAAAnc4A1m0uV0Y8J
         U0ytU+0DCNq9pSz19/14GtFBthWCraPoxz83a79JmTG6AA4sk2giV6jun3JzycMCj6wi
         RAVMGw+92SIrXR9naOewiHtcH3343FPd5K5onCBM4RNn2kOlviHSOlRbEysHEmmVQ7mc
         wz+nYP750LXL4n7GER0Sq/G0b/hCwiLE5A/VsmC6DVccUrnEufqF4AIry9806JXUSwA0
         NgYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=yNzF16PbnrymzXw8XwNj1X2cjJHo1hQQnEraT/RlzJM=;
        fh=63IYUuHZxWqeUuOxOZ9SKbja+DeLERv78ycuuONjE/c=;
        b=is30Sv1nJu5r5Yjf2rkfZ/j0KUvBr62MFIwKdv25xdCotslLRF5DQ8SV3E2mmCtrui
         i9x/r1pUj2FvMchBnPJ1tzi6mQTn6DDjQI6SAcnf78B6jIW9/nz891eHT/uKhR/1v6gX
         laLqTn63BXkFkHztu8pVGQK71a+XkCShx9ZdhXPrYRGnRfQ9S5tVazSD5Gl4cvAPI0CH
         PLMzK31iOP5tcutQ6OmaHd5d4aUT2DufOI20Pwpi01PZXI0s1MVZaVLTZto5HNMfNl7p
         ZyBpEsg0WHaPXlgYW+paKI/MI3M1UVlNpefe8Ix/MFKikJoMdp6gOMnL8NVEYDx5+SLn
         ROoA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20230601.gappssmtp.com header.s=20230601 header.b=teRod9qH;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=axboe@kernel.dk;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b5f36f48b9si112291cf.2.2025.09.05.04.26.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 04:26:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id 3f1490d57ef6-e9e87d98ce1so207659276.1
        for <kasan-dev@googlegroups.com>; Fri, 05 Sep 2025 04:26:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV4BYBBFKOF7BXAtY/oSJHVs2ZR9Gu9tgV2dqEF1uhYXHe64uMmmk650/HFD7CT3yHeK7VhDdr70gM=@googlegroups.com
X-Gm-Gg: ASbGncvBO3wlHyDByozTpPA8VMFxRx9jkPwkbDU5ND4fRhaYvelP/Ezjnkao+L901UG
	rBRTF7nGIgGIWFS348ZrcsOTT5hkIgp7Mfp1wKnGJbNK14NnNivVtfFVZDAMvxmCiowrq8+IBw2
	bLhNiD0Cug6HmJBbxyaqEji6dgou9DYEwmb5I/hEMqGPcb3EMl23R4t78f6ZMerBTrg8QA0SREK
	6xEOGLtvHwTd4/bYAp/sXSXkLcX4JlMzRymjSTKlNumOzYr/hBQAN9lr03GehOm2X6zjqpzLZyP
	urer09oendaw+jiiW/JdHvG0QHitKtYKEbXTRGvWc8DIMwLiND8ejSJ+G12JVms828ityQuTxif
	uTN4H5/1QJx3VDMhlBg==
X-Received: by 2002:a05:6902:18ce:b0:e96:fac0:60bc with SMTP id 3f1490d57ef6-e98a58455f2mr22114649276.41.1757071615282;
        Fri, 05 Sep 2025 04:26:55 -0700 (PDT)
Received: from [10.0.3.24] ([50.227.229.138])
        by smtp.gmail.com with ESMTPSA id 3f1490d57ef6-e9bbdf504e0sm3031724276.11.2025.09.05.04.26.53
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 04:26:54 -0700 (PDT)
Message-ID: <1513d5fd-14ef-4cd0-a9a5-1016e9be6540@kernel.dk>
Date: Fri, 5 Sep 2025 05:26:53 -0600
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 19/37] mm/gup: remove record_subpages()
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Johannes Weiner <hannes@cmpxchg.org>,
 John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
 kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
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
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org,
 Zi Yan <ziy@nvidia.com>
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-20-david@redhat.com>
 <5090355d-546a-4d06-99e1-064354d156b5@redhat.com>
Content-Language: en-US
From: Jens Axboe <axboe@kernel.dk>
In-Reply-To: <5090355d-546a-4d06-99e1-064354d156b5@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: axboe@kernel.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel-dk.20230601.gappssmtp.com header.s=20230601
 header.b=teRod9qH;       spf=pass (google.com: domain of axboe@kernel.dk
 designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=axboe@kernel.dk;
       dara=pass header.i=@googlegroups.com
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

On 9/5/25 12:41 AM, David Hildenbrand wrote:
> On 01.09.25 17:03, David Hildenbrand wrote:
>> We can just cleanup the code by calculating the #refs earlier,
>> so we can just inline what remains of record_subpages().
>>
>> Calculate the number of references/pages ahead of times, and record them
>> only once all our tests passed.
>>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
>> ---
>>   mm/gup.c | 25 ++++++++-----------------
>>   1 file changed, 8 insertions(+), 17 deletions(-)
>>
>> diff --git a/mm/gup.c b/mm/gup.c
>> index c10cd969c1a3b..f0f4d1a68e094 100644
>> --- a/mm/gup.c
>> +++ b/mm/gup.c
>> @@ -484,19 +484,6 @@ static inline void mm_set_has_pinned_flag(struct mm_struct *mm)
>>   #ifdef CONFIG_MMU
>>     #ifdef CONFIG_HAVE_GUP_FAST
>> -static int record_subpages(struct page *page, unsigned long sz,
>> -               unsigned long addr, unsigned long end,
>> -               struct page **pages)
>> -{
>> -    int nr;
>> -
>> -    page += (addr & (sz - 1)) >> PAGE_SHIFT;
>> -    for (nr = 0; addr != end; nr++, addr += PAGE_SIZE)
>> -        pages[nr] = page++;
>> -
>> -    return nr;
>> -}
>> -
>>   /**
>>    * try_grab_folio_fast() - Attempt to get or pin a folio in fast path.
>>    * @page:  pointer to page to be grabbed
>> @@ -2967,8 +2954,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
>>       if (pmd_special(orig))
>>           return 0;
>>   -    page = pmd_page(orig);
>> -    refs = record_subpages(page, PMD_SIZE, addr, end, pages + *nr);
>> +    refs = (end - addr) >> PAGE_SHIFT;
>> +    page = pmd_page(orig) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
>>         folio = try_grab_folio_fast(page, refs, flags);
>>       if (!folio)
>> @@ -2989,6 +2976,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
>>       }
>>         *nr += refs;
>> +    for (; refs; refs--)
>> +        *(pages++) = page++;
>>       folio_set_referenced(folio);
>>       return 1;
>>   }
>> @@ -3007,8 +2996,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
>>       if (pud_special(orig))
>>           return 0;
>>   -    page = pud_page(orig);
>> -    refs = record_subpages(page, PUD_SIZE, addr, end, pages + *nr);
>> +    refs = (end - addr) >> PAGE_SHIFT;
>> +    page = pud_page(orig) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
>>         folio = try_grab_folio_fast(page, refs, flags);
>>       if (!folio)
>> @@ -3030,6 +3019,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
>>       }
>>         *nr += refs;
>> +    for (; refs; refs--)
>> +        *(pages++) = page++;
>>       folio_set_referenced(folio);
>>       return 1;
>>   }
> 
> Okay, this code is nasty. We should rework this code to just return the nr and receive a the proper
> pages pointer, getting rid of the "*nr" parameter.
> 
> For the time being, the following should do the trick:
> 
> commit bfd07c995814354f6b66c5b6a72e96a7aa9fb73b (HEAD -> nth_page)
> Author: David Hildenbrand <david@redhat.com>
> Date:   Fri Sep 5 08:38:43 2025 +0200
> 
>     fixup: mm/gup: remove record_subpages()
>         pages is not adjusted by the caller, but idnexed by existing *nr.
>         Signed-off-by: David Hildenbrand <david@redhat.com>
> 
> diff --git a/mm/gup.c b/mm/gup.c
> index 010fe56f6e132..22420f2069ee1 100644
> --- a/mm/gup.c
> +++ b/mm/gup.c
> @@ -2981,6 +2981,7 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
>                 return 0;
>         }
>  
> +       pages += *nr;
>         *nr += refs;
>         for (; refs; refs--)
>                 *(pages++) = page++;
> @@ -3024,6 +3025,7 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
>                 return 0;
>         }
>  
> +       pages += *nr;
>         *nr += refs;
>         for (; refs; refs--)
>                 *(pages++) = page++;
> 

Tested as fixing the issue for me, thanks.

-- 
Jens Axboe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1513d5fd-14ef-4cd0-a9a5-1016e9be6540%40kernel.dk.
