Return-Path: <kasan-dev+bncBC32535MUICBB3MCYPCQMGQECKYGLIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id A8370B3ABF7
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 22:51:59 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-327d1fea06esf511306a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 13:51:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756414318; cv=pass;
        d=google.com; s=arc-20240605;
        b=MEklAf6LbWD3xJ5ivyQhmR85y24QfUIun+lwQUMozMgkdW37wsXKNV/QPNqTIPTS2B
         QuLK7XSj0XUiY0wsxQYAf6NhGoUTezoCJ7M6B126BdB6t7giQ37F8H2wj2Zo8diovfiH
         p/Gp7E1eOnYhe0MPAyb+cBhES2R6xEs873MW+hWypOsNBrnAQ+8MHo2sWrGtZa1aNG3g
         ddqOHm7BkM4VmPE7asV/G5RC+/6Q26bu8+ZPQIPcTwTEozPDA50QZIuFpNeFTpSUxcLK
         jhuXp0wcctzKH6tzB+OvzSg7J8vB58MBcpZyL7u+LTfa5qIwF7cSDLSjzv+S+Ww/otE8
         nT9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=+bkaNKbNpSbvODJ7XQNs87CEh/5WDV5z/CoygoqpTOI=;
        fh=OPdazmE5SsRmVvX11DHibnkEUkQLKDCHkoxUXYVfxvg=;
        b=Bq9a2N7PeQ6Sohms7I9h+C/ntvEkcvngAr/bUGDZx2uieO1EEjAQU3gACzPFXBlgDx
         5a0RX9DMeZw8an8TBrIwqzSix0hCH06/YetiiXjEh/2Pq1O7D0YebIf9K/rLukAk+K3E
         XdZgOijgJKHzmQE0TttqrzMpVfM7lAE4BGgmZHnblkjFsImizd5Qjxb6pTQqlFWM5nf8
         o8YyJnbHURbkKR/A66QeGBatCM9/uj2JJtMWKhJSlph5+TEnMnXo3hegBBJntGBMqmEo
         j7m3iXLgfwq2Jb6Y8V+WAOrhrbYLti73iTLgz5FDiTV9kQ79hvs3wQO/5OCWIbRcsLvn
         yyFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=LnDnbKmC;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756414318; x=1757019118; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=+bkaNKbNpSbvODJ7XQNs87CEh/5WDV5z/CoygoqpTOI=;
        b=WcjXPfeKFHfO4O47xVqnGwErqwyzSbYuL/e8ZuMaSoP4g6JwYgag7EcyG8u2Dum1VL
         CbBdZ3r3RvpIMhcOs4jscWAu6HOgjYHxRObNvzsVTnH0uIZNKwawLw5jVyvQXmuyju/E
         Xv+SOw2ODhvhEjf+X7Bn4eHuxjCkDmG/6Uv9cNqiIPAf+ye23WVFQAKN324BmaRc+dBR
         6TfQSpytzGrF58vVznblsxzJE8taEhyEEcovXD5jT5sQtHLJHzCmfXl+DA8o5lQ91pKq
         JutLmDDpzXC9DKKvxI5ZDZZPA2a6GBoqaBBzq6qTOpCiH7oHL/mcXvPx7WRUcB2LDSH9
         dLvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756414318; x=1757019118;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=+bkaNKbNpSbvODJ7XQNs87CEh/5WDV5z/CoygoqpTOI=;
        b=rSzUtY85IXeBayO/cU6+5dyE0NVI4FIvy5fA+Biv5YV3mwXdAZm1zQkFtNzpV0q2Hj
         ltgvHgxrwAB+FUyMiMUGYSOjNW+2VtMndAqqEyfHh5Fnh2B413KVrbZOCV4k7AGe82D7
         RE0xrFYilOVW7Pdvfs9t2Sr+t11GtZY2Clxf+os62pZtMRAJR8vHnG76knGuuAYoQdrl
         SCTTTJPokyS9gl04rejg83fNzLL969hhSgiojLv/sJZdVkCIbbR769slRKRaKFo95cu4
         cB50wARRbai88eXvKdl3bS+wa8gfyccewndzHhIh4cW6kF+Dbxz83neQDhkFx24+61Rh
         JxBA==
X-Forwarded-Encrypted: i=2; AJvYcCW2W+UUsDE70fFaGmu9CIpRG0sUGykhWn4hGNtbD/eVOWxYW8YXR7uOAlNjM1ZgKOuLPNJfjA==@lfdr.de
X-Gm-Message-State: AOJu0YyZD5DT3L5a7phw2rsClFt9OEwJrFVkplO6SV+bebIiPoYBPLQO
	1aGwAceISePsCylJH/eYhc8KEGMZOmI+9HGKAA0QNQHACqq54HeBYMlI
X-Google-Smtp-Source: AGHT+IEmfACmiT+7Apk+q7ZxxWBxHF1dFuuc7SdCxhWuNOOovJmcKS5nFnamIZwcMLxpvQDw0OYHUg==
X-Received: by 2002:a17:90b:3c05:b0:325:326a:b729 with SMTP id 98e67ed59e1d1-325326abd40mr27004199a91.28.1756414318009;
        Thu, 28 Aug 2025 13:51:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdjIVIhx7q1XAXdr74NBNZ1KkzLer2zeV1Pba/dT89/hA==
Received: by 2002:a17:90a:116:b0:325:c01f:f69 with SMTP id 98e67ed59e1d1-327aacde593ls1136268a91.1.-pod-prod-07-us;
 Thu, 28 Aug 2025 13:51:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU/tlArc23IIMuotcUT4JTM3ky4OH/xIdOHtXHFNxqT37yL+orZPTmjrlr1CFYLh4EEa5UZ2DG0x+o=@googlegroups.com
X-Received: by 2002:a17:90b:1fcc:b0:327:6823:bfe with SMTP id 98e67ed59e1d1-32768230e60mr10811282a91.8.1756414315554;
        Thu, 28 Aug 2025 13:51:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756414315; cv=none;
        d=google.com; s=arc-20240605;
        b=VN6yENRnJjAcyDXdnBMTnReQuWxJG0Hq62tFr5VJ0rluT6um0wChVCjHAd9PBIXWfS
         JmjihxeoCKvn30vZuUiT1p+7RGznu5gVyOhihHn2pT1DQQkP5BWgfMhvxbKan818aTVA
         32U6CW/4+z93nJ0HWULu5JdXNFPeuCyT/wPajdwDoC6ZAcEG/XmoA/wXQ+FBKAsXgCxi
         VVQwboZhlQaoFkDuzZlFD16nKdWvvvye9UOiBzv3k6T09UeZlYHqYgRZzLrSMNObCaAi
         Zt1puDMfoU7tWibdL0fVY6BrjzXyHWFaXs6zlOb9uvUQORny0UfOWSQxToH72V7M7EWZ
         PDiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=TWFVCA1eidbRWe4Mvk+B7obYKckT+mqN7M8LbBoJEjM=;
        fh=M6VmGWCR/jUIjZt0xTt7EE7Krv6m3wqA9li0wB6J1R4=;
        b=i9J/HCraxmz4YlhgRZG4dvPg8g+0bxMAisKKCZQS9BvGizlBeWFRra4mwPuQueXJTD
         YSo6cCVGXHbWW0LYRHY3FpNWvcdJLqu2w/HaF2ZRErASKqmqH9jI1btd4PBixbRcI3Km
         RdFUzNjniSm5Da+HZ/+ED6curnuxw18/X5e6MLqAo/YURlx2HnckwAofLUjigfqHBhDI
         EbT0QIPZdHYSdft2iiLmoFu7HrTaQa26h50QgJ6PVYJttB+E1GcCE7Vj+rUo8OaKDedm
         sNbeyR3oFrlCMriX/blIJYclIbZ0HwoEZajcnIkbB0evP8tqIe4+ZNJVr4kbm99BMHKs
         +ctg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=LnDnbKmC;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3276f6ad8b5si273096a91.3.2025.08.28.13.51.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 13:51:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-355-kVoY973rO3GpDTtc8LLR_Q-1; Thu, 28 Aug 2025 16:51:52 -0400
X-MC-Unique: kVoY973rO3GpDTtc8LLR_Q-1
X-Mimecast-MFC-AGG-ID: kVoY973rO3GpDTtc8LLR_Q_1756414311
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-45a1b0cb0aaso10124955e9.3
        for <kasan-dev@googlegroups.com>; Thu, 28 Aug 2025 13:51:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW+zM/mqRBTo3mV9RAdotDvupUqX2qv7Jy2xtSHxolq6p0E7Aw3jGaAeRjvrN1kYSmPG5y3ITrLfuI=@googlegroups.com
X-Gm-Gg: ASbGncv3A+485j48uEkpp+eAlS15/4ofiKcO5lakz7Ah5Wys1ZT8eeyVCvKIIFTKSwC
	VpmLiLcxv4EseJUyXM9MvWTXCYC0+aOkOj4WvZknVKokpiAWVIz20BlH95SN18mVon8wUZbrKiq
	+Mb5WuN7ZmMtHZV4MvJsYf8h1qwbu0kVyF20s5cUlDuqszttQmGSUA8RZvogTPCco1dtEqBYY/h
	30Ca6S/e+VbooQ35Cis/zA/UPaBIEB5UPmQlxCOt24KJEKKbi63g0R94/pAQ9l2UmTbyfQHzjkJ
	RHAKxGwvFdoaeSxw683JaLDBR+Ue9LdIHDOCPWnH5fOTb69Uv2yBxc/Vh/nHEuTPTbTDPNdaQdx
	z6QCQUeKQx8jvmxOj+hCVpbQZE5O2xIMv8898PbpT894o153LHDRVJ4aYgVZlklMZ1XE=
X-Received: by 2002:a05:600c:c491:b0:45b:4d47:5559 with SMTP id 5b1f17b1804b1-45b517dadd6mr212975635e9.36.1756414310754;
        Thu, 28 Aug 2025 13:51:50 -0700 (PDT)
X-Received: by 2002:a05:600c:c491:b0:45b:4d47:5559 with SMTP id 5b1f17b1804b1-45b517dadd6mr212975405e9.36.1756414310334;
        Thu, 28 Aug 2025 13:51:50 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f28:c100:2225:10aa:f247:7b85? (p200300d82f28c100222510aaf2477b85.dip0.t-ipconnect.de. [2003:d8:2f28:c100:2225:10aa:f247:7b85])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b7df3ff72sm8506805e9.1.2025.08.28.13.51.47
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Aug 2025 13:51:49 -0700 (PDT)
Message-ID: <2be7db96-2fa2-4348-837e-648124bd604f@redhat.com>
Date: Thu, 28 Aug 2025 22:51:46 +0200
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
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <ea74f0e3-bacf-449a-b7ad-213c74599df1@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: vTGWxzyrFsNOQ3YZ29_MPxIRqXVBNEMqdtyaF3jYpFc_1756414311
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=LnDnbKmC;
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

On 28.08.25 18:57, Lorenzo Stoakes wrote:
> On Thu, Aug 28, 2025 at 12:01:24AM +0200, David Hildenbrand wrote:
>> Let's make it clearer that we are operating within a single folio by
>> providing both the folio and the page.
>>
>> This implies that for flush_dcache_folio() we'll now avoid one more
>> page->folio lookup, and that we can safely drop the "nth_page" usage.
>>
>> Cc: Thomas Bogendoerfer <tsbogend@alpha.franken.de>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
>> ---
>>   arch/mips/include/asm/cacheflush.h | 11 +++++++----
>>   arch/mips/mm/cache.c               |  8 ++++----
>>   2 files changed, 11 insertions(+), 8 deletions(-)
>>
>> diff --git a/arch/mips/include/asm/cacheflush.h b/arch/mips/include/asm/cacheflush.h
>> index 5d283ef89d90d..8d79bfc687d21 100644
>> --- a/arch/mips/include/asm/cacheflush.h
>> +++ b/arch/mips/include/asm/cacheflush.h
>> @@ -50,13 +50,14 @@ extern void (*flush_cache_mm)(struct mm_struct *mm);
>>   extern void (*flush_cache_range)(struct vm_area_struct *vma,
>>   	unsigned long start, unsigned long end);
>>   extern void (*flush_cache_page)(struct vm_area_struct *vma, unsigned long page, unsigned long pfn);
>> -extern void __flush_dcache_pages(struct page *page, unsigned int nr);
>> +extern void __flush_dcache_folio_pages(struct folio *folio, struct page *page, unsigned int nr);
> 
> NIT: Be good to drop the extern.

I think I'll leave the one in, though, someone should clean up all of 
them in one go.

Just imagine how the other functions would think about the new guy 
showing off here. :)

> 
>>
>>   #define ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE 1
>>   static inline void flush_dcache_folio(struct folio *folio)
>>   {
>>   	if (cpu_has_dc_aliases)
>> -		__flush_dcache_pages(&folio->page, folio_nr_pages(folio));
>> +		__flush_dcache_folio_pages(folio, folio_page(folio, 0),
>> +					   folio_nr_pages(folio));
>>   	else if (!cpu_has_ic_fills_f_dc)
>>   		folio_set_dcache_dirty(folio);
>>   }
>> @@ -64,10 +65,12 @@ static inline void flush_dcache_folio(struct folio *folio)
>>
>>   static inline void flush_dcache_page(struct page *page)
>>   {
>> +	struct folio *folio = page_folio(page);
>> +
>>   	if (cpu_has_dc_aliases)
>> -		__flush_dcache_pages(page, 1);
>> +		__flush_dcache_folio_pages(folio, page, folio_nr_pages(folio));
> 
> Hmmm, shouldn't this be 1 not folio_nr_pages()? Seems that the original
> implementation only flushed a single page even if contained within a larger
> folio?

Yes, reworked it 3 times and messed it up during the last rework. Thanks!

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2be7db96-2fa2-4348-837e-648124bd604f%40redhat.com.
