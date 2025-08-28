Return-Path: <kasan-dev+bncBC32535MUICBBY4RYDCQMGQENIPT7DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DE47B395C2
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 09:44:37 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-30cce87c38dsf250659fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:44:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756367076; cv=pass;
        d=google.com; s=arc-20240605;
        b=WQRjW6fo1f0+322kKkicSzqmZHuCXq0DH1jTSvF35RmJq6Qcc4baI/FzEc2ZtEEBMu
         ZMsvOw40IZALmfDwKjoKLzlXLz/L666FbUY8X90RcPCsjrzpSD8ZGtCgEXhMWuOcLlPT
         a0X/bIvlQZUHHs7WGUVomXJWWYAOUxSEijWt+di+brXbFhLZHjEHlx7NmeIEOOmswcya
         WSrbvhtzawj+lR6/uwyBmuUqy4GEK0f1IHQKv1BQfPGxmSqP6GdQyOMXEjs4YOBar2ve
         jcx/DFh80b02dPLmoKeECIqlZ47MzxqTNZr18IfeL1d1uCJ4sGOSG5zYXTpRewQ9T+v2
         aEuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=90gZ3QNQNmqWtjlf8Rf/kbFVm9ic1MJCNnDrLavGFA4=;
        fh=PqlYbXP8DVyId9cOrrkPDZ1y9p7K3lDpWQj1X47K+YM=;
        b=TVwout8C2TDrZtHlYv2Y70pkNsRxL82HyZQUPePSAk8aLfCztbypUXLY6kw32jaGyK
         PUKf+RtbOt8z+2gHssW1xo1k7DHTVveahU/EyXP+hflYona0v+ypUT0qpd6PoBNcBQ+5
         y86sX/TaECCLqyJONPXZ/PghetDq/PCzAmoR5TuIUHcXVicsC6nrOVtnF4WCw4jn85E7
         /DHwskHqfdTkIn2SqMESzc3mb+mHsbxXmiyJ83WcxcseCFZT6T42cSyok5ETzgOphqRE
         20uvXXOhezxJAdPz/RniAgip31gwkE/vCqNtySGyMDwg2pA8L+l+vCJU/uoZ6xzVlXXu
         KeQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MA1dAyw6;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756367076; x=1756971876; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=90gZ3QNQNmqWtjlf8Rf/kbFVm9ic1MJCNnDrLavGFA4=;
        b=OR/D7cHxMC6lZWHhYiC5vVaqgyyI/e3ddENAGlWPOIuD62jUDWLSiLvq04UARqKRS6
         L4BjSRMybr4S9+9FkF8Gsjg138oZjjhC3HwMhFWud1s1f/KxTmKpfKVDWTg/phtfU6Mq
         gf8PNAN9C65x75v3mNCB00KZ9MEM0bxeao4NTMu5X8aWxIu+ALuqfPFEyYMp5TcokT3s
         PxyRyDh9lTK9kec0LOMn/fGXeChQiCVhFlAcPKAMKAwAxlXUqNGP9+vxN2asJRM+4I5p
         bFDDJQ+TI7QriEdtekxSc1kBJ2cFylQq0o3G2JI/FENeV1K+GrS355lpJV8hbCuBb4i0
         /Ayw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756367076; x=1756971876;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=90gZ3QNQNmqWtjlf8Rf/kbFVm9ic1MJCNnDrLavGFA4=;
        b=s1i/HzojLsu9BNKXEUpqIw6WmXfh5sI5wzXEyWv5MmMqJDcmkmQIsUBvpuDPe/U09x
         6hnOKdgVuRJ7GIM1A2ZSLiDR6X3ITPlNvIOhssiQNIe57EQnSoDT/H8+HLio2S1x3Fhq
         ah0wKz9QijjzfX8kcCKI55yv3kQsRdbEO8Y2Egv62kFOnRYNS1Sk/eMINVu6aoEGlHPZ
         w/aE5iQjYps0b8SrigKfseagfmAXwUoyKzzMt/hP4oeKphvRT4cRILjM4JfxXEBScTAc
         cBNLneRVEb+ELkqTV7lKWUxTKkO8NZiE2umYbr3WVRvRAnaHlE9VP61L644vTg3j5fxk
         NTbg==
X-Forwarded-Encrypted: i=2; AJvYcCXO6nKSwEZKOUvYHGsECQ3Hd9TvryW+M63bMoQxG3zFxf6uY8Fyl8a/62lOK+M7wr17E2SiWQ==@lfdr.de
X-Gm-Message-State: AOJu0YzczsbSu/7yt6E3XiJUCLN++J+qQ/jkZXKYlcvOrR0q+boVMcpN
	twP0zNHlVdnNCZQCrUEscLdXtDqNBMXWO34T4TVR3Fzne4vD0WCv+o4h
X-Google-Smtp-Source: AGHT+IH9HW1mEiLvCJFoar8qMetDXIhJde47OohuXENjxwak2mKM35FG6zHbcVxLNXqT/ujCFWkksQ==
X-Received: by 2002:a05:6871:22cc:b0:2ea:82c1:47c with SMTP id 586e51a60fabf-314dcaa135dmr11669496fac.2.1756367075932;
        Thu, 28 Aug 2025 00:44:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeO5U6TeGRPt/JjS2on3R+C3rSE2LvajsFtuwOrk2VApg==
Received: by 2002:a05:6871:58a9:b0:2ef:17ae:f2b0 with SMTP id
 586e51a60fabf-31595d603ffls182855fac.0.-pod-prod-06-us; Thu, 28 Aug 2025
 00:44:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXOXIRmssdHFdHIAf3u4YLw/uOKi865T/TS46JEqlGOjJE75lLKBayqi5yQQ+jnc2hTL6BFCOKVQgQ=@googlegroups.com
X-Received: by 2002:a05:6830:3c8b:b0:745:4609:9e58 with SMTP id 46e09a7af769-7454609a36bmr2031234a34.10.1756367074645;
        Thu, 28 Aug 2025 00:44:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756367074; cv=none;
        d=google.com; s=arc-20240605;
        b=Yjzdpq7FCu5BBMK/GRX6QwnoKVdAiRRgaosiuIIw4xcFTZYZ/a5zrjedo0z8bOY8eo
         2biT8ByfyE4uhOER5G1juFGEkgPurRmphaNNwOcYuOUByA4kC1zEcKdtECZeoBDJ7RDE
         ediAe8gvHO+z8ehNxO4uTmC6hadqV2UIivSDqTumchFswOXKqorlgH531tEZU27qNy71
         gAgaeZJXQ+GXG7QgcNfXIYkvjyiEYR7j8WsV6h671jvftDETJKjdcpbbmVRqGD8dqXNw
         ow02DjR3Z8mGVIuMgiJtKxYdwVRe5W5d5lIT5+eVZgEg+CB+rfEmzAHp/pxZTDCbb7Si
         SQXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=dhK+BxA/iOgcFdCxhcrFsJ9ic9ebRUg2wIpkT+UYj24=;
        fh=GZiOXPDVqxSNjkZa3oa4hNKO+ASiqNUJlH+qM0Us+M8=;
        b=GM9ZyKHo3KdNBizjnsBCDv6Hfdotf58IRrtbgCFpL+WPgltg4Q4mVhx1EpBarw0Cun
         /8W4OtEiVzX0pbXM1dIPpDeouNIHTnRtqHXe6uVu/iH+OeWcIrlDM+ZngRUGFD5Q3rzn
         VLbirXits4WrwDQrE8DCyLjkiGjTOGYguPAnz/Wis2hWdpy+L/GoSL4S2vf9/W9++leH
         nUrd/4v+y5zDytmH1OCghMMNqO4Pah4RxPWhL+7+vM476J2YVMZmQOPNIe2lWRWNzdGg
         Mj8o8euUFDo1NG8p4t7OMAbJS18fLVX4qWg6TkD/M9a1UutbImhyZN3PLCMqz7/er/iW
         SuUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MA1dAyw6;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7450e11c3d7si128027a34.0.2025.08.28.00.44.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 00:44:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-518-flwaM4d9OVSr5Uhvjc65xQ-1; Thu, 28 Aug 2025 03:44:32 -0400
X-MC-Unique: flwaM4d9OVSr5Uhvjc65xQ-1
X-Mimecast-MFC-AGG-ID: flwaM4d9OVSr5Uhvjc65xQ_1756367071
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-3ccfd9063a0so207491f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 28 Aug 2025 00:44:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXQ/w2J483b8LLlC0ByF9/3d4jaZxt4H01mSq9Pl8Os8gGmQbLRCLTT6LGttI+8w491kNMnyImB23o=@googlegroups.com
X-Gm-Gg: ASbGncsBBMnd3qiR2U9c3T3meDYzRrSjYAxBSNpZFjUKM2cZj2UNh459xBM213EsMwQ
	B8mz7gCjPpY+HtlR4mfzJfDhakcm+eBmejf0vj4LiJLSsTvnX/MJ9JRa+3Y5QUpTvLEcAoPn6PC
	FSp5NGSi3Ejgqgs8Fh+33HvGQVwYTJHFSGiqF7rkiwH7nw5JiIvYH6naDArTtRXF2lJx0IojKP5
	cy2s6Ts4VG7h04nb6462/BlkLvotYtW/Ojw93pqwTBS1gTGH7roiOIqOE3YYbzsRqG650pOJOaz
	fYt3VQbxx6RXPBlYrM+Gp3hkZL+cK62nSl37R+DJu+M4y9zjhG+3hJj4J6Lw9fFyg5yrzSwKHwe
	aRHk+7iCP6HpzgEwfXqBvNWM7PUzE8H0ih4OlkFqpfYSVaCZtKM2EbN+wrC3OR1SvB8E=
X-Received: by 2002:a5d:5d0a:0:b0:3b8:f358:e80d with SMTP id ffacd0b85a97d-3c5db8ab097mr18866991f8f.5.1756367070819;
        Thu, 28 Aug 2025 00:44:30 -0700 (PDT)
X-Received: by 2002:a5d:5d0a:0:b0:3b8:f358:e80d with SMTP id ffacd0b85a97d-3c5db8ab097mr18866962f8f.5.1756367070322;
        Thu, 28 Aug 2025 00:44:30 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f28:c100:2225:10aa:f247:7b85? (p200300d82f28c100222510aaf2477b85.dip0.t-ipconnect.de. [2003:d8:2f28:c100:2225:10aa:f247:7b85])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cd2e01dd9dsm4501230f8f.60.2025.08.28.00.44.28
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Aug 2025 00:44:29 -0700 (PDT)
Message-ID: <377449bd-3c06-4a09-8647-e41354e64b30@redhat.com>
Date: Thu, 28 Aug 2025 09:44:27 +0200
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
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <aLADXP89cp6hAq0q@kernel.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: HI8BZHtHqans4JZpFDsQRFdzFUsOyvv54s64OExa5EA_1756367071
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=MA1dAyw6;
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

On 28.08.25 09:21, Mike Rapoport wrote:
> On Thu, Aug 28, 2025 at 12:01:17AM +0200, David Hildenbrand wrote:
>> We can now safely iterate over all pages in a folio, so no need for the
>> pfn_to_page().
>>
>> Also, as we already force the refcount in __init_single_page() to 1,
>> we can just set the refcount to 0 and avoid page_ref_freeze() +
>> VM_BUG_ON. Likely, in the future, we would just want to tell
>> __init_single_page() to which value to initialize the refcount.
>>
>> Further, adjust the comments to highlight that we are dealing with an
>> open-coded prep_compound_page() variant, and add another comment explaining
>> why we really need the __init_single_page() only on the tail pages.
>>
>> Note that the current code was likely problematic, but we never ran into
>> it: prep_compound_tail() would have been called with an offset that might
>> exceed a memory section, and prep_compound_tail() would have simply
>> added that offset to the page pointer -- which would not have done the
>> right thing on sparsemem without vmemmap.
>>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
>> ---
>>   mm/hugetlb.c | 20 ++++++++++++--------
>>   1 file changed, 12 insertions(+), 8 deletions(-)
>>
>> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
>> index 4a97e4f14c0dc..1f42186a85ea4 100644
>> --- a/mm/hugetlb.c
>> +++ b/mm/hugetlb.c
>> @@ -3237,17 +3237,18 @@ static void __init hugetlb_folio_init_tail_vmemmap(struct folio *folio,
>>   {
>>   	enum zone_type zone = zone_idx(folio_zone(folio));
>>   	int nid = folio_nid(folio);
>> +	struct page *page = folio_page(folio, start_page_number);
>>   	unsigned long head_pfn = folio_pfn(folio);
>>   	unsigned long pfn, end_pfn = head_pfn + end_page_number;
>> -	int ret;
>> -
>> -	for (pfn = head_pfn + start_page_number; pfn < end_pfn; pfn++) {
>> -		struct page *page = pfn_to_page(pfn);
>>   
>> +	/*
>> +	 * We mark all tail pages with memblock_reserved_mark_noinit(),
>> +	 * so these pages are completely uninitialized.
> 
>                               ^ not? ;-)

Can you elaborate?

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/377449bd-3c06-4a09-8647-e41354e64b30%40redhat.com.
