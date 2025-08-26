Return-Path: <kasan-dev+bncBC32535MUICBBSVJW3CQMGQE2DX42JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 073DBB35AA1
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 13:04:44 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-70d9f5bdf6asf79442486d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 04:04:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756206283; cv=pass;
        d=google.com; s=arc-20240605;
        b=NWt378Ku7Wu2IghkOhDHBc4RXFTJaMZHXnLIl/UtY0Rhlfk0GDib0IDpmM9muaxvof
         tV5JR9nuwjaUbfojWTyxfWfRQxHksy12xFtBdFTSr89wylMBCobDSfuiBxgmvhRbNfQy
         u35MiW+cGbeBszPplM2FzbXPoTHWWVGRF4mF/quLmJ4GLZx1q6CqGQRNAbfcYaHrz32G
         PESpy8v5re7bM40xsIa2AQBFmb+cfFyWsGukA+JVlv8BncNZjIBm3/geBots184EINcV
         YRGb+zPFuW9zBKk8umC32PCS3OpgbcxhAAUsTJ2HJ5MTltctKxsjxS5PGCFqn9y2K61r
         iZFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=DDvrgHOKjEueRRuzxu9O5bT3OHarODbOf6ThG5Pg1pk=;
        fh=PQDppst87pgaWkEjGfy34AoVz9yOu8NNUVlVAriGkbw=;
        b=afKgTdWWV4WvbO5JpykUKV3CndktQpcbJENXf4qTg+efSeP7ZZP2Av28G0MOeX7Thm
         GOiE1ADJiUdxVGMoxqS1SDTj2Bjilub/OwKMoXcNhzeCmcWE60I6ighxxoBFNBLEZB3I
         HjituPy9BP3iOlEyboqpWzznG/5me/QJU+FZZdXkXsyLX0dWbhEgRoxRKgHsvqADQIi1
         tMxC8UH8e884oSqEW9Jv5w2wB2uCWIOBG7f9xqgEnUOeE8HyPkyGPj/jQw9k94kckNhH
         wXJswHBYzEX/RfXwEatanukcHgdXZgVOQQlSTNYR2PjfS5mvYoeX1iR5oNAi/F1/A4c3
         VCmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=canFekNU;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756206283; x=1756811083; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=DDvrgHOKjEueRRuzxu9O5bT3OHarODbOf6ThG5Pg1pk=;
        b=IWF9MEd5JANfk6bxfwDUi/BrwPOzk6L1sBL47fZbx7Zm4QpAG04XqVSMW32GNoaZMd
         mMldYvwzqtExaD8zmKa6xq37TQQhGJ/Bnur3hh1uJPxwj2HSLadY4cUOzUElbE1Q/k7c
         jDXgXM9B200znOQ6Rynaf1bfa6RALqMj8kPppLbBZ3cs7CT5BUG3bkepMte4doFc4Gxy
         +8tt6g7ZkrMBrf9Itjg1AyqWn4R7ewLQ43if33ce8HT/ciuO0N5eA05fhSQTgbP+6QYd
         7dt5Ab6raYeePT+d+Kv04i1CR1DB0IshozwI2Q5jAkyIoGYK7ipmD7bHrbem6QCjeqiY
         EGUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756206283; x=1756811083;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=DDvrgHOKjEueRRuzxu9O5bT3OHarODbOf6ThG5Pg1pk=;
        b=I6jpU4XPzgfis9Vhxyx/pnHiI4k+0LJmOgOPpVs5h79ZuM/p2eu+n2w8jy1+ZHZtmo
         57Gs6801nhK7Ms9ctn+fUfCit8+VXIKvjWZ2doluEyj2FmIGksNnROlWzzwWt4k3lFXA
         TuMJ02u3IT0t4lmVrNQVqI4n1CjLoxBHZsDTho+vCh82nutnGU1UhQIEN7eJiEnXle2+
         BBhZPnmaS+c6jxQGqPs/I/J5a2SM13QH0412dIBvlt6wcL9bDoBLmoDuogxX2Sls2Y1C
         tId0Y70edBOql1rmhIWUxBW5/ta3r2huszJTebj5tbwFG95sCLybnjqJ1tEZ56fWIp/y
         Z5pQ==
X-Forwarded-Encrypted: i=2; AJvYcCX0eoCCSXwg6qYeYJGKXJQJe5Zgt9TK9Yte6Q17pp05u58LnzH4dlj7KPElIwRrvUbNoYZGdw==@lfdr.de
X-Gm-Message-State: AOJu0Yz028JV4AUo93VaRylnAmvC83KrYhoFi4//hrrmkP1NTLxCfK+E
	Y8UWvmWjqomzDN3WyTD08BBaRZN/0+mYxTQqxQVTmIdc9hxR1vwBYPCF
X-Google-Smtp-Source: AGHT+IGbcfkxgVRRtDOwto4HFL2KtpheiCXCRGxgHTm0yZeROlU+fYkMCvYvm3FDVH3CWBUc9n2/jw==
X-Received: by 2002:a05:6214:dae:b0:70d:6df3:9a80 with SMTP id 6a1803df08f44-70d9725a314mr159809966d6.64.1756206282370;
        Tue, 26 Aug 2025 04:04:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcgSHnFngpYQ7FkJkeM6OPfToIlikIiJsxvuHOa/XfLzg==
Received: by 2002:a05:6214:29ef:b0:70d:9e42:dc8f with SMTP id
 6a1803df08f44-70d9e42e738ls64559736d6.0.-pod-prod-07-us; Tue, 26 Aug 2025
 04:04:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXYeL2Lg6wqtz8xyowcRV25Lv6CJeJ8r4fmFY/zko36lsbvi6YH971y0P7RXudkqPN6d54m7R4vxgo=@googlegroups.com
X-Received: by 2002:a05:6102:d8f:b0:521:f2f5:e444 with SMTP id ada2fe7eead31-521f2f5edf1mr2624651137.17.1756206281381;
        Tue, 26 Aug 2025 04:04:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756206281; cv=none;
        d=google.com; s=arc-20240605;
        b=dF3CNCMkfZXkR/7Lf2MymAOXP1JsazcpG2L6GVAVRN06ccPSfstQwAEXLUdJ02bMwc
         mzHUBapINQfhcCwn9SUeTGzABY50sta5uq83xoq6gEX/sHGrRsav0CIW3P6uxEpzO4cm
         X5fxOsOAhqfKg6rTkEZY022O9AXEyrrNTch/3hIs3+EA/eyXlG+zlAqcLZ9c3NWKwc25
         Zz2DOIpxWaWBxzBrzvOYcZRJbuwV599h8G+6wwxWHD2cuUKdk+Jhex4akKMLob5fXIJR
         6L5gy/w1ZMHywM79jRhD98AJ37vQHafOGtOSw8FkyPxXMY9odF0VFcCKGKVpxcBeoMqU
         9NXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=jhHf33zPn8FMTc4V2Pm10xsHI1Kc6Z2Rv/ZWcei/RDk=;
        fh=9cbIuJfVLx+pvGZqfaSIo1YVledwrKTDf99pIdQk+uk=;
        b=JZdq7YJQmgw5XTwUBsiZ2+TqxfErrMQQ6foZkzNxmQtivq+eZyC81AUvr6gzklmZ2a
         01bB4W8SCY3devyVutceLbgGL2JMB6KrRaM2AglIMiIMisJSSgyD07yONqD419kE4Ipn
         G/HBf595Pn3ZrOzN4wieujiikUUTsbNtoZ/j5T0RxLBdnkBJ/3xfkbtT2E8HUFiWHHKC
         YTe7GSaLhRdBh7bMQewvnDRBrx2pX9FfwkAqGUkBi7cqNmluT2Nm6UUj9VwVpWCTjs6u
         872bhU6qP7yG0TiLd+WEazq9wpPpHTtYN3jt+G3uJf5r4LkQwp0jzQL4qmo1nlkwtnic
         ZMrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=canFekNU;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-51e4bfd9b99si379842137.2.2025.08.26.04.04.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Aug 2025 04:04:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-ed1-f70.google.com (mail-ed1-f70.google.com
 [209.85.208.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-98-Tle2XyriOlSZ3fSeGF9VsA-1; Tue, 26 Aug 2025 07:04:39 -0400
X-MC-Unique: Tle2XyriOlSZ3fSeGF9VsA-1
X-Mimecast-MFC-AGG-ID: Tle2XyriOlSZ3fSeGF9VsA_1756206279
Received: by mail-ed1-f70.google.com with SMTP id 4fb4d7f45d1cf-61c6d735f15so1813800a12.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 04:04:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUHrXaLf9AhpiZhOXCQJCN/nk8F0Eqh7a8Y4GDhnLcuBsAA20677TTSEY2XAChEX2Cpjok6BXah8fU=@googlegroups.com
X-Gm-Gg: ASbGncvo0ZtviE0I4nfkEK0V9K08zxHI6gDMu+rfhnBGX0B00V7i5mSvDaxmhMDYVQ2
	otTavhA0yFEipanLMGcc6yxsNC/b036u91K9skfcv0XThft8ck0nvDJFHzDd3nkIm2PIY/vBg3P
	jNonJWGJUpCKKte4GTLGBA3KQnLvtiaU+qb/mUpLp9qStq8lDcWxMPHSP021elJXv4lZ38Nb68g
	FdE57LRakwVSRDWnrp8wZKg3F5vVYaDSxQmWSngt11SMTRuP07C0BKeS1srm6wu0omhF3TZTOAp
	F5893w40qB40NuS70u3kFNorSC1cGnggtXEh13GAAZ3YNINW98j5xmDZpZMiXH65ikWzMUayQw=
	=
X-Received: by 2002:a05:6402:510e:b0:61c:a1a6:52a2 with SMTP id 4fb4d7f45d1cf-61ca1a65d0amr110480a12.28.1756206278215;
        Tue, 26 Aug 2025 04:04:38 -0700 (PDT)
X-Received: by 2002:a05:6402:510e:b0:61c:a1a6:52a2 with SMTP id 4fb4d7f45d1cf-61ca1a65d0amr110409a12.28.1756206276561;
        Tue, 26 Aug 2025 04:04:36 -0700 (PDT)
Received: from ?IPV6:2a09:80c0:192:0:5dac:bf3d:c41:c3e7? ([2a09:80c0:192:0:5dac:bf3d:c41:c3e7])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-61c3172bf4csm6850118a12.38.2025.08.26.04.04.34
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 04:04:36 -0700 (PDT)
Message-ID: <ad521f4f-47aa-4728-916f-3704bf01f770@redhat.com>
Date: Tue, 26 Aug 2025 13:04:33 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 21/35] mm/cma: refuse handing out non-contiguous page
 ranges
To: Alexandru Elisei <alexandru.elisei@arm.com>
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
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org,
 Zi Yan <ziy@nvidia.com>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-22-david@redhat.com> <aK2QZnzS1ErHK5tP@raptor>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <aK2QZnzS1ErHK5tP@raptor>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: xapZPDjAkXp_7oY03sT4qLOngXMT6pbucvrhPyfZ0RM_1756206279
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=canFekNU;
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

>>   
>>   		pr_debug("%s(): memory range at pfn 0x%lx %p is busy, retrying\n",
>> -			 __func__, pfn, pfn_to_page(pfn));
>> +			 __func__, pfn, page);
>>   
>>   		trace_cma_alloc_busy_retry(cma->name, pfn, pfn_to_page(pfn),
> 
> Nitpick: I think you already have the page here.

Indeed, forgot to clean that up as well.

> 
>>   					   count, align);
>> -		/* try again with a bit different memory target */
>> -		start = bitmap_no + mask + 1;
>>   	}
>>   out:
>> -	*pagep = page;
>> +	if (!ret)
>> +		*pagep = page;
>>   	return ret;
>>   }
>>   
>> @@ -882,7 +892,7 @@ static struct page *__cma_alloc(struct cma *cma, unsigned long count,
>>   	 */
>>   	if (page) {
>>   		for (i = 0; i < count; i++)
>> -			page_kasan_tag_reset(nth_page(page, i));
>> +			page_kasan_tag_reset(page + i);
> 
> Had a look at it, not very familiar with CMA, but the changes look equivalent to
> what was before. Not sure that's worth a Reviewed-by tag, but here it in case
> you want to add it:
> 
> Reviewed-by: Alexandru Elisei <alexandru.elisei@arm.com>

Thanks!

> 
> Just so I can better understand the problem being fixed, I guess you can have
> two consecutive pfns with non-consecutive associated struct page if you have two
> adjacent memory sections spanning the same physical memory region, is that
> correct?

Exactly. Essentially on SPARSEMEM without SPARSEMEM_VMEMMAP it is not 
guaranteed that

	pfn_to_page(pfn + 1) == pfn_to_page(pfn) + 1

when we cross memory section boundaries.

It can be the case for early boot memory if we allocated consecutive 
areas from memblock when allocating the memmap (struct pages) per memory 
section, but it's not guaranteed.

So we rule out that case.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ad521f4f-47aa-4728-916f-3704bf01f770%40redhat.com.
