Return-Path: <kasan-dev+bncBC32535MUICBBQFW57CQMGQES2F4R6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 42042B4698B
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Sep 2025 08:57:07 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-24caf28cce0sf65833115ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 23:57:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757141825; cv=pass;
        d=google.com; s=arc-20240605;
        b=cm0wyRWpA40q3aKcqNik64xYhCKoknRQ/zSkSM45SRAyzh8lwqm07BYPK1IZGWeZv8
         oPmVtnVVdAQI+DouH++ROsSpR4pLJYV8OCVp5r0GbkVHy/34zfv2Yrw69N475zvw4z+o
         GEWitu14hAV1UAuxfZ3g7mGNKeGqzpNaK4yMAlAhG7FCBp/OfHmls5Os4flClMJi3qKa
         uZ/kj9qNL0hnP5h7c9I9OF2ev1Kzfoqc82Sv5BJk6DX98ZNR5M32P0CxYqYXgsP0quHp
         iU4bg+ElCWD44W9QkyCFULub+JQYWBD+ZYqn4g/s8IV5Ds1PhXnYqIdH9SQu+8rGPDdy
         n3kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=/TnZOvEL0hHLDoqweqmAfu7dvCmwpEvEEsnVJ3vtGOw=;
        fh=LyY1lOCF1jgBbg/ibsU/JznBum3Thj4YLRJuVE7Nfcw=;
        b=emqr7I+vxOsL2Y0sVn1sivDBXW+7Xb6/EcleLq+V8xPToeggrDxMBT+44PewSDDl/C
         MvNo+Pp+vHTIfcqc1J12XW1b/0zKyaKnPy7W3jPWtfCDHpjz6mO2/uN6ecP8ExM8xieA
         T3ub4DiKCj4zLJw82jtEzYXWCmvB5N0VGhlBDhnBXsBg08ZZZK6qVZYozCMw4mAWBiw4
         K0Fq5xzMNfZ8fVrB5Aaqu9i1P5VvkPMBqPh7/RYwOSJrWvN7Q/WmvasoDsmxn7pcPgjc
         +oWcLQTz0sbFfQsL4xK6ZxYQmcpLTckxKrDzggi1YBK5vg36RBxgBr+GRPeWxNP5Fd+L
         m79w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=XZrKF99G;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757141825; x=1757746625; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=/TnZOvEL0hHLDoqweqmAfu7dvCmwpEvEEsnVJ3vtGOw=;
        b=EYja14uYz75vPs8Upf1sHYxCkmZQcWDHqzvR6ioe2tUJKcTF/+BjZPNZN8uMI6mO/E
         9XEJ3v/A5avVE1e8qX3KM0+S3wdw95vsFPE2KnLLmaxcRBKtG48TluWKaBzzj/Xi4zuJ
         z465iSXkXlw8OXzmrZIEHVxMFIGNeKV+AfcZpoeFZp9jh0jnpmHlA/T+yijL4PUFKSfQ
         WxqQvAcCbhGh66W7EuXWn+z5i7Q74FIj/NMShtDArm4e+QMkyXa7W92rjyeMm7tXVBV1
         FIS0zVld3PxJXp+po6GnkgBA97TK8axGL00eWkuGnh/R5R5QCF4uEQPD8a8k18HYMQ2i
         nugw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757141825; x=1757746625;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=/TnZOvEL0hHLDoqweqmAfu7dvCmwpEvEEsnVJ3vtGOw=;
        b=sf1vyalYJ6bcbl6xusyFUpqIjnrhlWsjPa3/irOmt68xZuH2YqaZFMJ3vF3b0p3jAn
         W7hPVXOYjvbN4bkCDla53wHT8N65KwOwKJxhmXC+MlllGlVFzcfxKpdZbkG0fcEDBI8r
         z23ch/MtwyFAixAQ1gMuTz9ABkwxYeTDVJePD58yFzYGonlcYv30g3Wu+LNzOsAC93pj
         vj7x35dvkXX8EXbDHHw2AkzWOEmKM2CcUSem6e2tugtkAau3nw0crWi+mwKnuqF9fjbX
         FlPpFfEGQb3ACCIWJxhqN1YWhT/rmmljYCpMhVkIRCPmIiOgqLDP9XzeqqsM+wmlG3uy
         2NFg==
X-Forwarded-Encrypted: i=2; AJvYcCV7wCrL5CKAM0hLtoAOXhxgj7fL5p4PvY6nvX5EtRoSygu/oQjxGeLgJDZtw8mpYB+tFY0lWw==@lfdr.de
X-Gm-Message-State: AOJu0YwUIl9y2R8enWFtPjXbWGFG0WtzppdqsISqx8TBqQUehZIE7noL
	bDlObFVftQRVpz1eil/JioQao+CpAwziNSZFFG/T3hPQDK7cQtU8zEKR
X-Google-Smtp-Source: AGHT+IHDn+HDukkhkh98bA9ZAkc2pJEodkDlF+UwOep/UHwUNZ9/6wGzSq677OE6ldwQH4lPqanTvw==
X-Received: by 2002:a17:902:f711:b0:248:96af:51e with SMTP id d9443c01a7336-251751e5bc1mr19270755ad.45.1757141825361;
        Fri, 05 Sep 2025 23:57:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdzIHbw9UIrPVtF5Fb3j9ACxt0pMGzLOe09YpCms29SXw==
Received: by 2002:a17:903:2f83:b0:246:7bc8:5845 with SMTP id
 d9443c01a7336-24d4c560993ls17292375ad.0.-pod-prod-08-us; Fri, 05 Sep 2025
 23:57:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVajMQrESJBeVdwH6lH/U7+o4GFzYIJPQuYT7k7LcSrdlUnw8SV9A4yv2pAmm6SRqzn2mVuoBTntf4=@googlegroups.com
X-Received: by 2002:a17:902:f550:b0:24b:270e:56f4 with SMTP id d9443c01a7336-251736df030mr18718795ad.37.1757141823475;
        Fri, 05 Sep 2025 23:57:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757141823; cv=none;
        d=google.com; s=arc-20240605;
        b=X99j/Bm724R+WQHWG4jjFU9Q+j2YhzfhFw91PQSUkKJK6PziTCo1uogmQgfwMWIZvo
         T0rmOy4TWD4AU/p6WQkktlEJARa+fWCGRDCNBQn48YOFnpsosXQ/Q4Ic2aK4CTclGVOK
         vc6ngKY1Vv4+kQTUKvVA14hYm9DsIo9+VdBqal/YVd0Hc2Pmqx9Q8ba8yHFguj73exkf
         UsHc8ZbzsuvwHHlE1okNZvA8amF7C6bNZBBr2oTi499la8UI4dCPqGmcGf95MeY2uOdr
         aMdqGW/e3OTRZHdPllxuFxDtof068Gu5xGN+y3IkcjAOVVAKLdrHtysX804IMFQrYihk
         sEVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=Vne0EVwrnVHw6NJLJyd+zZpE6+oJG9x8TCUx1n8W1nw=;
        fh=E9DPpRgp+rlA1N7DjPlRhB/HiS0HKpIG1mNKSTgZniQ=;
        b=GrGo0lcx0KRpfOzuef5QHBMS3aveRwtdHqYR8FMMeKbosUu5jxGLgGRbbv07bD7G/0
         wFWLse12XEAM7utBmnETev/kuaCJsT7D2Uqlft16GxWM7DdhKWV0jtf2dWMwY5M6ssL/
         U1nJYcz7BhrikGoXSRZ+3ZC5EpqrKG5y0AZGEjLzO57oG/ii5+TTR1V1OC7cIaP1f+zu
         IVuibnVl0RTNQHdQ+uzECuQxSHOoPj4jCF63iHCH5D7jT1yUqGgr1NoyIxzTsfJI63/w
         JY4qpNft8C8LNctFUAPzaErYziDxufjnBDwstradgLPKetbRDADy6njQodlN8HlnSb9U
         69qg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=XZrKF99G;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-24c966877d4si731585ad.0.2025.09.05.23.57.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Sep 2025 23:57:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-281-fE6Yvm5-M_6H801YAk54eA-1; Sat, 06 Sep 2025 02:56:59 -0400
X-MC-Unique: fE6Yvm5-M_6H801YAk54eA-1
X-Mimecast-MFC-AGG-ID: fE6Yvm5-M_6H801YAk54eA_1757141819
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45dd5c1b67dso11069205e9.2
        for <kasan-dev@googlegroups.com>; Fri, 05 Sep 2025 23:56:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXNJ0wmLtMS6iOb+9YEWxrcIaYU7IKKxKbZp/AhVz5Ak30Tr0RbiXp/LHbS5+qxV80v20QvBgUvWzI=@googlegroups.com
X-Gm-Gg: ASbGncsDX7wcV9XX+9S6GHAAcDFZUPj3spuLPxHQkc254IX+8X/mOjyFiuSEOsrQ7rq
	T+8eSr3f5uv4Mbp4Bmzlj8qUtSuSMw8u4r4V/YQKd6NcH+BXSXcpOxWrJxWjSa6UfywNGQa3e2K
	7OHOgMAbcz0mseBIRg1Vk5Wgj9U7qHq3Eh7mhOLoXZGO0Di6VSuRFyYxJBH3UZRsJxsxAhk/tYH
	pgqRgRfMltcqyDHdMUVNdCvn7wjA9Hd01tBbC0TLnQBBKWRAZxqjErV4Sp8mRZ8dPL+cKAD/Ty5
	82gtsw3Th4NWDydvnmGPOpWHL4b683bYVdVpychIMgxqkgYxQMIBT1z9xbP2n0PDtQjV49XI50j
	NpGmr6RGLkGu4RYQsEbhPdv4WiPrD6c9SLkZLDN5MXl+oIW1HLaCwARiw/J8Mb86cEkc=
X-Received: by 2002:a05:6000:4406:b0:3e7:404f:6b9 with SMTP id ffacd0b85a97d-3e7404f0ad9mr25517f8f.24.1757141818666;
        Fri, 05 Sep 2025 23:56:58 -0700 (PDT)
X-Received: by 2002:a05:6000:4406:b0:3e7:404f:6b9 with SMTP id ffacd0b85a97d-3e7404f0ad9mr25486f8f.24.1757141818148;
        Fri, 05 Sep 2025 23:56:58 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f30:de00:8132:f6dc:cba2:9134? (p200300d82f30de008132f6dccba29134.dip0.t-ipconnect.de. [2003:d8:2f30:de00:8132:f6dc:cba2:9134])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3df4fd372ccsm11959114f8f.32.2025.09.05.23.56.49
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 23:56:53 -0700 (PDT)
Message-ID: <85e760cf-b994-40db-8d13-221feee55c60@redhat.com>
Date: Sat, 6 Sep 2025 08:56:48 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 19/37] mm/gup: remove record_subpages()
To: John Hubbard <jhubbard@nvidia.com>, linux-kernel@vger.kernel.org
Cc: Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, kasan-dev@googlegroups.com,
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
 <016307ba-427d-4646-8e4d-1ffefd2c1968@nvidia.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <016307ba-427d-4646-8e4d-1ffefd2c1968@nvidia.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: WKSDzdbe1WDwzAMqSVGEMt-6kWWFZqh32jT7o9sBUv4_1757141819
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=XZrKF99G;
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

On 06.09.25 03:05, John Hubbard wrote:
> On 9/1/25 8:03 AM, David Hildenbrand wrote:
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
>>   
>>   #ifdef CONFIG_HAVE_GUP_FAST
>> -static int record_subpages(struct page *page, unsigned long sz,
>> -			   unsigned long addr, unsigned long end,
>> -			   struct page **pages)
>> -{
>> -	int nr;
>> -
>> -	page += (addr & (sz - 1)) >> PAGE_SHIFT;
>> -	for (nr = 0; addr != end; nr++, addr += PAGE_SIZE)
>> -		pages[nr] = page++;
>> -
>> -	return nr;
>> -}
>> -
>>   /**
>>    * try_grab_folio_fast() - Attempt to get or pin a folio in fast path.
>>    * @page:  pointer to page to be grabbed
>> @@ -2967,8 +2954,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
>>   	if (pmd_special(orig))
>>   		return 0;
>>   
>> -	page = pmd_page(orig);
>> -	refs = record_subpages(page, PMD_SIZE, addr, end, pages + *nr);
>> +	refs = (end - addr) >> PAGE_SHIFT;
>> +	page = pmd_page(orig) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
>>   
>>   	folio = try_grab_folio_fast(page, refs, flags);
>>   	if (!folio)
>> @@ -2989,6 +2976,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
>>   	}
>>   
>>   	*nr += refs;
>> +	for (; refs; refs--)
>> +		*(pages++) = page++;
>>   	folio_set_referenced(folio);
>>   	return 1;
>>   }
>> @@ -3007,8 +2996,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
>>   	if (pud_special(orig))
>>   		return 0;
>>   
>> -	page = pud_page(orig);
>> -	refs = record_subpages(page, PUD_SIZE, addr, end, pages + *nr);
>> +	refs = (end - addr) >> PAGE_SHIFT;
>> +	page = pud_page(orig) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
>>   
>>   	folio = try_grab_folio_fast(page, refs, flags);
>>   	if (!folio)
>> @@ -3030,6 +3019,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
>>   	}
>>   
>>   	*nr += refs;
>> +	for (; refs; refs--)
>> +		*(pages++) = page++;
> 
> Hi David,

Hi!

> 
> Probably a similar sentiment as Lorenzo here...the above diffs make the code
> *worse* to read. In fact, I recall adding record_subpages() here long ago,
> specifically to help clarify what was going on.

Well, there is a lot I dislike about record_subpages() to go back there.
Starting with "as Willy keeps explaining, the concept of subpages do
not exist and ending with "why do we fill out the array even on failure".

:)

> 
> Now it's been returned to it's original, cryptic form.
> 

The code in the caller was so uncryptic that both me and Lorenzo missed
that magical addition. :P

> Just my take on it, for whatever that's worth. :)

As always, appreciated.

I could of course keep the simple loop in some "record_folio_pages"
function and clean up what I dislike about record_subpages().

But I much rather want the call chain to be cleaned up instead, if possible.


Roughly, what I am thinking (limiting it to pte+pmd case) about is the following:


 From d6d6d21dbf435d8030782a627175e36e6c7b2dfb Mon Sep 17 00:00:00 2001
From: David Hildenbrand <david@redhat.com>
Date: Sat, 6 Sep 2025 08:33:42 +0200
Subject: [PATCH] tmp

Signed-off-by: David Hildenbrand <david@redhat.com>
---
  mm/gup.c | 79 ++++++++++++++++++++++++++------------------------------
  1 file changed, 36 insertions(+), 43 deletions(-)

diff --git a/mm/gup.c b/mm/gup.c
index 22420f2069ee1..98907ead749c0 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -2845,12 +2845,11 @@ static void __maybe_unused gup_fast_undo_dev_pagemap(int *nr, int nr_start,
   * also check pmd here to make sure pmd doesn't change (corresponds to
   * pmdp_collapse_flush() in the THP collapse code path).
   */
-static int gup_fast_pte_range(pmd_t pmd, pmd_t *pmdp, unsigned long addr,
-		unsigned long end, unsigned int flags, struct page **pages,
-		int *nr)
+static unsigned long gup_fast_pte_range(pmd_t pmd, pmd_t *pmdp, unsigned long addr,
+		unsigned long end, unsigned int flags, struct page **pages)
  {
  	struct dev_pagemap *pgmap = NULL;
-	int ret = 0;
+	unsigned long nr_pages = 0;
  	pte_t *ptep, *ptem;
  
  	ptem = ptep = pte_offset_map(&pmd, addr);
@@ -2908,24 +2907,20 @@ static int gup_fast_pte_range(pmd_t pmd, pmd_t *pmdp, unsigned long addr,
  		 * details.
  		 */
  		if (flags & FOLL_PIN) {
-			ret = arch_make_folio_accessible(folio);
-			if (ret) {
+			if (arch_make_folio_accessible(folio)) {
  				gup_put_folio(folio, 1, flags);
  				goto pte_unmap;
  			}
  		}
  		folio_set_referenced(folio);
-		pages[*nr] = page;
-		(*nr)++;
+		pages[nr_pages++] = page;
  	} while (ptep++, addr += PAGE_SIZE, addr != end);
  
-	ret = 1;
-
  pte_unmap:
  	if (pgmap)
  		put_dev_pagemap(pgmap);
  	pte_unmap(ptem);
-	return ret;
+	return nr_pages;
  }
  #else
  
@@ -2938,21 +2933,24 @@ static int gup_fast_pte_range(pmd_t pmd, pmd_t *pmdp, unsigned long addr,
   * get_user_pages_fast_only implementation that can pin pages. Thus it's still
   * useful to have gup_fast_pmd_leaf even if we can't operate on ptes.
   */
-static int gup_fast_pte_range(pmd_t pmd, pmd_t *pmdp, unsigned long addr,
-		unsigned long end, unsigned int flags, struct page **pages,
-		int *nr)
+static unsigned long gup_fast_pte_range(pmd_t pmd, pmd_t *pmdp, unsigned long addr,
+		unsigned long end, unsigned int flags, struct page **pages)
  {
  	return 0;
  }
  #endif /* CONFIG_ARCH_HAS_PTE_SPECIAL */
  
-static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
-		unsigned long end, unsigned int flags, struct page **pages,
-		int *nr)
+static unsigned long gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
+		unsigned long end, unsigned int flags, struct page **pages)
  {
+	const unsigned long nr_pages = (end - addr) >> PAGE_SHIFT;
  	struct page *page;
  	struct folio *folio;
-	int refs;
+	unsigned long i;
+
+	/* See gup_fast_pte_range() */
+	if (pmd_protnone(orig))
+		return 0;
  
  	if (!pmd_access_permitted(orig, flags & FOLL_WRITE))
  		return 0;
@@ -2960,33 +2958,30 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
  	if (pmd_special(orig))
  		return 0;
  
-	refs = (end - addr) >> PAGE_SHIFT;
  	page = pmd_page(orig) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
  
-	folio = try_grab_folio_fast(page, refs, flags);
+	folio = try_grab_folio_fast(page, nr_pages, flags);
  	if (!folio)
  		return 0;
  
  	if (unlikely(pmd_val(orig) != pmd_val(*pmdp))) {
-		gup_put_folio(folio, refs, flags);
+		gup_put_folio(folio, nr_pages, flags);
  		return 0;
  	}
  
  	if (!gup_fast_folio_allowed(folio, flags)) {
-		gup_put_folio(folio, refs, flags);
+		gup_put_folio(folio, nr_pages, flags);
  		return 0;
  	}
  	if (!pmd_write(orig) && gup_must_unshare(NULL, flags, &folio->page)) {
-		gup_put_folio(folio, refs, flags);
+		gup_put_folio(folio, nr_pages, flags);
  		return 0;
  	}
  
-	pages += *nr;
-	*nr += refs;
-	for (; refs; refs--)
+	for (i = 0; i < nr_pages; i++)
  		*(pages++) = page++;
  	folio_set_referenced(folio);
-	return 1;
+	return nr_pages;
  }
  
  static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
@@ -3033,11 +3028,11 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
  	return 1;
  }
  
-static int gup_fast_pmd_range(pud_t *pudp, pud_t pud, unsigned long addr,
-		unsigned long end, unsigned int flags, struct page **pages,
-		int *nr)
+static unsigned long gup_fast_pmd_range(pud_t *pudp, pud_t pud, unsigned long addr,
+		unsigned long end, unsigned int flags, struct page **pages)
  {
-	unsigned long next;
+	unsigned long cur_nr_pages, next;
+	unsigned long nr_pages = 0;
  	pmd_t *pmdp;
  
  	pmdp = pmd_offset_lockless(pudp, pud, addr);
@@ -3046,23 +3041,21 @@ static int gup_fast_pmd_range(pud_t *pudp, pud_t pud, unsigned long addr,
  
  		next = pmd_addr_end(addr, end);
  		if (!pmd_present(pmd))
-			return 0;
+			break;
  
-		if (unlikely(pmd_leaf(pmd))) {
-			/* See gup_fast_pte_range() */
-			if (pmd_protnone(pmd))
-				return 0;
+		if (unlikely(pmd_leaf(pmd)))
+			cur_nr_pages = gup_fast_pmd_leaf(pmd, pmdp, addr, next, flags, pages);
+		else
+			cur_nr_pages = gup_fast_pte_range(pmd, pmdp, addr, next, flags, pages);
  
-			if (!gup_fast_pmd_leaf(pmd, pmdp, addr, next, flags,
-				pages, nr))
-				return 0;
+		nr_pages += cur_nr_pages;
+		pages += cur_nr_pages;
  
-		} else if (!gup_fast_pte_range(pmd, pmdp, addr, next, flags,
-					       pages, nr))
-			return 0;
+		if (nr_pages != (next - addr) >> PAGE_SIZE)
+			break;
  	} while (pmdp++, addr = next, addr != end);
  
-	return 1;
+	return nr_pages;
  }
  
  static int gup_fast_pud_range(p4d_t *p4dp, p4d_t p4d, unsigned long addr,
-- 
2.50.1



Oh, I might even have found a bug moving away from that questionable
"ret==1 means success" handling in gup_fast_pte_range()? Will
have to double-check, but likely the following is the right thing to do.



 From 8f48b25ef93e7ef98611fd58ec89384ad5171782 Mon Sep 17 00:00:00 2001
From: David Hildenbrand <david@redhat.com>
Date: Sat, 6 Sep 2025 08:46:45 +0200
Subject: [PATCH] mm/gup: fix handling of errors from
  arch_make_folio_accessible() in follow_page_pte()

In case we call arch_make_folio_accessible() and it fails, we would
incorrectly return a value that is "!= 0" to the caller, indicating that
we pinned all requested pages and that the caller can keep going.

follow_page_pte() is not supposed to return error values, but instead
0 on failure and 1 on success.

That is of course wrong, because the caller will just keep going pinning
more pages. If we happen to pin a page afterwards, we're in trouble,
because we essentially skipped some pages.

Fixes: f28d43636d6f ("mm/gup/writeback: add callbacks for inaccessible pages")
Signed-off-by: David Hildenbrand <david@redhat.com>
---
  mm/gup.c | 3 +--
  1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/mm/gup.c b/mm/gup.c
index 22420f2069ee1..cff226ec0ee7d 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -2908,8 +2908,7 @@ static int gup_fast_pte_range(pmd_t pmd, pmd_t *pmdp, unsigned long addr,
  		 * details.
  		 */
  		if (flags & FOLL_PIN) {
-			ret = arch_make_folio_accessible(folio);
-			if (ret) {
+			if (arch_make_folio_accessible(folio)) {
  				gup_put_folio(folio, 1, flags);
  				goto pte_unmap;
  			}
-- 
2.50.1


-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/85e760cf-b994-40db-8d13-221feee55c60%40redhat.com.
