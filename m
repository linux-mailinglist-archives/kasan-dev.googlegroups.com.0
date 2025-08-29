Return-Path: <kasan-dev+bncBC32535MUICBBFXVY3CQMGQELIKCDCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id D9005B3BDE1
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 16:35:03 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-30cce848d95sf1275668fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 07:35:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756478102; cv=pass;
        d=google.com; s=arc-20240605;
        b=F7Eg1ve8m3iO2OzBjPMQ9h3ytdDkPXmgjMBDsEOfqERsJq/GFm+oStYAVc3upOCD9D
         rHbeT8ZgaP8VEmnZxTPDPG51Pe+3H3jHekjGTn4TpczK1OM6kL/iI5kB6ClW9glNoWNr
         rvPr1JC6pi7e7ywDioKvswSxS+0X19+GazEK/xFRidJaKnDhF/Mw9EQEInGxqVWGBKMA
         9NKRv3PHzKPc1+XfeNSDjJrVaZGDcKogBsagmbglZoncN/3zppbu2f7r8u8CaYY+cSZT
         kBOWkFOJmAmfeKF8AusRoFIFHZRwWCNmmmHOq5G+zV9U6EPrlE8S0K/KUYhL5nSYPL/E
         F5bQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=J2D0+SsVZhRtvh3NQm9OEwiiZAi+5ymCN1eRX836eng=;
        fh=pM39p2fnGzAN1GYRob0yRDwWVEKb1R78JHimqL1XzeE=;
        b=T94YHaGR29QiDYHQ3LBbRvDL9w8FFVTI7/bTxo8BNhfO/Qhsk4Ed1Z5BWVNm58xK2k
         j/bEqg6wAChsN0yi5+m+odjf7o4AiwMRvBfD4aLSRPoLm9yl04nMvsieV4Thzi+HjJbi
         plhzVnIeeAST7VqNovDAD+2I5QXo2ohwi1Dkxhq39vL1rKWfFNlG1rEj37aglqGLuUXw
         jMnkH7Fs7+/qD4NZRxnZXHRVr5KcPA0ELH0uWpkMxhj0usUMh8zeowuvUBhtt8ckGcLR
         x0iWUHk8C+OjHAAYWBXm9xNsewFgrX6v8ByF81/rxUgk1pgVMTHYmzHG+chIPBYAoOzE
         V8Rw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Fk8yoWI4;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756478102; x=1757082902; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=J2D0+SsVZhRtvh3NQm9OEwiiZAi+5ymCN1eRX836eng=;
        b=ZuW9p44mefjxyPE1SuLRdJJabhzVpw87KQzvFePypmNBVIPoJzPuu+pjl7OYJXK9pI
         O1m/tOLTQ8S+dOYRyyIzOtTADJw5ilxPUjNmcjjhzRXYHQr17dnIeTHlaBJt8NsnaExb
         gUQjlUKhAOX2PI18GO5q/5BU7TyI/0Uu27il4N/PSk8ee1aIjZh1qwiQn9IFAQYdSZio
         JOHIzbqwM6a/SRxjIheYhsHUmPnUYh+oy55vL3rwUbOG7kaqWOaI1aNhVO5r+Q449DJY
         bzQAYoDwMHgvepdvsXOpmM8ADHwybb6hbJm3ajidbjqDUmZOnsHpPrpfx3XVZlzlAF/x
         qWNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756478102; x=1757082902;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=J2D0+SsVZhRtvh3NQm9OEwiiZAi+5ymCN1eRX836eng=;
        b=fBe5q1TAnWgtRL0Dz/u7dCf2cQ/0QsPvSMSWymHhHCesEGKmb2lmDfeuOotO2Cs2bL
         43zzAzJUtO8YHVdyJAICRkGpqCuVDAZb21xdRkzFaIe5iBWcu2/tdefNMeLKJkLQjmPz
         QPV3Z4GtYpw+ZsXb6cWNgtXF+UrW2fYiInE/TwF2+jNtitz0rDytXYAS5Ft1nZaqHdbA
         Frofvsyv5M2X2SVJhqLoRmwjJXWTTUoYbHRfP/5W4Ek0mxD1bCxE5NY8N6Iq2ssTf7qO
         8cfNtc/QIbtOL9wU1IQ22hq3R69RQUHxEvZ2q/h8NnpaAjy7gkY051GS4aBamRlEnm9F
         QvlQ==
X-Forwarded-Encrypted: i=2; AJvYcCWrqh2zyCk/J8dJCJh8U2O6+TqoD9yjoP7HWOOb7dR3o9vnLcCyix++DIgf3YgjsBPsQ0SO9A==@lfdr.de
X-Gm-Message-State: AOJu0YwijI/jf5G6b9XHEGW5a5DOu1PbPxVDCJVjkhLr6PR8g0hJiaFd
	BGH3K5WTmIMRFCFaYc4p+cbFESwLxULmgxawzFGZBSZr7Iu8leAKYT+k
X-Google-Smtp-Source: AGHT+IFvIQji9YiGt8duxHTnP7PJeTKOfpZzZ4MpEXZKwpJD0rura4fFw3FQeYGAQ3OPP1z+aJDimw==
X-Received: by 2002:a05:6870:5693:b0:315:7222:d4e4 with SMTP id 586e51a60fabf-3157222e5e9mr5140554fac.23.1756478102192;
        Fri, 29 Aug 2025 07:35:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdA5iFMGKY0h3+9A8irhmPYHt0t7PeF3rZ7URKTYExlIg==
Received: by 2002:a05:6870:9a8f:b0:30b:cb7c:ba90 with SMTP id
 586e51a60fabf-31596322e99ls893939fac.2.-pod-prod-02-us; Fri, 29 Aug 2025
 07:35:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVoP8XhJXTeJT7py4h9AGnzPCoIwKgvt0+HST2h9tx9eeD36McD5qyT2NacpWTtbXbiydqPMLwQx4g=@googlegroups.com
X-Received: by 2002:a05:6870:88a0:b0:30b:85e1:d3d3 with SMTP id 586e51a60fabf-314dcd408b6mr13371952fac.32.1756478101040;
        Fri, 29 Aug 2025 07:35:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756478101; cv=none;
        d=google.com; s=arc-20240605;
        b=b1EZFJh92kHFhxnZWGTzOtHHzESwRgdQd2FB1DTFEZ+Ju+UmuJZ/h24QAsvZJdBoLn
         gO8Ae/F6knEu6F521fmUzDHomoE82l4dIkl1QIHYRmr6lUN1vNB85X/l+Vc5OO9/o5PB
         gM6mOJR3kFviaDhuv9uBJMNcVV1I6TxyTB1V3rklPUHUqVwbFDdg7s9h6s3o4R1xJL5s
         PJ1oFsboLHK5+4EWPcXZ7J+iiZ+CckLIXLipxuDRQ3wRrCTpNArwCLN/UIWa+5FEgMWn
         49Sby2PaF1N1AI70Uom2CkO1ajKMjclI05+ACm1rbAYKX0ritTI8rblUS3Q2COo9cjwl
         doNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=hfIlMYGAPM5qq+lZD1SPgFCFfaNMq7ewyyxdxPY6Oa8=;
        fh=Qbm8KqGGVsWCWjMv4TRbJLlwMDCnNQnivBTPIXuCVDg=;
        b=E7KNUe1bX1E3Q65d1mlPus9erAVV9O63STc7TKupgEtETVGWw79x9lDWvjadeQUfQ6
         N9yzVJC1g3bj0lnbFWGkBRqVnfYjkfyvdu8U39PGzHqs6Bc/RGX5DLdFvpUC9sv90Beo
         znfQ4mWZFc+dlvZJ50BzbG87JqDHolpnC8SdNvlQb3XZVcx/awO+0Szeg54hEdLUASwQ
         CNRHSfYC3PcDE615milAvy4qFXfztDYef/x7vT/PXIdTl1ZrMYHeEDas5IlJeIgGXuLh
         8WZIiFABgfJIBUXGingtKtuQgvXLajVSWQcMofW898MyS9kb1doIjWc6iRYWM6GPx14v
         diuQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Fk8yoWI4;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-315afdefa46si132556fac.3.2025.08.29.07.35.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 07:35:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-417-Fb1WO9FEPoKOzW4HyvxSBw-1; Fri, 29 Aug 2025 10:34:59 -0400
X-MC-Unique: Fb1WO9FEPoKOzW4HyvxSBw-1
X-Mimecast-MFC-AGG-ID: Fb1WO9FEPoKOzW4HyvxSBw_1756478098
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45a1b05d31cso10806495e9.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 07:34:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVTi/ZfXEdSEpP57aap2r6ZPqPsu0zyygAK9x3xlf61U1jUpbvAcxh9VYtuJ+/xHDZnoENaBh2AvLc=@googlegroups.com
X-Gm-Gg: ASbGncuYJArnN4xsNGAwfIgpuxpKPqfl0pfOfqht3rRqtYZ95VggrjhJM5+QLdkk6XU
	L/qaZorWJlKSgxthv4YDwVev++pSB4uLyPbGqun8HU0nKp8lthXJp9vs4Vtp7qCkltpblsT/pU6
	G26g9AhW6uNo7XETKAZiCnCHoO+H+KsDzUJGh6D2XG4YOhDwPLXznRnI48g7Rq0qoPDEbt3jinH
	OexWW0dr/v4PS2xLJrmBJNbiiDDA882ixIq+LIP3E6gpxfAufxGJ2D9oezRvuPOK0994bDnPzwk
	vFKlFeqmJD40QhX8+FUFOH43gv5rwsEElKVKln5pSaUUC5Ikdu9vKiq5J3YTPpSGnnaBHH42BU1
	WAQVwPu4REz3smn9M0XLNS4h0ifqXuNBH1zSIpNDsxPshV1PF819P2wLvqXF4azwn
X-Received: by 2002:a05:600c:198f:b0:459:db7b:988e with SMTP id 5b1f17b1804b1-45b517a0878mr226233875e9.13.1756478097751;
        Fri, 29 Aug 2025 07:34:57 -0700 (PDT)
X-Received: by 2002:a05:600c:198f:b0:459:db7b:988e with SMTP id 5b1f17b1804b1-45b517a0878mr226233525e9.13.1756478097177;
        Fri, 29 Aug 2025 07:34:57 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b6f0d32a2sm134907275e9.9.2025.08.29.07.34.55
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 07:34:56 -0700 (PDT)
Message-ID: <62fad23f-e8dc-4fd5-a82f-6419376465b5@redhat.com>
Date: Fri, 29 Aug 2025 16:34:54 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 21/36] mm/cma: refuse handing out non-contiguous page
 ranges
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: linux-kernel@vger.kernel.org, Alexandru Elisei
 <alexandru.elisei@arm.com>, Alexander Potapenko <glider@google.com>,
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
 <20250827220141.262669-22-david@redhat.com>
 <b772a0c0-6e09-4fa4-a113-fe5adf9c7fe0@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <b772a0c0-6e09-4fa4-a113-fe5adf9c7fe0@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: uM5xxacRs84grhvNMjv1tE0ZI-vq3v-AKrvjYWC5DwY_1756478098
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Fk8yoWI4;
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

On 28.08.25 19:28, Lorenzo Stoakes wrote:
> On Thu, Aug 28, 2025 at 12:01:25AM +0200, David Hildenbrand wrote:
>> Let's disallow handing out PFN ranges with non-contiguous pages, so we
>> can remove the nth-page usage in __cma_alloc(), and so any callers don't
>> have to worry about that either when wanting to blindly iterate pages.
>>
>> This is really only a problem in configs with SPARSEMEM but without
>> SPARSEMEM_VMEMMAP, and only when we would cross memory sections in some
>> cases.
> 
> I'm guessing this is something that we don't need to worry about in
> reality?

That my theory yes.

> 
>>
>> Will this cause harm? Probably not, because it's mostly 32bit that does
>> not support SPARSEMEM_VMEMMAP. If this ever becomes a problem we could
>> look into allocating the memmap for the memory sections spanned by a
>> single CMA region in one go from memblock.
>>
>> Reviewed-by: Alexandru Elisei <alexandru.elisei@arm.com>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
> 
> LGTM other than refactoring point below.
> 
> CMA stuff looks fine afaict after staring at it for a while, on proviso
> that handing out ranges within the same section is always going to be the
> case.
> 
> Anyway overall,
> 
> LGTM, so:
> 
> Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> 
> 
>> ---
>>   include/linux/mm.h |  6 ++++++
>>   mm/cma.c           | 39 ++++++++++++++++++++++++---------------
>>   mm/util.c          | 33 +++++++++++++++++++++++++++++++++
>>   3 files changed, 63 insertions(+), 15 deletions(-)
>>
>> diff --git a/include/linux/mm.h b/include/linux/mm.h
>> index f6880e3225c5c..2ca1eb2db63ec 100644
>> --- a/include/linux/mm.h
>> +++ b/include/linux/mm.h
>> @@ -209,9 +209,15 @@ extern unsigned long sysctl_user_reserve_kbytes;
>>   extern unsigned long sysctl_admin_reserve_kbytes;
>>
>>   #if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
>> +bool page_range_contiguous(const struct page *page, unsigned long nr_pages);
>>   #define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
>>   #else
>>   #define nth_page(page,n) ((page) + (n))
>> +static inline bool page_range_contiguous(const struct page *page,
>> +		unsigned long nr_pages)
>> +{
>> +	return true;
>> +}
>>   #endif
>>
>>   /* to align the pointer to the (next) page boundary */
>> diff --git a/mm/cma.c b/mm/cma.c
>> index e56ec64d0567e..813e6dc7b0954 100644
>> --- a/mm/cma.c
>> +++ b/mm/cma.c
>> @@ -780,10 +780,8 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
>>   				unsigned long count, unsigned int align,
>>   				struct page **pagep, gfp_t gfp)
>>   {
>> -	unsigned long mask, offset;
>> -	unsigned long pfn = -1;
>> -	unsigned long start = 0;
>>   	unsigned long bitmap_maxno, bitmap_no, bitmap_count;
>> +	unsigned long start, pfn, mask, offset;
>>   	int ret = -EBUSY;
>>   	struct page *page = NULL;
>>
>> @@ -795,7 +793,7 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
>>   	if (bitmap_count > bitmap_maxno)
>>   		goto out;
>>
>> -	for (;;) {
>> +	for (start = 0; ; start = bitmap_no + mask + 1) {
>>   		spin_lock_irq(&cma->lock);
>>   		/*
>>   		 * If the request is larger than the available number
>> @@ -812,6 +810,22 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
>>   			spin_unlock_irq(&cma->lock);
>>   			break;
>>   		}
>> +
>> +		pfn = cmr->base_pfn + (bitmap_no << cma->order_per_bit);
>> +		page = pfn_to_page(pfn);
>> +
>> +		/*
>> +		 * Do not hand out page ranges that are not contiguous, so
>> +		 * callers can just iterate the pages without having to worry
>> +		 * about these corner cases.
>> +		 */
>> +		if (!page_range_contiguous(page, count)) {
>> +			spin_unlock_irq(&cma->lock);
>> +			pr_warn_ratelimited("%s: %s: skipping incompatible area [0x%lx-0x%lx]",
>> +					    __func__, cma->name, pfn, pfn + count - 1);
>> +			continue;
>> +		}
>> +
>>   		bitmap_set(cmr->bitmap, bitmap_no, bitmap_count);
>>   		cma->available_count -= count;
>>   		/*
>> @@ -821,29 +835,24 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
>>   		 */
>>   		spin_unlock_irq(&cma->lock);
>>
>> -		pfn = cmr->base_pfn + (bitmap_no << cma->order_per_bit);
>>   		mutex_lock(&cma->alloc_mutex);
>>   		ret = alloc_contig_range(pfn, pfn + count, ACR_FLAGS_CMA, gfp);
>>   		mutex_unlock(&cma->alloc_mutex);
>> -		if (ret == 0) {
>> -			page = pfn_to_page(pfn);
>> +		if (!ret)
>>   			break;
>> -		}
>>
>>   		cma_clear_bitmap(cma, cmr, pfn, count);
>>   		if (ret != -EBUSY)
>>   			break;
>>
>>   		pr_debug("%s(): memory range at pfn 0x%lx %p is busy, retrying\n",
>> -			 __func__, pfn, pfn_to_page(pfn));
>> +			 __func__, pfn, page);
>>
>> -		trace_cma_alloc_busy_retry(cma->name, pfn, pfn_to_page(pfn),
>> -					   count, align);
>> -		/* try again with a bit different memory target */
>> -		start = bitmap_no + mask + 1;
>> +		trace_cma_alloc_busy_retry(cma->name, pfn, page, count, align);
>>   	}
>>   out:
>> -	*pagep = page;
>> +	if (!ret)
>> +		*pagep = page;
>>   	return ret;
>>   }
>>
>> @@ -882,7 +891,7 @@ static struct page *__cma_alloc(struct cma *cma, unsigned long count,
>>   	 */
>>   	if (page) {
>>   		for (i = 0; i < count; i++)
>> -			page_kasan_tag_reset(nth_page(page, i));
>> +			page_kasan_tag_reset(page + i);
>>   	}
>>
>>   	if (ret && !(gfp & __GFP_NOWARN)) {
>> diff --git a/mm/util.c b/mm/util.c
>> index d235b74f7aff7..0bf349b19b652 100644
>> --- a/mm/util.c
>> +++ b/mm/util.c
>> @@ -1280,4 +1280,37 @@ unsigned int folio_pte_batch(struct folio *folio, pte_t *ptep, pte_t pte,
>>   {
>>   	return folio_pte_batch_flags(folio, NULL, ptep, &pte, max_nr, 0);
>>   }
>> +
>> +#if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
>> +/**
>> + * page_range_contiguous - test whether the page range is contiguous
>> + * @page: the start of the page range.
>> + * @nr_pages: the number of pages in the range.
>> + *
>> + * Test whether the page range is contiguous, such that they can be iterated
>> + * naively, corresponding to iterating a contiguous PFN range.
>> + *
>> + * This function should primarily only be used for debug checks, or when
>> + * working with page ranges that are not naturally contiguous (e.g., pages
>> + * within a folio are).
>> + *
>> + * Returns true if contiguous, otherwise false.
>> + */
>> +bool page_range_contiguous(const struct page *page, unsigned long nr_pages)
>> +{
>> +	const unsigned long start_pfn = page_to_pfn(page);
>> +	const unsigned long end_pfn = start_pfn + nr_pages;
>> +	unsigned long pfn;
>> +
>> +	/*
>> +	 * The memmap is allocated per memory section. We need to check
>> +	 * each involved memory section once.
>> +	 */
>> +	for (pfn = ALIGN(start_pfn, PAGES_PER_SECTION);
>> +	     pfn < end_pfn; pfn += PAGES_PER_SECTION)
>> +		if (unlikely(page + (pfn - start_pfn) != pfn_to_page(pfn)))
>> +			return false;
> 
> I find this pretty confusing, my test for this is how many times I have to read
> the code to understand what it's doing :)
> 
> So we have something like:
> 
>    (pfn of page)
>     start_pfn        pfn = align UP
>          |                 |
>          v                 v
>   |         section        |
>          <----------------->
>            pfn - start_pfn
> 
> Then check page + (pfn - start_pfn) == pfn_to_page(pfn)
> 
> And loop such that:
> 
>    (pfn of page)
>     start_pfn                                      pfn
>          |                                          |
>          v                                          v
>   |         section        |         section        |
>          <------------------------------------------>
>                          pfn - start_pfn
> 
> Again check page + (pfn - start_pfn) == pfn_to_page(pfn)
> 
> And so on.
> 
> So the logic looks good, but it's just... that took me a hot second to
> parse :)
> 
> I think a few simple fixups
> 
> bool page_range_contiguous(const struct page *page, unsigned long nr_pages)
> {
> 	const unsigned long start_pfn = page_to_pfn(page);
> 	const unsigned long end_pfn = start_pfn + nr_pages;
> 	/* The PFN of the start of the next section. */
> 	unsigned long pfn = ALIGN(start_pfn, PAGES_PER_SECTION);
> 	/* The page we'd expected to see if the range were contiguous. */
> 	struct page *expected = page + (pfn - start_pfn);
> 
> 	/*
> 	 * The memmap is allocated per memory section. We need to check
> 	 * each involved memory section once.
> 	 */
> 	for (; pfn < end_pfn; pfn += PAGES_PER_SECTION, expected += PAGES_PER_SECTION)
> 		if (unlikely(expected != pfn_to_page(pfn)))
> 			return false;
> 	return true;
> }
> 

Hm, I prefer my variant, especially where the pfn is calculated in the for loop. Likely a
matter of personal taste.

But I can see why skipping the first section might be a surprise when not
having the semantics of ALIGN() in the cache.

So I'll add the following on top:

diff --git a/mm/util.c b/mm/util.c
index 0bf349b19b652..fbdb73aaf35fe 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -1303,8 +1303,10 @@ bool page_range_contiguous(const struct page *page, unsigned long nr_pages)
         unsigned long pfn;
  
         /*
-        * The memmap is allocated per memory section. We need to check
-        * each involved memory section once.
+        * The memmap is allocated per memory section, so no need to check
+        * within the first section. However, we need to check each other
+        * spanned memory section once, making sure the first page in a
+        * section could similarly be reached by just iterating pages.
          */
         for (pfn = ALIGN(start_pfn, PAGES_PER_SECTION);
              pfn < end_pfn; pfn += PAGES_PER_SECTION)

Thanks!

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/62fad23f-e8dc-4fd5-a82f-6419376465b5%40redhat.com.
