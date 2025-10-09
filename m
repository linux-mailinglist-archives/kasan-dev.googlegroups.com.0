Return-Path: <kasan-dev+bncBC32535MUICBBU5ETXDQMGQE2QZOMVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 35FE5BC77FF
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 08:12:38 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4e231785cc3sf3269801cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Oct 2025 23:12:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759990356; cv=pass;
        d=google.com; s=arc-20240605;
        b=j3YiM3KdK+DM3/f6fik86Y2IB8e0a8FlkPjXlCbcj6Q6Us7r4mcr4wUvF6H51jx7jt
         dKDHJ+ja6PysNBwWK5hCbxDTDvCVh2YyGvtleYqQ62/lalWVO2sAVzJdTF6JBtsW+cTB
         Fop6eziwd8Z85Uh/ABqxHqz5am1YXgZVUJbpx2oyl6il3OM80bn3NwWVt/fdMWplzgEC
         /A9iVRqCemvbsAZoxwd1obCpLswsb+zPG85q2f9NqTahZVohHYPp8aYnzjFsnfT7oUla
         +1c7uCIMfLky/QBLkOfhPu7eJg87zTCkreJWdzWr0lY4B2HRRgxj2b7+cpGUf7+z9qQ1
         Wc5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=uMm26gJ9AKUT3vwoAt2CjkHMeD+MMP1mBYRs31XGMaY=;
        fh=NQZYB3T9/PDJHHG4ilBD68r+GfT9IKNCyNXK+uZXF4o=;
        b=K89uNqUCdFRiZr9lIL7C7wudeJJVY9nWSd8w0AXAjO4kjtMIVC343eEIcDKuDtMdnS
         HN57+J+22+bP45NQ2/MC7BTmBcvseJJthj/fVuIdvJwJcaS16F8rjQY1xzqvxWHWdeIF
         RYVAB4DX48L2Z8Co2LhxCZMQjfJZN7bG2umC7oLCb+jRFcgGBA/LQp7ArU9+bX8FNMHK
         VeaFfQ5CJKMP9eG4qPg8BLcjpWWjjYFMIY5ZEqdSnaFQC9weQNpmEpfI/C6ljoGFhQQP
         o8dKpnqDPwsJTrgzqKShg5w3TjvEHQYECw6gw7SIHoJGcnFo4poOoNdU+BQ1Ofq9Er6H
         AJOg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=CbmIGXve;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759990356; x=1760595156; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=uMm26gJ9AKUT3vwoAt2CjkHMeD+MMP1mBYRs31XGMaY=;
        b=rfQq8N5mvuumWQtm8pGaMB/GpzVvGrNJd7CE478V2dTC08kBWWuaj4Rs/qJcT3efr+
         LkKXl8/Z7uQ5rp7zYRKxIAh8d+sOdPoANEcEJdJ32fkGryLSzfw8bUEWv7BXbMJx4Lk3
         ZHIRjD3cN2x1WHlTjdm0kwjkWwhNsMGL0wDRH9GCe3LIWunXtnn0zUMm5QwV6fvCoxLK
         HVO4A7NSyYpzumquHzhK13fQgquxDmNdFaYs2Sqr+pRd3CIEjWlYt8X6a1fsObpMy5a3
         vZ4yu5y8vgGpFjRDf5Qf8AjIgYtBfR+ZJTACDIO5kSSrxzNI1a0mEgo/XJgdc/Pu43dG
         YEQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759990356; x=1760595156;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=uMm26gJ9AKUT3vwoAt2CjkHMeD+MMP1mBYRs31XGMaY=;
        b=gsw5XvEAMU8Mp+z5R2x9YWPMoe1CpgHVfDd9n7XNVoU/RiL5g8aMGKotKAA3mAXgCW
         TxNPTwXsPilYugWPWQU3v+mrWsfKdNLxwkBAGz73dU6B9oQoAifWmsVuCRdEQQwPUXwy
         vpA8Y0oSr22hAOoM7bFEsgXJQ2Sk+rzY5dd10pSnY/tQF48MNT8orsXwwEkixyYwkDnf
         j9j374iD0pSnQlYFEBITvcgJ+mvmzqYKu4OlXxi7eEr9pM4W7P8gosWS2Ao6RByho9q5
         MDB6q+vwokqXAEausiIvWTG9GAbtkEkPjQWjrtzkVPkC+kl+MtsDfb+Zn0uRcxfOhmAO
         B2DQ==
X-Forwarded-Encrypted: i=2; AJvYcCWXMK+TL9kx12oZieTBYDDPs667qwQuAO2EvK55DksMQ5LKoCpCUukX//j13MEEM6WXrM23vw==@lfdr.de
X-Gm-Message-State: AOJu0Yz9QQB5g1dGhkiH2m01/DyxWVRnrJTKyAglqE8OWmkk9YWzBq3g
	+GpN79VwW4FMmNXgwoSZjM6WHOU4sV9Qxv0VY+I6niMMrb5EExGcUNrM
X-Google-Smtp-Source: AGHT+IFm9wHDdsBsiMEv9OwZuphsXWphkgR1NIIFg+rOYUl5w5Z8dKEHOVlY+ZlTKPaRVMapeJt+xg==
X-Received: by 2002:a05:622a:60c:b0:4d9:ac87:1bdc with SMTP id d75a77b69052e-4e6ead0aba7mr58676721cf.6.1759990355911;
        Wed, 08 Oct 2025 23:12:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5hNjaKWqSKnm+nk+7c67DApGIQh4z+7fezDiqKcwys8Q=="
Received: by 2002:a05:622a:a6c6:b0:4d0:cdd7:addc with SMTP id
 d75a77b69052e-4e6f8bbc572ls11041541cf.2.-pod-prod-09-us; Wed, 08 Oct 2025
 23:12:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVMN94eE/RpdDSFGKH3eI7cqZBuWm8e29ZjAQcii3iIgDiaQV4/f30eHEe2PmfJgm3y+S9EZpgUh/s=@googlegroups.com
X-Received: by 2002:a05:622a:1e99:b0:4d7:3fe2:721a with SMTP id d75a77b69052e-4e6ead54bc7mr82012121cf.47.1759990355047;
        Wed, 08 Oct 2025 23:12:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759990355; cv=none;
        d=google.com; s=arc-20240605;
        b=erVIwhK8FI82jxooBWLUiyjU5ZF69Ylzh90X5pUokfAFa6W81hlVEPyah8LsNjoxbs
         q6CwPv1Lpn4ll3U1EcIb+0lYq5uQaFXmCIY3Q3/VRJfpfQ/8xTSfqv1oEc1HtWPIqbxm
         iPSvBz/ESiiWsG+n0JZp0haBEU6tTnwAGASfKlUcTcfxgFcw6DEl3AXUmM312sd2CQfw
         usYgpfmlt4C7lskYMGHp1DVW1bokBspZ4/bf/XFHivwuO+UVuJNnrbsEIREqW872wkrO
         3qkZU3v2Ry8QjlJ6UXQXzzSETPe+ldXVhkdIMSEpWRVBhN7m2TetAzaTzvRz8bYqt0U4
         gWmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=NRkB3HnbXEauvObRKfhLALPNCnH0LKvnQC+gj83VPV0=;
        fh=z9ocFUDjVkA6205plV3W5xf5VomogeXGJxOuVNER1wg=;
        b=a+7b7sFUFe4VlpAnGCfOKcNY/Mcmg7mX5KCMittQqkJmz0+00LArdCylysm/7Yac3x
         bX/aZToDEo1HR6EckzdLfdW2ruEmN9bEkiW97FF3ShRDLz/Gd6+GI9TqiTPPMwGt0hRw
         9dO910lRVsrLupTYNObWCgFOfShfUw/2zIE8CtiuJf/gSFQFRs6ba/1RlY+P3ZMrXiFD
         C0aiuki2GhY5+MefuaLC3XmhwqRI5jdtCQbb9+VSmj4etkCIa5IyCMgpIsGU2h3QJbDz
         9qJDQ6bLtm7ncQysC5v46R4Z7P10j9uMReRuJNaqsmRfceabkZSZPratu3tFltEGDOMN
         rcCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=CbmIGXve;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8849f6bedf2si11320385a.1.2025.10.08.23.12.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Oct 2025 23:12:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-647-WiJVezygMUKMC20mfGSCAA-1; Thu, 09 Oct 2025 02:12:31 -0400
X-MC-Unique: WiJVezygMUKMC20mfGSCAA-1
X-Mimecast-MFC-AGG-ID: WiJVezygMUKMC20mfGSCAA_1759990350
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-46e36686ca1so5715885e9.2
        for <kasan-dev@googlegroups.com>; Wed, 08 Oct 2025 23:12:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUfTNig2/2gdSDZkKbGPOImv2f4ZREeKdYNOEMi/moZvgAhxVo2xbu87aavJ2Nbu/ASsjsW15aAVCY=@googlegroups.com
X-Gm-Gg: ASbGncueQysjM89TLoZEF/lK4Wz9UAEIMAO2CS5ot+SUMUjv6bBhh11ZH3ndNTBw47/
	EZtXSj/fefxgfef8WR9L2UjXLvV/EgTHFPMxNg8IcUYuWBU6P51QeOle5uq1wP7H17ucCajRWBQ
	mIJ4MYQgpnmWeMSfOggKCMsgj4dkKcpdUhCKx0cpgnFHT2Zdw4R1Uol1EBJdrzWnS4j1/r65IFz
	vbAwfYR9Gvqukhjy0eBw4p7F1hHo8QA2WJxiEurnWcbi4JQSL1evFfDEzyRc+X2UlrASaLBr/MC
	10zgYbVeRw+0sncDG/BCeIJwlJF50i7ujb25ymgLmgo40jnRXPBQPe2fpD6/t3dg+LLoMqu7imw
	IvKvAFXw6
X-Received: by 2002:a05:600c:34cc:b0:46e:59dd:1b4d with SMTP id 5b1f17b1804b1-46fa9aa2076mr63277595e9.16.1759990350185;
        Wed, 08 Oct 2025 23:12:30 -0700 (PDT)
X-Received: by 2002:a05:600c:34cc:b0:46e:59dd:1b4d with SMTP id 5b1f17b1804b1-46fa9aa2076mr63277065e9.16.1759990349745;
        Wed, 08 Oct 2025 23:12:29 -0700 (PDT)
Received: from [192.168.3.141] (tmo-083-189.customers.d1-online.com. [80.187.83.189])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-4255d869d50sm33971611f8f.0.2025.10.08.23.12.26
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Oct 2025 23:12:29 -0700 (PDT)
Message-ID: <5a5013ca-e976-4622-b881-290eb0d78b44@redhat.com>
Date: Thu, 9 Oct 2025 08:12:25 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 06/35] mm/page_alloc: reject unreasonable
 folio/compound page sizes in alloc_contig_range_noprof()
To: Balbir Singh <balbirs@nvidia.com>, linux-kernel@vger.kernel.org
Cc: Alexander Potapenko <glider@google.com>,
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
 <20250821200701.1329277-7-david@redhat.com>
 <fa2e262c-d732-48e3-9c59-6ed7c684572c@nvidia.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <fa2e262c-d732-48e3-9c59-6ed7c684572c@nvidia.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: 70kaVtcPOf02VCJ7SXrsFrAHLmh3DXQue42evNyuFTI_1759990350
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=CbmIGXve;
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

On 09.10.25 06:21, Balbir Singh wrote:
> On 8/22/25 06:06, David Hildenbrand wrote:
>> Let's reject them early, which in turn makes folio_alloc_gigantic() reject
>> them properly.
>>
>> To avoid converting from order to nr_pages, let's just add MAX_FOLIO_ORDER
>> and calculate MAX_FOLIO_NR_PAGES based on that.
>>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
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
> 
> Do we need to check for CONTIG_ALLOC as well with CONFIG_ARCH_HAS_GIGANTIC_PAGE?
> 

I don't think so, can you elaborate?

>>   #else
>> -#define MAX_FOLIO_NR_PAGES	MAX_ORDER_NR_PAGES
>> +#define MAX_FOLIO_ORDER		MAX_PAGE_ORDER
>>   #endif
>>   
>> +#define MAX_FOLIO_NR_PAGES	(1UL << MAX_FOLIO_ORDER)
>> +
>>   /*
>>    * compound_nr() returns the number of pages in this potentially compound
>>    * page.  compound_nr() can be called on a tail page, and is defined to
>> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
>> index ca9e6b9633f79..1e6ae4c395b30 100644
>> --- a/mm/page_alloc.c
>> +++ b/mm/page_alloc.c
>> @@ -6833,6 +6833,7 @@ static int __alloc_contig_verify_gfp_mask(gfp_t gfp_mask, gfp_t *gfp_cc_mask)
>>   int alloc_contig_range_noprof(unsigned long start, unsigned long end,
>>   			      acr_flags_t alloc_flags, gfp_t gfp_mask)
>>   {
>> +	const unsigned int order = ilog2(end - start);
> 
> Do we need a VM_WARN_ON(end < start)?

I don't think so.

> 
>>   	unsigned long outer_start, outer_end;
>>   	int ret = 0;
>>   
>> @@ -6850,6 +6851,9 @@ int alloc_contig_range_noprof(unsigned long start, unsigned long end,
>>   					    PB_ISOLATE_MODE_CMA_ALLOC :
>>   					    PB_ISOLATE_MODE_OTHER;
>>   
>> +	if (WARN_ON_ONCE((gfp_mask & __GFP_COMP) && order > MAX_FOLIO_ORDER))
>> +		return -EINVAL;
>> +
>>   	gfp_mask = current_gfp_context(gfp_mask);
>>   	if (__alloc_contig_verify_gfp_mask(gfp_mask, (gfp_t *)&cc.gfp_mask))
>>   		return -EINVAL;
>> @@ -6947,7 +6951,6 @@ int alloc_contig_range_noprof(unsigned long start, unsigned long end,
>>   			free_contig_range(end, outer_end - end);
>>   	} else if (start == outer_start && end == outer_end && is_power_of_2(end - start)) {
>>   		struct page *head = pfn_to_page(start);
>> -		int order = ilog2(end - start);
>>   
>>   		check_new_pages(head, order);
>>   		prep_new_page(head, order, gfp_mask, 0);
> 
> Acked-by: Balbir Singh <balbirs@nvidia.com>

Thanks for the review, but note that this is already upstream.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5a5013ca-e976-4622-b881-290eb0d78b44%40redhat.com.
