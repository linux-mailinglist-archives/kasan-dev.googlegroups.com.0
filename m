Return-Path: <kasan-dev+bncBC32535MUICBBY7TYXCQMGQELHRP2EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EB4AB3B7EA
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 11:59:01 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-71e7181cddesf23366767b3.2
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 02:59:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756461540; cv=pass;
        d=google.com; s=arc-20240605;
        b=MkXuKRNROQDuAJRhSG46hwuNmpXN4GogSZdsvm5QSNakb9CgWeSIgzEN6JNRsxEw3y
         aIzV2wqf2yMfMaJzVOx1ZMjrjFrpa8njB90ybL3R43Xbho0c2+1KjFaw8vN9qI0R6nAr
         CE9lFyj7mxiTICLDOMv4SbVonMnuDKBRiovqM7CQ7HODuLKYkmMop+aAxZqeXr0Cguli
         jMOsqk+ThwvZrYVYr6SKgJ9YPRZIlVJGBb3UUl2f9o57YpLqJxidp5ggWPV1qX7vVAuD
         ztb4A7thAbqOLqpLNBHXFNEn9UIJIDC013DUQbtT2kdZxsM5vwCXMLSe4V7z0QmgzmcM
         orSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=Fo6V6JLX5jQV4OZQCQ9mhdrnaqNP1AukPh80bP67gd4=;
        fh=zX948vgcchoKqNxOk8hMdQGwVKafI5tEgn4HSwmoYZY=;
        b=GuPABgdWWhFPzAUmnOkndoI5NgMwou+5cYCTIhrhucBBRkxzbCtZUO9qbWQ8tQWQQt
         4CQgC1P+suTQwTa+GdUwIOASDqZTD25y48caHAGa7DjMPUvLyypLK+WrgJbtsuao0Awk
         eLv6NW1Gght8Q0Bknz+7HNFMqbG9MTR4oMiL9MOG9M3R4c7IHIXLXh9VLWlNPkpYBKxr
         5TvZG9Bac89Y5MfJw6SzQU4MBIis6IlB0+vUdSRiXIejkGl9BDC3VktW7YcPCqLpQOVT
         Emwj/6SeDVSNshfNzP+xJ+iZaNu2+CepEH0JCjssmEDEM6jSk+FxfugdGsOZwrgY4FZj
         UVTg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZuCuHfoW;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756461540; x=1757066340; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Fo6V6JLX5jQV4OZQCQ9mhdrnaqNP1AukPh80bP67gd4=;
        b=pIrxiHIccIJPRfQc0IzFBdses2TSVOK1UYXWMCySjJJeeXruB6LsyLLjpekJisdOEO
         RgJHME6UxHHvhx4+oWxan1ZxVzRbBbMsDs5zjzgAjsDO3fcYMzOhpNjmR2cSKYJSwaO4
         ii9cHJUN5++7Qa6CPUwHxoDqK6flLA1dmUko6OPkckJ+bUTSi1Sa/mFPRb8MkyemohOY
         C6jkm4o+4HyZOO61OcoxKj+A7ydy+ajb1J4LPPHy9P15CDyrisx5FoOiJeAcwwgfmro/
         V33CFhF4Lvowe1JjXt9ors9BJ5E0VA+rU82ppNCh/7vCWJmWH5Us4Oarb9YaYDkEh6CA
         hrpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756461540; x=1757066340;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Fo6V6JLX5jQV4OZQCQ9mhdrnaqNP1AukPh80bP67gd4=;
        b=Ky4SvFMJtntQ2IC8nWv01dRsv7z08QrATxT+OXW/iw2GI+sX7+JJ2Nhbme/6ytDWPW
         RQ45KzyoUFk23oB8kzRMKi1c8uS5vzcQcm42cHbjQCGQmbv5TVg6q3tuEHFWEv23MGcR
         eS2O94dYPRMzBQEV2M6oDupXEDgNtOusJClHpqHX/hefoaXbKiBm6KY8/Hxghx0kBZlL
         4oKl/Ah5F+y0m1goW4QlqYOZkKr3D+gcQXRvZISRCrq75+ib1IfZnlDymEzlTtAN+VE4
         1YoDT5Fd6llP/KsG+qyU6mpB0CcPa5jfzEGwvtDoLJxbXQEBMahH81qLuP1OBCR9qxSt
         mlJQ==
X-Forwarded-Encrypted: i=2; AJvYcCX6LMVrflTZJJmh6po1kaWTiio8n2PnQJQUpPAaR2f7ou/rtmPXKxPxIk+RtYTJgjZ76woFGw==@lfdr.de
X-Gm-Message-State: AOJu0YwlsqlxgildF0Z8V2iZPbEfxd2EWbQ4zFjcJU+c/I8QTKn8cEO6
	H9UNiPO9YB16r5PgGCdXqC8HMUVwSyjRHrRX5ayC3MT7AJGKkbr+Ggb2
X-Google-Smtp-Source: AGHT+IGIHh/6BMDX/ntsyEv1KikN++Mjnado8TCQM6byXiE4OjOCM/eES4sDhOXF6xR/6paTFtMwbA==
X-Received: by 2002:a05:6902:1884:b0:e95:32a9:908 with SMTP id 3f1490d57ef6-e9532a910b1mr22359805276.42.1756461539875;
        Fri, 29 Aug 2025 02:58:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc9O40ZNNcZ6Wb9iTp9R9LHibr82HXMEVxajYZeCqqzDQ==
Received: by 2002:a25:d8cd:0:b0:e96:e522:ae0e with SMTP id 3f1490d57ef6-e9700f51b42ls1433104276.2.-pod-prod-06-us;
 Fri, 29 Aug 2025 02:58:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWkKsq2Dn49Kz7PYxgVY2rSDOeungOVt33AKiWD9TMPsX5zf8gXfczqMaSAfvfOt7Lv1GB5Vaw9//s=@googlegroups.com
X-Received: by 2002:a05:690c:6d84:b0:721:6b2e:a0a0 with SMTP id 00721157ae682-7216b2ea54bmr39567507b3.3.1756461538213;
        Fri, 29 Aug 2025 02:58:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756461538; cv=none;
        d=google.com; s=arc-20240605;
        b=WSttg+0dXq6OPM+4Pykp7pUw75qwJ/aSVrEQgbiQguUxlcopc7salXBPwW8ZJRAtrF
         38atKdZSMc3Zi0nikycfY7iOsOsEB+wW0l9DjxkqxsnGPbNmbCB7OYDb515ihBHZ0inz
         oE5jyYAyZA8m2p0zMXckMx5T2J9RaqvMtoc9+/dwd+DD/3tRYJkXVyLgJvJtB6SixyvS
         sdz9CiFcz1OEuqU7M1M/DNOhT3xGRXCjqYaV3VNf7DCdgtP4EDk1eMuSBcAouCfBVTJS
         +UBiCFUWbH1awhucb1oMJHLkONIahtcVO76xgcGAP/UP6x7xiGDNdoq01E1kNlgQDHZ0
         WP8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=CIYlE8yYA+z63gvbmepekc4lArepb/yuA3iZBVH5fy4=;
        fh=8XniAi1XGOmmPgKOOYyOm30fvupL9wjIrvD0WcGbPVs=;
        b=iSvsrgu3Sq2IiBh80a+7Uq2Ht8AmEXh7pBHt7yzJJchouxj9dQ2T6fIAMH5li8mVYQ
         DkNsiF+ICA/L/Sl9GSntN7dJF5L2WM/M8UBf/GSHkOB0jBflyFQ/c9LikuFKtccbPyQI
         2bmuowQjB3BUfqlj+WtUbYpulc2jiFj16zOxPJ6ab0tM2jFl5MsBqnBU7YL+DfTxi1mq
         Z7OzYN9hDc5ftbTJsQipFxC1vSdx0DgvkUX2yxZOMiN7ULpE+8eSrDJeB/qt15bAWMwA
         pHmxAAcof63sIu8DZmZea6GG4QS5FkTiwd4aofONq/COvhCCG+9q9jnH5CU+RxhmzeXh
         JD7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZuCuHfoW;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-721ce605a5dsi826717b3.4.2025.08.29.02.58.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 02:58:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-553-sUqk-zymNmWokGhCYjZ4tQ-1; Fri, 29 Aug 2025 05:58:54 -0400
X-MC-Unique: sUqk-zymNmWokGhCYjZ4tQ-1
X-Mimecast-MFC-AGG-ID: sUqk-zymNmWokGhCYjZ4tQ_1756461533
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-45b80aecb97so2904595e9.3
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 02:58:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW2U62e1HrWZj/aM7NFCzlFPltzBad/G2pyKCxvZWbkPM1LeO2hgCQuMcvlAPxWlcR7wJ15Rs7chwk=@googlegroups.com
X-Gm-Gg: ASbGncuEELPtvXc/YvvYtTXPBH3Vy2l+uSDnPghXMnoH42TV7jWZQLj5EKMt9P7eUB0
	HsM8BXLctN4Zq6gtqMGarfP00XvsS1fxprb+Q+Sy1GorJXlUSoioP7dINsi3j4VXitdPhFImpeN
	OTxLP624C5mTCS3nvftyrYsJmLry/0dDL7SxJg674ns+jaHTH2qXeKfdg19dOEGSdyRyuRn1fSy
	oahtuAZQ0Yki+O02NO03vkJ5rY8h6WlWeiJK8t1+Q1DLq4AeYhIiYENqYhDUv81gni/+oG9Usem
	FVAsAA0CH01gEmIvBBvIyCoB30gxp7gJRDFUB8w/JL2+6E3XicJ6RuMXRxwSr1vbQShZovSWmtR
	ZszdDRN81+9oCU57bp042efGl176RJuWN2ORDwfiuRmrdwTPS8eEeMBC2Z+v2tmXX
X-Received: by 2002:a05:600c:35d0:b0:45b:7f72:340 with SMTP id 5b1f17b1804b1-45b7f720599mr16993505e9.25.1756461532882;
        Fri, 29 Aug 2025 02:58:52 -0700 (PDT)
X-Received: by 2002:a05:600c:35d0:b0:45b:7f72:340 with SMTP id 5b1f17b1804b1-45b7f720599mr16993185e9.25.1756461532358;
        Fri, 29 Aug 2025 02:58:52 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b7271cd01sm102235695e9.23.2025.08.29.02.58.49
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 02:58:51 -0700 (PDT)
Message-ID: <6a2e2ba2-e5ea-4744-a66e-790216c1e762@redhat.com>
Date: Fri, 29 Aug 2025 11:58:49 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 06/36] mm/page_alloc: reject unreasonable
 folio/compound page sizes in alloc_contig_range_noprof()
To: "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
 SeongJae Park <sj@kernel.org>, Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
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
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-7-david@redhat.com>
 <3hpjmfa6p3onfdv4ma4nv2tdggvsyarh7m36aufy6hvwqtp2wd@2odohwxkl3rk>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <3hpjmfa6p3onfdv4ma4nv2tdggvsyarh7m36aufy6hvwqtp2wd@2odohwxkl3rk>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: mYJhpZoK9_l_iIM_zW0XdFOtJ69uG1wlT27n3me7oRU_1756461533
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ZuCuHfoW;
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

On 29.08.25 02:33, Liam R. Howlett wrote:
> * David Hildenbrand <david@redhat.com> [250827 18:04]:
>> Let's reject them early, which in turn makes folio_alloc_gigantic() reject
>> them properly.
>>
>> To avoid converting from order to nr_pages, let's just add MAX_FOLIO_ORDER
>> and calculate MAX_FOLIO_NR_PAGES based on that.
>>
>> Reviewed-by: Zi Yan <ziy@nvidia.com>
>> Acked-by: SeongJae Park <sj@kernel.org>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
> 
> Nit below, but..
> 
> Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>
> 
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
>> index baead29b3e67b..426bc404b80cc 100644
>> --- a/mm/page_alloc.c
>> +++ b/mm/page_alloc.c
>> @@ -6833,6 +6833,7 @@ static int __alloc_contig_verify_gfp_mask(gfp_t gfp_mask, gfp_t *gfp_cc_mask)
>>   int alloc_contig_range_noprof(unsigned long start, unsigned long end,
>>   			      acr_flags_t alloc_flags, gfp_t gfp_mask)
>>   {
>> +	const unsigned int order = ilog2(end - start);
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
> 
> You have changed this from an int to a const unsigned int, which is
> totally fine but it was left out of the change log.  

Considered to trivial to document, but I can add a sentence about that.

> Probably not really
> worth mentioning but curious why the change to unsigned here?

orders are always unsigned, like folio_order().

Thanks!

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6a2e2ba2-e5ea-4744-a66e-790216c1e762%40redhat.com.
