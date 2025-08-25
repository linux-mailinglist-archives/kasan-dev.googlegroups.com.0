Return-Path: <kasan-dev+bncBC32535MUICBBHE4WLCQMGQE6M62BWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id CE267B34730
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 18:23:57 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-3111d74dbefsf16022889fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 09:23:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756139036; cv=pass;
        d=google.com; s=arc-20240605;
        b=CPq7orTbNQ10RLKPW1NnZtxjYYcPB6849svi6huT16AfnLC+8zAWzSlZxLa8AGLlCW
         bTrmQXdCjnpyRdnC63jyvIyiNmqQfLCVNuBcU51XRZEeu+Yw+0A1qE0V4Jvqy5FrmKz3
         tUjPkQjJbYCPvMjJcuh+467nBNH+T8LmZRfYLN6p62CzKz1s5XWBFUPtLS6qvU0WEAiI
         OE8qeLT2jPB1/0vWqTdzCOCN8LgsmA2eiJkq75blbEM35x9jCK86Mj3gpuPZhqptQsDr
         tlhGyV55h/qLzEiHSs3FG5gAX+eaR5gf/psFPnGNUwVwGeIuXrAg1mQNqteHUnOhJabm
         iRwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=ZrAuvWAc3QtsbqnycIZGyuTTwnUYM+WaXKJPA1yDOkU=;
        fh=IjMyyBj/kV2S5Q2PNALgTGBJgVZVF7l14DLIqm+Ck3E=;
        b=ewLJL5UFQb0hjIINJB1jFMfAR9+Qxd8uJ+dFYp88atbeLZ/mQReukqOxRhlQlNyyc7
         PK1aMzzPWt6haDdhzkGT3JP7tzPxbXQqGGPSiBdGmwhqYTZp2N2nFqkmsYMI81ZwsKLD
         ROc58fBRp8ikKRzW138APX3Nej+ZPwOfvLbJQQMbiWjpTR+t6m+gLdw31Jo6J2+qmAPF
         52BjT669xdoe4dSw+YWPa62c1ZDoP9nTfmhX8X/lBHILJTm8WWk/f2esE97JjVx0Tyzm
         NY/BcCVUyeKMCv47qxJavEL2np64agCzIZnNaqB7ixx3NxpFfShCMfrNF5RFuTrzWptW
         hr2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=LpdWRuxS;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756139036; x=1756743836; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=ZrAuvWAc3QtsbqnycIZGyuTTwnUYM+WaXKJPA1yDOkU=;
        b=NVd7ly609nslsW5qDGnJ5Gvy1hnDo7w8DdM5G7s0BKhbnjEj3GPBuQGrpd7oLsFAzU
         0x14nGf67rgkWljdZBq0O6ZeTuMVoVnyXC83w5JXZktglL+xbbyPtnxoHB7YwfFI7RuG
         BwueEBJp+ebKmtYJLC17zyaxXd0uPKTjs2CtaCdOXRVKfs1J5PdZ6rFwWy5nodcaheVh
         TK3gCZ/qV7A+Et8K+MmyS6NHoSphIicFTWaGinJujXEjQe0z/GTggf2pBl0ViGXafJRb
         7azIEuudLi3S8eDD2OiP87FBfxuzoVaCppuogU+VsRHSXJgdeEmlU0AfD89mHQXC8BYK
         i5XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756139036; x=1756743836;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ZrAuvWAc3QtsbqnycIZGyuTTwnUYM+WaXKJPA1yDOkU=;
        b=HGC2rMJa40is1/GK4q7euqGPcfy8geYs2HTGrpvLtrhThYsosBWDCNGTqnnJHyF5p1
         IYuQhcVNJ+jF4xIJPEsZjvr38VTz7y+uz+feKOpKRVMcJKpZMgerkraXBwFS/j4Po9KK
         7WcKw3FEsgN3o91yZLiLsa15457lZmOd6Ukbb6wXe8+vGX6Wepdxy4rjJdk1D1lsbZnw
         a7T0M8+QbwunoInd63hrOx5dmsHZWPhLNhW1CAy2lYwqnp25P0njyhb6Yp7GszXmglVX
         SE6UAUuhtNKNq747BsArDgBrga8dAJl6rXRzxJ74q7i4Jih/ijqpi4/YHS2sAxdvnf7m
         +Wpg==
X-Forwarded-Encrypted: i=2; AJvYcCWQ2cSn1CpImKh6adBURxtulYkYMO0yY9PenYR6/fZ3VCMdX8+PFj6i8Ah+bkQVTKWZGFUH/g==@lfdr.de
X-Gm-Message-State: AOJu0YwmWWW5nEBAOwQIN8giIsCOmSPGC1ZDhrLVCBi9an9nvzRKAnlO
	QtZugKlmPR97lURXoWkao7imGmpkjqDiiRvV2ZkYeAsNK7ey0zpmwA46
X-Google-Smtp-Source: AGHT+IEvZwGHvbxW9C8KGUPV3q8f0VUhflhdrip2u4lra7LAEKaRHlLgemoQSqMwMJi4MfZqdKXlXg==
X-Received: by 2002:a05:6870:2145:b0:30b:733d:516c with SMTP id 586e51a60fabf-31543841f2emr73856fac.2.1756139036481;
        Mon, 25 Aug 2025 09:23:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeUBcT+EfO+HPNglmYNB+RtSfYXK1l36AQRSf5bQjD0Tw==
Received: by 2002:a05:6870:7029:b0:30c:93bb:6f15 with SMTP id
 586e51a60fabf-314c23448e6ls1055069fac.2.-pod-prod-00-us; Mon, 25 Aug 2025
 09:23:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX57rj0T6Y1pxaEi+CIUxm2Xc/tmdyWRYUseXtNZCm3pSz+D1e62MBANsJW2+gBh9/81dFEs99IztM=@googlegroups.com
X-Received: by 2002:a05:6871:7824:b0:314:9687:6dca with SMTP id 586e51a60fabf-31543b1cf38mr93643fac.20.1756139035387;
        Mon, 25 Aug 2025 09:23:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756139035; cv=none;
        d=google.com; s=arc-20240605;
        b=OHEYzQo1JpQq7Wo0Nidwc+H2GJlzoGy8G5uMwwuJGqug/ZRuwpB+4RiuSAyRV/FwLv
         ZucTRhlhkk0/Etbzp7i+t2xFF9yk67eHIJZ7AmOJS1q6/0Xw7VqpFAdlUXmgHoJ5vVK7
         +FrPi49rukJCentbrRODAet2CmWawGrzYc4XHZ6IdtIO5DlD95N7VZdPxwJpZy3zcoFI
         fDRotcTjLsvfseVB4KYYfjPxy/Zg1Ed6PTttbSTh4mCsvlyTTlrBxcMLDD/PnMsxbckK
         TSMss9IpWSgnPaYnNki8ySUvjghslxqd6Xw2zjXiw0pDYqTkMqV0XTZUnNGGO0nHeon5
         1oHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=ZJ9VR6/AHZevQeWHrHcSWQbnm5iFaXQGfgpXOMo3AYo=;
        fh=m8UIwH5cAx8r+lqa6KxnsSqzKehPUZKXsxIZrbMNt/U=;
        b=SKaPW+E6y23qoms3tpvHY5bdCcjUleBJu2SNdsX5Ovvi7HOJOpjOrAsWkk0K0LANgh
         ob0EJ17kzXY3oEEE/voA9iKYmR6iIrqzIXRaPsS57MNKyXsSzj4fDaCptyLab4lR0EBK
         p8ZCdqNHUmc8wMGUc4UoOO6jlthCput8v/HQe15yIoSpAtAfMOEpN71bnSTZ34R+tdRX
         S14ZvpmcHL8bDyQPpR+oQDrptVVWDIAHeCDcNWufphDdMll62buWYueFD3dzJzQaKlQy
         E8U7NbIN1/8PpuM1Ro2zgwHvkwAdSGz/heazv33WuvEL7Wy/ltNlNzjfz9uRjaPR+YzK
         hqbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=LpdWRuxS;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-314f7bc3b10si298073fac.3.2025.08.25.09.23.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Aug 2025 09:23:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-252-si-D9XcoNl2XpaCu_ubgHg-1; Mon, 25 Aug 2025 12:23:53 -0400
X-MC-Unique: si-D9XcoNl2XpaCu_ubgHg-1
X-Mimecast-MFC-AGG-ID: si-D9XcoNl2XpaCu_ubgHg_1756139032
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45b612dbc28so7294365e9.0
        for <kasan-dev@googlegroups.com>; Mon, 25 Aug 2025 09:23:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWwvA/iK5Mzd0uWJPrRk91UIjzaFEQVyVHwwnDQdmp4JIBtkPgVVLkZPDG+Yu+1GHNsQm5Ae6LlQR0=@googlegroups.com
X-Gm-Gg: ASbGncuXpUCd9WFqdUEkaa/4CUfsokYDsais9MOWCt1b/knn36k4/2q02VXlRJeMpJa
	nqJkqGVLL9KH23wAfqvRVkWLVlm4V0XI5sHjtUXHq7U8hsYRhR3MtbqTYODbfM6itFmxxDtTBmn
	FXRk1lrM1NzCE/nlDjBvbpBjiawhVa57BAydX826ENwI9It37JJBhNOsxPn73JHOulvMMwfqfZo
	2j/xPqETr4A9dkwDiwYUc0I9CFXxtJXru6HypadqtkPAnvRjw4AAiroPzxjzi3paPfqtlJkwBsl
	076nyyaYoU3MStcP51Aisf8FttjxSbxG65ducJBpse/J0KOIUQHK/4GHpn+ENdi3fmsQhRHA9lq
	43l80/U+FU+oH9jvLePQtm276MPncJqfKCl5DsJpmJ5U1jipBPZ59Twe9VXYsF5ZaPKY=
X-Received: by 2002:a05:600c:4685:b0:458:bfe1:4a91 with SMTP id 5b1f17b1804b1-45b517c5551mr109881615e9.20.1756139031876;
        Mon, 25 Aug 2025 09:23:51 -0700 (PDT)
X-Received: by 2002:a05:600c:4685:b0:458:bfe1:4a91 with SMTP id 5b1f17b1804b1-45b517c5551mr109881195e9.20.1756139031315;
        Mon, 25 Aug 2025 09:23:51 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f4f:1300:42f1:98e5:ddf8:3a76? (p200300d82f4f130042f198e5ddf83a76.dip0.t-ipconnect.de. [2003:d8:2f4f:1300:42f1:98e5:ddf8:3a76])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b5fec8e80sm29037215e9.0.2025.08.25.09.23.48
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Aug 2025 09:23:50 -0700 (PDT)
Message-ID: <dbd2ec55-0e7f-407a-a8bd-e1ac83ac2a0a@redhat.com>
Date: Mon, 25 Aug 2025 18:23:48 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 10/35] mm/hugetlb: cleanup
 hugetlb_folio_init_tail_vmemmap()
To: Mike Rapoport <rppt@kernel.org>
Cc: =?UTF-8?Q?Mika_Penttil=C3=A4?= <mpenttil@redhat.com>,
 linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
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
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-11-david@redhat.com>
 <9156d191-9ec4-4422-bae9-2e8ce66f9d5e@redhat.com>
 <7077e09f-6ce9-43ba-8f87-47a290680141@redhat.com>
 <aKmDBobyvEX7ZUWL@kernel.org>
 <a90cf9a3-d662-4239-ad54-7ea917c802a5@redhat.com>
 <aKxz9HLQTflFNYEu@kernel.org>
 <a72080b4-5156-4add-ac7c-1160b44e0dfe@redhat.com>
 <aKx6SlYrj_hiPXBB@kernel.org>
 <f8140a17-c4ec-489b-b314-d45abe48bf36@redhat.com>
 <aKyMfvWe8JetkbRL@kernel.org>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <aKyMfvWe8JetkbRL@kernel.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: zvsF4_Exqz8SiBtZLw1PtcX5kQW9xFFQTJrVNLqO95w_1756139032
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=LpdWRuxS;
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

>   
>> We should do something like:
>>
>> diff --git a/mm/memblock.c b/mm/memblock.c
>> index 154f1d73b61f2..ed4c563d72c32 100644
>> --- a/mm/memblock.c
>> +++ b/mm/memblock.c
>> @@ -1091,13 +1091,16 @@ int __init_memblock memblock_clear_nomap(phys_addr_t base, phys_addr_t size)
>>   /**
>>    * memblock_reserved_mark_noinit - Mark a reserved memory region with flag
>> - * MEMBLOCK_RSRV_NOINIT which results in the struct pages not being initialized
>> - * for this region.
>> + * MEMBLOCK_RSRV_NOINIT which allows for the "struct pages" corresponding
>> + * to this region not getting initialized, because the caller will take
>> + * care of it.
>>    * @base: the base phys addr of the region
>>    * @size: the size of the region
>>    *
>> - * struct pages will not be initialized for reserved memory regions marked with
>> - * %MEMBLOCK_RSRV_NOINIT.
>> + * "struct pages" will not be initialized for reserved memory regions marked
>> + * with %MEMBLOCK_RSRV_NOINIT if this function is called before initialization
>> + * code runs. Without CONFIG_DEFERRED_STRUCT_PAGE_INIT, it is more likely
>> + * that this function is not effective.
>>    *
>>    * Return: 0 on success, -errno on failure.
>>    */
> 
> I have a different version :)
>   
> diff --git a/include/linux/memblock.h b/include/linux/memblock.h
> index b96746376e17..d20d091c6343 100644
> --- a/include/linux/memblock.h
> +++ b/include/linux/memblock.h
> @@ -40,8 +40,9 @@ extern unsigned long long max_possible_pfn;
>    * via a driver, and never indicated in the firmware-provided memory map as
>    * system RAM. This corresponds to IORESOURCE_SYSRAM_DRIVER_MANAGED in the
>    * kernel resource tree.
> - * @MEMBLOCK_RSRV_NOINIT: memory region for which struct pages are
> - * not initialized (only for reserved regions).
> + * @MEMBLOCK_RSRV_NOINIT: memory region for which struct pages don't have
> + * PG_Reserved set and are completely not initialized when
> + * %CONFIG_DEFERRED_STRUCT_PAGE_INIT is enabled (only for reserved regions).
>    * @MEMBLOCK_RSRV_KERN: memory region that is reserved for kernel use,
>    * either explictitly with memblock_reserve_kern() or via memblock
>    * allocation APIs. All memblock allocations set this flag.
> diff --git a/mm/memblock.c b/mm/memblock.c
> index 154f1d73b61f..02de5ffb085b 100644
> --- a/mm/memblock.c
> +++ b/mm/memblock.c
> @@ -1091,13 +1091,15 @@ int __init_memblock memblock_clear_nomap(phys_addr_t base, phys_addr_t size)
>   
>   /**
>    * memblock_reserved_mark_noinit - Mark a reserved memory region with flag
> - * MEMBLOCK_RSRV_NOINIT which results in the struct pages not being initialized
> - * for this region.
> + * MEMBLOCK_RSRV_NOINIT
> + *
>    * @base: the base phys addr of the region
>    * @size: the size of the region
>    *
> - * struct pages will not be initialized for reserved memory regions marked with
> - * %MEMBLOCK_RSRV_NOINIT.
> + * The struct pages for the reserved regions marked %MEMBLOCK_RSRV_NOINIT will
> + * not have %PG_Reserved flag set.
> + * When %CONFIG_DEFERRED_STRUCT_PAGE_INIT is enabled, setting this flags also
> + * completly bypasses the initialization of struct pages for this region.

s/completly/completely.

I don't quite understand the interaction with PG_Reserved and why 
anybody using this function should care.

So maybe you can rephrase in a way that is easier to digest, and rather 
focuses on what callers of this function are supposed to do vs. have the 
liberty of not doing?

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/dbd2ec55-0e7f-407a-a8bd-e1ac83ac2a0a%40redhat.com.
