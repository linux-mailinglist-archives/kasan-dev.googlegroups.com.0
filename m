Return-Path: <kasan-dev+bncBC32535MUICBBD4KUCZQMGQEFRUXX4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id A35209034BB
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 10:04:33 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2c2dd8026dbsf2114914a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 01:04:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718093071; cv=pass;
        d=google.com; s=arc-20160816;
        b=znKDgVu/3R42riFSZnZ1YNyBsgUxj/DvZxqSTIvOwwn6swYeqxNheS/pLzHq1HZWAJ
         OPW1hwpbqhYOrIJIrVr5SEqLH9eurcwQnvefhw3gI87TqaYTSidnuG4jJbkK8oso1+Ti
         pO6H0Z42Dsvm9PYfUxnuSRZ3l4GTr8j3zOkfSfMIsN5R6vj4uRlrvCud6BQ6ky9n+2jt
         AHGIkYt0MWfcn2wjB3zTdLXFO1D8oPZIRFcJlZU86Wd3v0tZDaM/Bqp3bM+lrD6fOXaZ
         xk9DaQm+onTbEAVsIK9e3oQQRw5jl8z6N0o5WiYmJggYkfUgtBHq2heTgU07XasO+qNB
         JnpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=c7SelaXVD7mh5g+mY5LJN36QsAvPamPZWyf+1L4kCPQ=;
        fh=Wbvlpt4KjItq7igLc2zq5f5AisjhIzKPqN0K9GroCoQ=;
        b=ySlzz6ibSgMVy1vmuPNx09ZhJX6KumGDWXG8ILd/Uybrf2QnZoj7Ul1TzWF2hdbEwX
         +RwmmJMPviHjibboPb9sZAUcqVNGTeDk5EjOLnIVSXeCBiVnM7h+kZD3YwSaUTvbtnnr
         uqsanC/ISKoA+UKHaThGeJyjnmbY4NaOah4EHIPaKT9OoL4t89rMa2XHZk0Sal9/2Zh2
         +HULdzMnEXWJy8WMtDYOffl9PtXhq4znjSeNcU+Grt82pPUOUNjGHp4E6n2ZBCWOlzs9
         7yKZEoG1NhvfjE2S8UTEMpaged5GFZpq+s7MPyVK5EiMopaoqzt9A1AQTheT59lGOROU
         GahQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="V/iPQSba";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718093071; x=1718697871; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=c7SelaXVD7mh5g+mY5LJN36QsAvPamPZWyf+1L4kCPQ=;
        b=Yy8yzAWjMZCj05vwcXE6UzEV8vQUpPfuoYq5EOhsR08hNvxQiwruO1PGXWI+PmtlrF
         RiunC+kGLWNlHsRm1oKPKX8RAlsci4QSwE3O7Af8rY5JfQ1f/g9V2CkymRDCdbolgz4Y
         MsqlvjMisjIBiAzReYP8mTgjl3hF51hfqXdwr+Q9v7icRgNm669tfjY7NvypeeQev0vo
         S4DWG00KvuKAVq6LgaK8e78cV/pBysnE3Sixwd8IvHtWEamyvUDuCyZMUvPlYZsc2wXR
         uaAlInKUkhD8x1AaoSlvb0yfG7AOkrsrT7VGlGdTT4qLJBDPdZKze0vEjJs+8bXOh0wY
         TmlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718093071; x=1718697871;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c7SelaXVD7mh5g+mY5LJN36QsAvPamPZWyf+1L4kCPQ=;
        b=gccX8r7Ot38apPrIF8jfoMDJZ6UksbY+IG+Ed/z8kC8TPKUo8KjGAJGZ8bYIJCcjRh
         MjjGL4hxpSCuyGkLK3wOt6Ihrl99gcVnKnO8It9bMuCjBrUR28FSs2Ysn0DSHXQjf0YD
         6300srwCoC/LTwKazGs4RYIC9J9My7JXGIfc9FCqQ2mfefyBveDr//L9gkvMlmSvdM6/
         wUZaDks3D50KDDQIKalEgqOk17xTcUe9WqNmS3ICfxteFwtRQAdByT2Aljj1JKoSEYrW
         u7k1/OsTPf8oCWckiC4dUu4JryIUK8yp/Kp+2r1eOJpJaxlBjyCjUwmsWQ87pI2W8PdK
         9OZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVuDqXmEb89vJihbc/+rKokC1DvRo0AdFxNSopiHaoZNXazSjVFbupYBtk7XN+d5Ng521ZfzX7i826Q0Umd8cer3oFLT6KElA==
X-Gm-Message-State: AOJu0YxtHt6riyUERrR9kNdGUBFCdMsVcV+wODOztdAGnjmSx+xpxVq4
	pPsVjWEdSs2/sfNxV0TVbVB3zBRmDOOMs5+0hKDCbVERo3vwtfRt
X-Google-Smtp-Source: AGHT+IHk+muWLB9KiFV3+TTeiUWNf+gNU69GA2T2gUAPYcfwW+BV2iouhD5UMbeh6ML92k6vXNSQkg==
X-Received: by 2002:a17:90a:17ac:b0:2bd:d6c6:f454 with SMTP id 98e67ed59e1d1-2c32b518e4dmr2708249a91.21.1718093071329;
        Tue, 11 Jun 2024 01:04:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1e08:b0:2c3:34b0:9f with SMTP id 98e67ed59e1d1-2c334b0026els256200a91.1.-pod-prod-00-us;
 Tue, 11 Jun 2024 01:04:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWXLT5fJTzWKTlFYaGHzyTt3tRUuFEpu5caON8PUMVhETjx6Bw+/KQmdYDu51wjC5NQ3dOSSyXx077q1QCmaTTctTZGfQUjck+LPA==
X-Received: by 2002:a17:90a:7181:b0:2c2:e0f1:bb1 with SMTP id 98e67ed59e1d1-2c32b51ce9dmr2552990a91.22.1718093069932;
        Tue, 11 Jun 2024 01:04:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718093069; cv=none;
        d=google.com; s=arc-20160816;
        b=YXMw6RxPTCAKGlUe3vEg7SfRQHMVbUk+Q6jbuks64HFQLM59ebBIeeb1WDkAlFuUoL
         s6/oNLWYjyoO9rnqHj6pHopTtutlA+4oopGSNguZGPdf8qwp+ktkCKzsbsBsSYShGuC5
         33J1NzW1rVhlhpFiwoyIi5BAyWr9V1Ss2Za1IsvmMTUIWeV4SX9pjm97rxzHpD9xXL/f
         DwvbiTKRYWNlttAN3VvIaVGFweptm6H8BtB1THTr6wDT9Jz3pOjgP7D0laLkWaON8Nhe
         SdjMDjbAtU1NKWSSAfE2HwCqWkENZRzMMLusp++yeigMztN/xdE0WqBC9dExoMdPdThW
         Jv/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=hqXBYKFMfHuGo/oWXFTKDIQ0hmdU9g1oFp9QTADLe9k=;
        fh=5Fuo9NISap6YzSPGOAkPGD5qOl23uXwWYgAsgt8fX0s=;
        b=wGPbShM4awzXqwCqEQHaL8mk/1mWsvFXlvqWlnxTawlKryd/JQmEQYx9z7CgMOiClk
         ZY7P52f1J+PD0Mg9Qjp6lPAVIePLQRkO71mN1LO65F+USYxrbr5CezX70rKvH1NH5ifE
         uJQ1pTG/gTuH5qE39w5WkkrtOUHVaguoszVcNriystnz5S2wlbeJp18PIKtAhcXJyv9m
         5F4186Ch8uIi/CZifIdM3eDjelYhYQxSiLifsrnHuH3BpRNkvKbLA5wMP2B7+EceBRMP
         usZNJUuEEK6Aw1rmBNG5twevqwrkp+i4sUqMygeCb0JqZZ+BvbA3YsF7z0yUtpsHifHu
         J0lg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="V/iPQSba";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c2df95ab5fsi415685a91.3.2024.06.11.01.04.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jun 2024 01:04:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-lj1-f198.google.com (mail-lj1-f198.google.com
 [209.85.208.198]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-609--UU8s4UmM5eByd98hbbibA-1; Tue, 11 Jun 2024 04:04:19 -0400
X-MC-Unique: -UU8s4UmM5eByd98hbbibA-1
Received: by mail-lj1-f198.google.com with SMTP id 38308e7fff4ca-2ebd6b87ff5so21428531fa.0
        for <kasan-dev@googlegroups.com>; Tue, 11 Jun 2024 01:04:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV0VK6INlYB2z4Tb98Lt6NLV6+P1sp19ZFVHtRSjoy7kweVjP2oJBtSQ9gFQQe2nG9Gs5s5mQGVMiXNniXRC/v6rFWBiOiZX0wyxg==
X-Received: by 2002:a2e:87cb:0:b0:2eb:f82a:d8d2 with SMTP id 38308e7fff4ca-2ebf82adfe7mr159511fa.41.1718093058328;
        Tue, 11 Jun 2024 01:04:18 -0700 (PDT)
X-Received: by 2002:a2e:87cb:0:b0:2eb:f82a:d8d2 with SMTP id 38308e7fff4ca-2ebf82adfe7mr159231fa.41.1718093057647;
        Tue, 11 Jun 2024 01:04:17 -0700 (PDT)
Received: from ?IPV6:2003:cb:c748:ba00:1c00:48ea:7b5a:c12b? (p200300cbc748ba001c0048ea7b5ac12b.dip0.t-ipconnect.de. [2003:cb:c748:ba00:1c00:48ea:7b5a:c12b])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-42182ed2b23sm75337235e9.18.2024.06.11.01.04.16
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Jun 2024 01:04:17 -0700 (PDT)
Message-ID: <30b5d493-b7c2-4e63-86c1-dcc73d21dc15@redhat.com>
Date: Tue, 11 Jun 2024 10:04:15 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 2/3] mm/memory_hotplug: initialize memmap of
 !ZONE_DEVICE with PageOffline() instead of PageReserved()
To: Oscar Salvador <osalvador@suse.de>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-hyperv@vger.kernel.org, virtualization@lists.linux.dev,
 xen-devel@lists.xenproject.org, kasan-dev@googlegroups.com,
 Andrew Morton <akpm@linux-foundation.org>, Mike Rapoport <rppt@kernel.org>,
 "K. Y. Srinivasan" <kys@microsoft.com>,
 Haiyang Zhang <haiyangz@microsoft.com>, Wei Liu <wei.liu@kernel.org>,
 Dexuan Cui <decui@microsoft.com>, "Michael S. Tsirkin" <mst@redhat.com>,
 Jason Wang <jasowang@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
 =?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>,
 Juergen Gross <jgross@suse.com>, Stefano Stabellini
 <sstabellini@kernel.org>,
 Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>
References: <20240607090939.89524-1-david@redhat.com>
 <20240607090939.89524-3-david@redhat.com>
 <ZmZ_3Xc7fdrL1R15@localhost.localdomain>
 <5d9583e1-3374-437d-8eea-6ab1e1400a30@redhat.com>
 <ZmgAsolx7SAHeDW7@localhost.localdomain>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <ZmgAsolx7SAHeDW7@localhost.localdomain>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="V/iPQSba";
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 11.06.24 09:45, Oscar Salvador wrote:
> On Mon, Jun 10, 2024 at 10:56:02AM +0200, David Hildenbrand wrote:
>> There are fortunately not that many left.
>>
>> I'd even say marking them (vmemmap) reserved is more wrong than right: note
>> that ordinary vmemmap pages after memory hotplug are not reserved! Only
>> bootmem should be reserved.
> 
> Ok, that is a very good point that I missed.
> I thought that hotplugged-vmemmap pages (not selfhosted) were marked as
> Reserved, that is why I thought this would be inconsistent.
> But then, if that is the case, I think we are safe as kernel can already
> encounter vmemmap pages that are not reserved and it deals with them
> somehow.
> 
>> Let's take at the relevant core-mm ones (arch stuff is mostly just for MMIO
>> remapping)
>>
> ...
>> Any PageReserved user that I am missing, or why we should handle these
>> vmemmap pages differently than the ones allocated during ordinary memory
>> hotplug?
> 
> No, I cannot think of a reason why normal vmemmap pages should behave
> different than self-hosted.
> 
> I was also confused because I thought that after this change
> pfn_to_online_page() would be different for self-hosted vmemmap pages,
> because I thought that somehow we relied on PageOffline(), but it is not
> the case.

Fortunately not :) PageFakeOffline() or PageLogicallyOffline()  might be 
clearer, but I don't quite like these names. If you have a good idea, 
please let me know.

> 
>> In the future, we might want to consider using a dedicated page type for
>> them, so we can stop using a bit that doesn't allow to reliably identify
>> them. (we should mark all vmemmap with that type then)
> 
> Yes, a all-vmemmap pages type would be a good thing, so we do not have
> to special case.
> 
> Just one last thing.
> Now self-hosted vmemmap pages will have the PageOffline cleared, and that
> will still remain after the memory-block they belong to has gone
> offline, which is ok because those vmemmap pages lay around until the
> chunk of memory gets removed.

Yes, and that memmap might even get poisoned in debug kernels to catch 
any wrong access.

> 
> Ok, just wanted to convince myself that there will no be surprises.
> 
> Thanks David for claryfing.

Thanks for the review and raising that. I'll add more details to the 
patch description!

-- 
Cheers,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/30b5d493-b7c2-4e63-86c1-dcc73d21dc15%40redhat.com.
