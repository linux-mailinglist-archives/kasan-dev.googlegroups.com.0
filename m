Return-Path: <kasan-dev+bncBC32535MUICBBRPW7PCQMGQEBXFQSOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id B2D1BB49439
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:50:30 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-3253fdac880sf5351573fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:50:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757346629; cv=pass;
        d=google.com; s=arc-20240605;
        b=MDYzjtrv1jbSKuYzGt5a/7Bd7HWWcsRPiLXwmrcNZHD0JMWc5TOU9U0bP7YnLz8kb8
         U++n8y4sYA1Bx8ATzz//SMjdQtu5vkSE3MB4cdmyPOlYgJMD00mZycF7jad9mhxIWTGY
         pKJ+6yQEY7/BcFSPeDxhMPGhi0/gOrpEy90UyDTcHG3rQ1GKONplNWYHbv7UlJpWwsfx
         GcL9K/nNOXYJ1neoe+V42PwfPISG0g1Y9Ej1SU2ZkGhhtGZzIdlTK6hUJUTpbpCsqlE6
         r+XuacJ1CJK0E6N7R6DV0Ph+3pEVbKDQtHnA2kXP9YNWB2vUGakuuYpShpRREEpX/3Mf
         FwuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:references:cc:to:from:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=PLv1pFnb6xXvpoA1dOYZWFUm99QOB50VMERe9qxIOlY=;
        fh=VwW2S2v/CXrfCZI43UwBaYPltOUqLu43RsPtwdAEmCc=;
        b=k722/E3aLTsVRHvbc+oeIzB797/5HF442OfGxHpr6AUOLRQoJm7vQJTP2BBtzRAXZ1
         SE/8KHCLzb9KsGtDcXtJsHo/iBblI6f7VfzyzX8kI39DB/cIrYY9JFz88raCkKjudPFN
         /AKjtTivPEe+DeeR87vuRgtWV5YOZw6AfS5TtetfH/dzOckW78X2igsgNVGuWI4SUI6O
         HU0cOnQ80ief0Cz0xGMBxoi80dWl6U1EgRDFYabk171I9rW7ayfIazv4F03Q7f1vrAmZ
         1iZ6byMq8IEdeLX3iQ61IGSmia8WMSwh0NZUb7RCQWD6Y4Eta888U667hgh5zAMAoaOL
         hwYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Vm9Jcf4F;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757346629; x=1757951429; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:references:cc:to:from
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=PLv1pFnb6xXvpoA1dOYZWFUm99QOB50VMERe9qxIOlY=;
        b=RhDZi/zhQBRcPqmILVdKhYdeGQKwDE8lNtIoFRHeyt/AS46dBV5q74QI3K8RM/9qrY
         EQR7UCqRPXREJ2KEAmVahsjzRYV7nBp74iXEmqa8rlO3NShj3FM4uexSKxwNMaA8ONAD
         C8nTBALalWWQBLUMFR/31VdhcCHc8EgyAmYiQzsESNoNBOsuPikgVZe6WlVQtyYZ+y2O
         /+aTDPucLOLn4YonBXMZ2p+iiG9amBOWHZa6LLfI/SxY0d5Sk0Jl6nzi9vDpgGwaYzjF
         seDNME5ZL8qGga05eQnO4USNAPefx9gJ8SoTpIqvN0uPxIn6qrjyMD3sLWsVCw4NQAdk
         OqpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757346629; x=1757951429;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:references:cc:to:from
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=PLv1pFnb6xXvpoA1dOYZWFUm99QOB50VMERe9qxIOlY=;
        b=m9AzCVUOiE2Ml7YbDlJ5NTQJsCmGP0sMZzJul5+7PxHcjdMP4hxmVD4MuSpFrEOMCB
         FT8gvms6EJQ59E8uaBWdjJTRE3I6+5sMnGe5ThKR44igvJ8wg9QaoLYkqAhnnurFaWig
         zLLRFC5XxurCjSq8ATeJHx6eV1Co/zuCTYzwTZBKG/Mia8TQdVvYaNqyxc6q5lhj5IA4
         9ixyyHQZ/3ytpZibs/Nl7DQ8XlXMpxJ/9RfpShE2/SLKGW+NXRnNuE9ACH4iSZ9j5kYi
         VyzyGIxXffHbcpYMW/dEsHpPNCdcow0/6z7grHzYGpMlBgImI1ZU7892sYWMeB3HvPCf
         qUQQ==
X-Forwarded-Encrypted: i=2; AJvYcCWWtdSzd3+ANhkLmKjBejqFOGBfC1yvD4RKiv9mWjE5PS+PIolOf599xGzIpsPClCejD7Qfgw==@lfdr.de
X-Gm-Message-State: AOJu0YzInrpVonBYgNsNf6tmGuIFOH6bmQqKDYf4xrvF1TZZcuee4N7H
	PCvXVh489hGHz7pK+J227o4c1A9DVrLRhVEH6iIqDv0CX7WpC+Lxdoi/
X-Google-Smtp-Source: AGHT+IGBrzMceK+imgOxaCHtU/uqheaOBpL0dk4jRBG4e4BgKpGMkt2eqQA84wtt5A3Ao2GFnc/1Pg==
X-Received: by 2002:a05:6870:3043:b0:30b:b123:b6c9 with SMTP id 586e51a60fabf-32262d9225emr3688457fac.12.1757346629349;
        Mon, 08 Sep 2025 08:50:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5BUKmKlGHMCiiPesDcr6fIemAo1kRQl0C6ZdnOreMS9Q==
Received: by 2002:a05:6870:79a:b0:30c:c0b:fe9d with SMTP id
 586e51a60fabf-3212692fe22ls1873027fac.0.-pod-prod-03-us; Mon, 08 Sep 2025
 08:50:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXANY96FHsXgQv/1muLDsfp6lWU55L9QwF1MoqO9eSIGhNvZqzf7fsiAJn+B6ph5MhUQ60/MSFBIxw=@googlegroups.com
X-Received: by 2002:a05:6870:9713:b0:319:c3d3:21cb with SMTP id 586e51a60fabf-32264c1b7e3mr3526800fac.28.1757346627385;
        Mon, 08 Sep 2025 08:50:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757346627; cv=none;
        d=google.com; s=arc-20240605;
        b=AIJmedcMjr7n8Tw9VbYdy9pozi71UHEurPYYgaTS0sAXny9EnBjO1p+8mUXn7jh9bF
         TN16bZ0pX+y0H02UqgHUSoMPQE52M4RV5bIflgk+ZR0o6KcSabklihARRys8pnDGpJEY
         tpnl0997B1xxmCOshq2poSTph5MyqUiIbRgaLGtdjbIARvQ3B8GlNgYV5m9hPWdT+DL7
         g5EKgPovUak34ySYpZzJyKS+gKnSHBy9eoEY8kUgY+KJDZ4blZthYsY/erwp9ErGmXrx
         ZboWKjhzLRzeQfW/TP/npgWAydD/amBNXhlmoRkAzuzr6YbfKYwRcXAEEnrECAWyc5My
         PKhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :references:cc:to:from:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=yRW3ZVdYmN/Kdh0wLmiEq7GLlrJxKlfpeCG0COnVkik=;
        fh=x+n8TjoRB3FUq93UmZbCqETwB6WhjA63CZyps7n6FkM=;
        b=a/jqoRibcgZoMux6YAVFOv+tsXl2Pl9FT2D4RlrSdKOU6f52rgCipoKQORzi54CKvh
         37sb/NuBewMAYd+3a2BfEW+kbBD9SLdEMmdYVF0eG5hk+p5HxSJe1QbOMUSDygec0dPC
         J6fjPkaI82hL2CkenYPNF/IaPcXVakNVqQG74KG4sNkaOV3BufpiwTZ5OZ/I8tPPRhXH
         1kA5/AE2c0fWhH2trh/r3GOH5L8ZTNWR9TUWWv9nVCOhWZllMosUKjqr24qYwmxLghH9
         8GKTud1/MEVeWcF6zjhYoETd9HMXSSSSz01UKXoM+t++gDVmwngKrygjjSaivwqYfeEY
         WUAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Vm9Jcf4F;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-31d895ec2c8si434825fac.4.2025.09.08.08.50.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:50:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-345-cXmIHVzxOWS3kVd6_EqIug-1; Mon, 08 Sep 2025 11:50:23 -0400
X-MC-Unique: cXmIHVzxOWS3kVd6_EqIug-1
X-Mimecast-MFC-AGG-ID: cXmIHVzxOWS3kVd6_EqIug_1757346622
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-45dd66e1971so30647865e9.2
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 08:50:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVNXTUjzgq7o4Z7YPvax5bSUqOHKS3M/p9IyYu3wdX4zxiftoOfakdPIxekX3P/O9OH0l6034z/Vws=@googlegroups.com
X-Gm-Gg: ASbGnct7ZpeXb5Razc7lxm7YTLKD96j/TknHMMWfV2B5pYvA/NKh9jOIhHu524rK+zn
	GsDfkrKBv2ZFQGZrT3kHpUa7jf0c3hAZsoqbGJu5fG+MREl9pwin2OI/QeakOjHX+yS6CFXq7Il
	5C2LBn65uSrFrOHtye8muU66sTgK9TPnfV82t9JYuOMkJndJchZjtRLG4PDiUZqQxkBBb8daLqc
	/g+/nQALPT+keEHmO2hmgWyoJBWF1JV2eFLHVX366SsKUgVi1DtlBKW8I/6sfIKigL7/tN6kmae
	+m2G2TEMdGxmmh7wS4FMDGr8fKaMwIxO5OvCMrMIpA7LvmujSkinx7BspxVQ7k1ctqQHPypFplp
	7pkJvxwyB/VsCIUE3PfdDxMFjgPwa2/r6udDpPwcvTKvStrT4qZ2k7oqUhS7xQtZP
X-Received: by 2002:a05:600c:4e14:b0:45b:86ee:415f with SMTP id 5b1f17b1804b1-45ddde8a741mr84356005e9.6.1757346622244;
        Mon, 08 Sep 2025 08:50:22 -0700 (PDT)
X-Received: by 2002:a05:600c:4e14:b0:45b:86ee:415f with SMTP id 5b1f17b1804b1-45ddde8a741mr84355495e9.6.1757346621708;
        Mon, 08 Sep 2025 08:50:21 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45dd0595af9sm100737155e9.2.2025.09.08.08.50.18
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:50:20 -0700 (PDT)
Message-ID: <3229ac90-943f-4574-a9b8-bd4f5fa6cf03@redhat.com>
Date: Mon, 8 Sep 2025 17:50:18 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 03/16] mm: add vma_desc_size(), vma_desc_pages() helpers
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Andrew Morton <akpm@linux-foundation.org>, Jonathan Corbet <corbet@lwn.net>,
 Matthew Wilcox <willy@infradead.org>, Guo Ren <guoren@kernel.org>,
 Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
 Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
 Alexander Gordeev <agordeev@linux.ibm.com>,
 Christian Borntraeger <borntraeger@linux.ibm.com>,
 Sven Schnelle <svens@linux.ibm.com>, "David S . Miller"
 <davem@davemloft.net>, Andreas Larsson <andreas@gaisler.com>,
 Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Dan Williams <dan.j.williams@intel.com>,
 Vishal Verma <vishal.l.verma@intel.com>, Dave Jiang <dave.jiang@intel.com>,
 Nicolas Pitre <nico@fluxnic.net>, Muchun Song <muchun.song@linux.dev>,
 Oscar Salvador <osalvador@suse.de>,
 Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
 Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
 Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
 Reinette Chatre <reinette.chatre@intel.com>,
 Dave Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>,
 Alexander Viro <viro@zeniv.linux.org.uk>,
 Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
 "Liam R . Howlett" <Liam.Howlett@oracle.com>,
 Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
 Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 Hugh Dickins <hughd@google.com>, Baolin Wang
 <baolin.wang@linux.alibaba.com>, Uladzislau Rezki <urezki@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
 sparclinux@vger.kernel.org, nvdimm@lists.linux.dev,
 linux-cxl@vger.kernel.org, linux-mm@kvack.org, ntfs3@lists.linux.dev,
 kexec@lists.infradead.org, kasan-dev@googlegroups.com
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908125101.GX616306@nvidia.com>
 <e71b7763-4a62-4709-9969-8579bdcff595@lucifer.local>
 <20250908133224.GE616306@nvidia.com>
 <090675bd-cb18-4148-967b-52cca452e07b@lucifer.local>
 <20250908142011.GK616306@nvidia.com>
 <764d413a-43a3-4be2-99c4-616cd8cd3998@lucifer.local>
 <20250908151637.GM616306@nvidia.com>
 <8edb13fc-e58d-4480-8c94-c321da0f4d8e@redhat.com>
 <20250908153342.GA789684@nvidia.com>
 <365c1ec2-cda6-4d94-895c-b2a795101857@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <365c1ec2-cda6-4d94-895c-b2a795101857@redhat.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: aKgYG1Z0DZStrUrGo3pT9f3WhazN1P7ScduxlK-kI9M_1757346622
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Vm9Jcf4F;
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

On 08.09.25 17:46, David Hildenbrand wrote:
> On 08.09.25 17:33, Jason Gunthorpe wrote:
>> On Mon, Sep 08, 2025 at 05:24:23PM +0200, David Hildenbrand wrote:
>>>>
>>>>> I think we need to be cautious of scope here :) I don't want to
>>>>> accidentally break things this way.
>>>>
>>>> IMHO it is worth doing when you get into more driver places it is far
>>>> more obvious why the VM_SHARED is being checked.
>>>>
>>>>> OK I think a sensible way forward - How about I add desc_is_cowable() or
>>>>> vma_desc_cowable() and only set this if I'm confident it's correct?
>>>>
>>>> I'm thinking to call it vma_desc_never_cowable() as that is much much
>>>> clear what the purpose is.
>>>
>>> Secretmem wants no private mappings. So we should check exactly that, not
>>> whether we might have a cow mapping.
>>
>> secretmem is checking shared for a different reason than many other places..
> 
> I think many cases just don't want any private mappings.
> 
> After all, you need a R/O file (VM_MAYWRITE cleared) mapped MAP_PRIVATE
> to make is_cow_mapping() == false.

Sorry, was confused there. R/O file does not matter with MAP_PRIVATE. I 
think we default to VM_MAYWRITE with MAP_PRIVATE unless someone 
explicitly clears it.

So in practice there is indeed not a big difference between a private 
and cow mapping.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3229ac90-943f-4574-a9b8-bd4f5fa6cf03%40redhat.com.
