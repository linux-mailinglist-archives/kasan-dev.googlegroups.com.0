Return-Path: <kasan-dev+bncBC32535MUICBBLFLY3CQMGQELW3KEYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E560B3BA58
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 13:57:34 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-b4c746c020csf961890a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 04:57:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756468652; cv=pass;
        d=google.com; s=arc-20240605;
        b=NhiHZTarnjZgBNWAKfj5uv6tPA/cbG9UN1GbLkgtl7GE8u9o/J666nt6JY5v2sC6gG
         76Cj/lxQQbxc8A/DgzBgiaBzdLMmKAmhymERrnDpf1u18/UGj0DlWrnXvUFCutSnppXE
         l9eV3wdrMEunzNmh1dUc+Q+/0UwmX6FowUI8X67LLMpWMNFeiCv9ma5CRAKDfDX9ChXV
         VZsHKn8v+gYpvJL32m7IdThgrN2MXO7+NabQYuQKVynJ6s3UAYdl9wF3SAczaIwW0CiF
         x7gnEmu5qsI/+sTCk5eTEXg+VgKBp37K6l0NVvKGYS1GDoMMo9bRIo1IbE4fjsJnH3Db
         8P2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=NRuYk1Jdh/SkdJPxUwHZJMZUiFMYf4opsy/2NutDBws=;
        fh=/SROnn9qSviK/ZcyFH33haoRbc8VGTjdUV69OUJfBZA=;
        b=b1+kK5XXnhwNttFDE2BSnOv5QEywgcLwFMqQH8HPhHOMOAn4q1I9japAelxNlx+yrS
         bRocm5RhcDFzQufGcfahOnP2tTF+WHS3dmqIA7RDDgcS5KQfgaGxBK0UCoA4b4gty0l9
         EnsaWWSOWpIccHQ/fN9IgOUJcwFxoYJeKI1fDB1WDRix/E//yVeD5f0eYvRvm/D/pt21
         hpZO4waLanInLSp5h/ZUZTBEn/QomW6C7uoZvaoOLNzTO9w74rY1ZggUWbwuSyf9k4l2
         0iXnvOB4npTE4OIxedYQ719wN2bj5W1Lg8nOlMMnRHxEts6ptkqQEb1nEUYxrGbHFEoq
         4pNg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WNUDebRf;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756468652; x=1757073452; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=NRuYk1Jdh/SkdJPxUwHZJMZUiFMYf4opsy/2NutDBws=;
        b=l/SIJL29mhTh2+PMv/j7MbfJAw3seGjoGavzl4EyEfKgVpv2QKFLG/SMeONDPbp4Jr
         0BFuneVETYRQv/Aybu5BgNdXE6keZPuClWbK0uRFWeTiAafEZjTSBq8uo4Mj/PVnhJDM
         sjsgF2SbyoJ91dU05xmQstrKmMo/Xnd9dfE0QI+SAgGnXHhrY/Eu1fMiKZ26/sO42zEx
         UHMgdMuQ9EawJmK8byxrpg/Wgb/JOiDdvRwb+9cB6cdAlS7kHljfr0n8IgBckbYnTZRl
         MNNm5DYzKAm0EjIe4GfyrbXlUNJNUNfXHqnhnHah73NrfK+zWMCRPOr9lV983cMvXBNz
         WS9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756468652; x=1757073452;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=NRuYk1Jdh/SkdJPxUwHZJMZUiFMYf4opsy/2NutDBws=;
        b=fCSuODJcnt2MscWoZar7acRhVtC4RgOauOasyCeQ5JRjH+RWCWPDVxjjzGUw9osGsW
         a+RUozG78Sb4vggdd0I+SYO1O7autlNbfhZslKmDCSZs2yTumBOJ5eVIFsBFRC3geKZ0
         eZuB7zdlZxvdnr4tp95lJbTuzMLBWi0Zuk4LGtSvsSOw1yLiPN9iJ+KgxKyEfgfwHgqI
         g/nP0UAqyCEW5wbKNQXrhgo32JmSac28t503K+P/MvIVVTA6Ck2px+aIC+RMh/u8n/hF
         toh+6HvNYqBpA2OBjbYdHWGBfCzTss1QmZa+zTzVSm8E1B3JZbRemVE9JMj2lmo9n74F
         w5KA==
X-Forwarded-Encrypted: i=2; AJvYcCV4S6mPh3FXJJmvnU85NPD6WvVCN+kgeRWibdZmCKy5f42UTqfiZKNyfYibbZbudEEFBKJhlw==@lfdr.de
X-Gm-Message-State: AOJu0Ywq8eSGdiMODnMza2FcwyZxftMnyA4DNsb3X14sCiF4/kgjj0Dx
	5Strlwg6TokqBLhiueXqjdUAHk2MAm4ZxoCU+o2zwFah1uhiyYqJAC1z
X-Google-Smtp-Source: AGHT+IFz4u74rziIPU82CAtrJNEgCUQTwZzpc2WDxUkOEO8cpvW5TJ7QOFikXCQUdkXnDLZZB3rMqg==
X-Received: by 2002:a05:6a20:12c3:b0:243:ce0f:e809 with SMTP id adf61e73a8af0-243ce0fed66mr317574637.23.1756468652518;
        Fri, 29 Aug 2025 04:57:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdTBbG4InXQhHlNEk57qKgqGvVkHWxnje1CjJjHKv62FA==
Received: by 2002:a17:90a:ac2:b0:31e:cf05:e731 with SMTP id
 98e67ed59e1d1-327aa8db21els1798834a91.0.-pod-prod-07-us; Fri, 29 Aug 2025
 04:57:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVN7LuqcxAFj3UXhWJxVK/fd9Ic3xg7ar5er6lktlu/8lGFdHM5kbX8V+GsaiUV/VOrQ6i6gfcqGRk=@googlegroups.com
X-Received: by 2002:a17:90b:4b85:b0:327:96dd:6293 with SMTP id 98e67ed59e1d1-32796dd656cmr11257322a91.26.1756468650756;
        Fri, 29 Aug 2025 04:57:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756468650; cv=none;
        d=google.com; s=arc-20240605;
        b=hJwC2t4EAFNyZhC6XwdfiBfVMf5R7SmPoxzomDRsOxN2kWt7iStEdBW/G3wgacvFCU
         /wEF6Q0MsOdgQFChJ2uZchb7riotWdPbNSBnSdHQRFYkB2h0F4+BG4BUXYruI4jHwIIb
         TH0Ynnb7W8ghkVvYt6SRxIIjBKfXumw7yZ1ELAzblh7hU4M/2DnjiVUYf436QbMIP/63
         sRTEeMFo6pwdpxaQveEQVUWfsQKrP1EPqEh1DLcEvvOefAiWkBAItwhLlyx0UdszmezZ
         JEnmybC4fuPW9CLxI/ktc7jYKN2Et8YdHHXtng1QW2g0ivgJZLWz7vbzCMyu44PJ0qnG
         kY1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=hoDokfG1MQmzSDgEaptCicCjaaQpWxY2iqh8txE4sWo=;
        fh=PamJ/b3pOlsK5sQWH3NASPU9enZx0qhk2eLF0DHyILo=;
        b=b7czpDzBxFxUngq07lqD5L8UIlVZo5dr1WeqnvW2P+GGwVMhL/Xn77m0ERHvjlh0Sk
         DGYY/ywhkuYSqtGePb0sw/RtK/FtSm6tRSAbLNc1lvlMy5MY08bLEjceMr/oM91OssLf
         P4S2mArxa2Z5VtO+DYSAClup6mjpQF0kZD+g8oWxIQcCFHr/1nUrGgTMQWK2llT9eG+n
         XQsMzH7cR8XR23jpz7DS+lzL//BFyHQJp+2JX8uUQBj1PAscIywVKDnHTyxhZt+r3+u0
         2DJuS5PbucxuvpTqI+qb5NXIPGum+x0XGdBOOL/iKHNcn4Vm7G1SkzBFt5SimxyoufYh
         A3MQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WNUDebRf;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-327b61686e0si73715a91.0.2025.08.29.04.57.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 04:57:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-342-h2DqwrEiOduKbViqhRfbMA-1; Fri, 29 Aug 2025 07:57:27 -0400
X-MC-Unique: h2DqwrEiOduKbViqhRfbMA-1
X-Mimecast-MFC-AGG-ID: h2DqwrEiOduKbViqhRfbMA_1756468646
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45b7f0d1449so4065015e9.0
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 04:57:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXXOEuukNP7E0z8oYllMrQnEUbhVmAJaV8G+q/yADGxhlkwTQ1plzeHefs1qldj4VukQ3/TBBdSMCA=@googlegroups.com
X-Gm-Gg: ASbGnctwF/MjcCVoGopPMz9YWdfd9rgsLfSn+25dpziq/eKjgt1sjJfLtNqOgdsFmpt
	FTPEcm3kjQni1eKFVyNqIRq/XJoUqnP9BI+URZ89LsfWuYS+PcJbqgsn15W+IYBLmc9t3HcGpPv
	RNphV7l9dMjpQaQqS5ORRq3gr2qWQyJOv7SM8a2onyHYPsWnWdBVEMiWS4uWPcc5eSmVMpUgMR0
	dggCgayNM1tiQufBdiBidcpWMJ/IX+qWwXxvqGi2GQOoH1796Q1OJgab85rwzuUXpwpPLU7z2Wb
	HnFBlu80+4ttaUfCRPDpD7vXnb42xvM0QP8ZNv2RHrkNOtXUYLZymjRoZSnNN4SffFEKvQopHeg
	zkHgu4dV8B9T+hgPgY3DlItJ2sIeGGAVQ+FtuuObpoQDSXLBqizgQg2KVTMyCtMA=
X-Received: by 2002:a05:600c:348d:b0:45b:80ab:3359 with SMTP id 5b1f17b1804b1-45b80ab35acmr15395075e9.0.1756468645783;
        Fri, 29 Aug 2025 04:57:25 -0700 (PDT)
X-Received: by 2002:a05:600c:348d:b0:45b:80ab:3359 with SMTP id 5b1f17b1804b1-45b80ab35acmr15394435e9.0.1756468645290;
        Fri, 29 Aug 2025 04:57:25 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b6f0c6b99sm116739135e9.4.2025.08.29.04.57.23
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 04:57:24 -0700 (PDT)
Message-ID: <eff8badd-0ddd-4a5f-a2ef-0e3ded39687a@redhat.com>
Date: Fri, 29 Aug 2025 13:57:22 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 11/36] mm: limit folio/compound page sizes in
 problematic kernel configs
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
 "Mike Rapoport (Microsoft)" <rppt@kernel.org>,
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
 Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
 Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
 Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>,
 Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev,
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-12-david@redhat.com>
 <baa1b6cf-2fde-4149-8cdf-4b54e2d7c60d@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <baa1b6cf-2fde-4149-8cdf-4b54e2d7c60d@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: 4xRKocbFssNUTgDgwOJbK3nJzcWXV56H_B73W8n4-7M_1756468646
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=WNUDebRf;
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

On 28.08.25 17:10, Lorenzo Stoakes wrote:
> On Thu, Aug 28, 2025 at 12:01:15AM +0200, David Hildenbrand wrote:
>> Let's limit the maximum folio size in problematic kernel config where
>> the memmap is allocated per memory section (SPARSEMEM without
>> SPARSEMEM_VMEMMAP) to a single memory section.
>>
>> Currently, only a single architectures supports ARCH_HAS_GIGANTIC_PAGE
>> but not SPARSEMEM_VMEMMAP: sh.
>>
>> Fortunately, the biggest hugetlb size sh supports is 64 MiB
>> (HUGETLB_PAGE_SIZE_64MB) and the section size is at least 64 MiB
>> (SECTION_SIZE_BITS == 26), so their use case is not degraded.
>>
>> As folios and memory sections are naturally aligned to their order-2 size
>> in memory, consequently a single folio can no longer span multiple memory
>> sections on these problematic kernel configs.
>>
>> nth_page() is no longer required when operating within a single compound
>> page / folio.
>>
>> Reviewed-by: Zi Yan <ziy@nvidia.com>
>> Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
> 
> Realy great comments, like this!
> 
> I wonder if we could have this be part of the first patch where you fiddle
> with MAX_FOLIO_ORDER etc. but not a big deal.

I think it belongs into this patch where we actually impose the 
restrictions.

[...]

>> +/*
>> + * Only pages within a single memory section are guaranteed to be
>> + * contiguous. By limiting folios to a single memory section, all folio
>> + * pages are guaranteed to be contiguous.
>> + */
>> +#define MAX_FOLIO_ORDER		PFN_SECTION_SHIFT
> 
> Hmmm, was this implicit before somehow? I mean surely by the fact as you say
> that physical contiguity would not otherwise be guaranteed :))

Well, my patches until this point made sure that any attempt to use a 
larger folio would fail in a way that we could spot now if there is any 
offender.

That is why before this change, nth_page() was required within a folio.

Hope that clarifies it, thanks!

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/eff8badd-0ddd-4a5f-a2ef-0e3ded39687a%40redhat.com.
